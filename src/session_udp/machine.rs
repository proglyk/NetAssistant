//! UDP Session handshake state machine.
//!
//! Pure logic module: it imports neither gpui nor tokio and does not get the time or the random bytes on its own.
//! The time is advanced by an external timer (`Command::Tick`), the random nonce comes from outside (`Command::Start`),
//! therefore the whole state machine is deterministic and can be tested by a script.

use crate::session_udp::codec::{
    DecodeError, HKDF_INFO, Packet, data_aad, data_nonce, decode, hello_mac_input,
    session_ok_mac_input,
};
use crate::session_udp::crypto::{
    TAG_LEN, aes_gcm_decrypt, aes_gcm_encrypt, hkdf_sha256, hmac_sha256, hmac_verify,
};
use std::fmt;

/// Input of the state machine
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Start the handshake: the client nonce, the pre-shared secret, the number of HELLO resends
    Start {
        nonce_a: [u8; 16],
        psk: String,
        hello_retries: u8,
    },
    /// Handshake timeout (triggered by an external timer)
    Tick,
    /// A parsed protocol packet has arrived
    Packet(Packet),
    /// Bytes sent by the user
    UserBytes(Vec<u8>),
    /// The user disconnects on purpose
    UserDisconnect,
}

/// Output of the state machine
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// A protocol packet that has to be sent
    Send(Packet),
    /// The decrypted plain text payload
    Deliver(Vec<u8>),
    /// The handshake is over, the session is established
    Established { session_id: [u8; 16] },
    /// Fatal failure: the connection ends
    Failed(String),
    /// The session is closed
    Closed,
    /// Non-fatal warning: the connection stays
    Warn(String),
}

/// Internal state
enum State {
    Idle,
    /// Waiting for the SessionOk
    Wait {
        nonce_a: [u8; 16],
        psk: String,
        tries_left: u8,
        /// The sent Hello is kept as it is: a resend must carry the same nonce and the same proof,
        /// another nonce would let the server open a parallel handshake
        hello: Packet,
    },
    /// The session is established
    Established {
        session_id: [u8; 16],
        key: [u8; 32],
        tx_seq: u64,
        rx_seq: u64,
    },
    Closed,
    Failed,
}

/// UDP Session handshake state machine
pub struct Machine {
    state: State,
}

impl Machine {
    pub fn new() -> Self {
        Machine { state: State::Idle }
    }

    /// Process one input and return the list of actions of the state machine
    pub fn handle(&mut self, cmd: Command) -> Vec<Action> {
        match cmd {
            Command::Start {
                nonce_a,
                psk,
                hello_retries,
            } => self.on_start(nonce_a, psk, hello_retries),
            Command::Tick => self.on_tick(),
            Command::Packet(packet) => self.on_packet(packet),
            Command::UserBytes(bytes) => self.on_user_bytes(bytes),
            Command::UserDisconnect => self.on_user_disconnect(),
        }
    }

    /// Process a received datagram: parse it first, and on a parse failure decide from the state whether to fail or to drop it silently
    pub fn on_datagram(&mut self, bytes: &[u8]) -> Vec<Action> {
        match decode(bytes) {
            Ok(packet) => self.handle(Command::Packet(packet)),
            Err(DecodeError::BadSessionErrUtf8) => {
                if matches!(&self.state, State::Wait { .. }) {
                    self.state = State::Failed;
                    vec![Action::Failed("bad session err".to_string())]
                } else {
                    self.warn_bad_datagram()
                }
            }
            Err(_) => self.warn_bad_datagram(),
        }
    }

    /// Start the handshake: it only works in the Idle state
    fn on_start(&mut self, nonce_a: [u8; 16], psk: String, hello_retries: u8) -> Vec<Action> {
        if !matches!(&self.state, State::Idle) {
            return Vec::new();
        }
        // An empty PSK is not a valid key: fail right away, not a single byte goes on the wire
        if psk.is_empty() {
            self.state = State::Failed;
            return vec![Action::Failed("empty psk".to_string())];
        }
        let proof_a = hmac_sha256(psk.as_bytes(), &hello_mac_input(&nonce_a));
        let hello = Packet::Hello { nonce_a, proof_a };
        self.state = State::Wait {
            nonce_a,
            psk,
            tries_left: hello_retries,
            hello: hello.clone(),
        };
        vec![Action::Send(hello)]
    }

    /// Handshake timeout: resend the same Hello; when the attempts are used up it fails
    fn on_tick(&mut self) -> Vec<Action> {
        let (tries_left, hello) = match &self.state {
            State::Wait {
                tries_left, hello, ..
            } => (*tries_left, hello.clone()),
            _ => return Vec::new(),
        };
        if tries_left == 0 {
            self.state = State::Failed;
            return vec![Action::Failed("handshake timeout".to_string())];
        }
        if let State::Wait { tries_left, .. } = &mut self.state {
            *tries_left -= 1;
        }
        vec![Action::Send(hello)]
    }

    /// A protocol packet has arrived: dispatch it by the current state
    fn on_packet(&mut self, packet: Packet) -> Vec<Action> {
        // Take the state out first and put it back after the computation: the handler has to rewrite the state
        match std::mem::replace(&mut self.state, State::Idle) {
            State::Wait {
                nonce_a,
                psk,
                tries_left,
                hello,
            } => {
                let (state, actions) = Self::wait_packet(packet, nonce_a, psk, tries_left, hello);
                self.state = state;
                actions
            }
            State::Established {
                session_id,
                key,
                tx_seq,
                rx_seq,
            } => {
                let (state, actions) =
                    Self::established_packet(packet, session_id, key, tx_seq, rx_seq);
                self.state = state;
                actions
            }
            state => {
                self.state = state;
                Vec::new()
            }
        }
    }

    /// Packet handling during the wait
    fn wait_packet(
        packet: Packet,
        nonce_a: [u8; 16],
        psk: String,
        tries_left: u8,
        hello: Packet,
    ) -> (State, Vec<Action>) {
        match packet {
            Packet::SessionOk {
                session_id,
                nonce_b,
                proof_b,
            } => {
                let mac = session_ok_mac_input(&session_id, &nonce_b);
                if !hmac_verify(psk.as_bytes(), &mac, &proof_b) {
                    return (State::Failed, vec![Action::Failed("bad proof".to_string())]);
                }
                // salt = nonce_a || nonce_b; the info is fixed; the OKM is the AES-256 key
                let mut salt = Vec::with_capacity(nonce_a.len() + nonce_b.len());
                salt.extend_from_slice(&nonce_a);
                salt.extend_from_slice(&nonce_b);
                let key = hkdf_sha256(psk.as_bytes(), &salt, HKDF_INFO);
                (
                    State::Established {
                        session_id,
                        key,
                        tx_seq: 1,
                        rx_seq: 1,
                    },
                    vec![Action::Established { session_id }],
                )
            }
            Packet::SessionErr { code, message } => (
                State::Failed,
                vec![Action::Failed(format!("session err {code}: {message}"))],
            ),
            // The other packets (Hello / Data / Close) are only passing datagrams during the wait, they are ignored silently
            _ => (
                State::Wait {
                    nonce_a,
                    psk,
                    tries_left,
                    hello,
                },
                Vec::new(),
            ),
        }
    }

    /// Packet handling after the session is established
    fn established_packet(
        packet: Packet,
        session_id: [u8; 16],
        key: [u8; 32],
        tx_seq: u64,
        rx_seq: u64,
    ) -> (State, Vec<Action>) {
        match packet {
            Packet::Data {
                session_id: sid,
                seq,
                ciphertext,
            } => {
                // First the session_id, then the seq, and only then the decryption:
                // the packets of others and the out-of-order packets must not be hidden behind a "bad tag" as one single error
                if sid != session_id {
                    return (
                        Self::established_state(session_id, key, tx_seq, rx_seq),
                        vec![Action::Warn("foreign session".to_string())],
                    );
                }
                if seq != rx_seq {
                    return (
                        Self::established_state(session_id, key, tx_seq, rx_seq),
                        vec![Action::Warn("bad seq".to_string())],
                    );
                }
                let nonce = data_nonce(&session_id, seq);
                let aad = data_aad(&session_id, seq, ciphertext.len() as u16);
                match aes_gcm_decrypt(&key, &nonce, &aad, &ciphertext) {
                    Ok(plain) => (
                        Self::established_state(session_id, key, tx_seq, rx_seq + 1),
                        vec![Action::Deliver(plain)],
                    ),
                    Err(_) => (
                        Self::established_state(session_id, key, tx_seq, rx_seq),
                        vec![Action::Warn("bad tag".to_string())],
                    ),
                }
            }
            Packet::Close {
                session_id: sid, ..
            } => {
                if sid == session_id {
                    // The Close is neither encrypted nor authenticated; its seq takes no part in the check
                    (State::Closed, vec![Action::Closed])
                } else {
                    (
                        Self::established_state(session_id, key, tx_seq, rx_seq),
                        vec![Action::Warn("foreign session".to_string())],
                    )
                }
            }
            _ => (
                Self::established_state(session_id, key, tx_seq, rx_seq),
                vec![Action::Warn("unexpected packet".to_string())],
            ),
        }
    }

    fn established_state(session_id: [u8; 16], key: [u8; 32], tx_seq: u64, rx_seq: u64) -> State {
        State::Established {
            session_id,
            key,
            tx_seq,
            rx_seq,
        }
    }

    /// The user sends: before the session is established it is always refused (the plain text must not go on the wire)
    fn on_user_bytes(&mut self, bytes: Vec<u8>) -> Vec<Action> {
        let (session_id, key, tx_seq) = match &self.state {
            State::Established {
                session_id,
                key,
                tx_seq,
                ..
            } => (*session_id, *key, *tx_seq),
            _ => return vec![Action::Warn("not established".to_string())],
        };
        // An empty payload does not spend a sequence number
        if bytes.is_empty() {
            return Vec::new();
        }
        // The sequence number is exhausted: nothing is encrypted any more and the number does not go on the wire
        if tx_seq == u64::MAX {
            self.state = State::Failed;
            return vec![Action::Failed("seq exhausted".to_string())];
        }
        debug_assert!(bytes.len() + TAG_LEN <= u16::MAX as usize);
        let cipher_len = (bytes.len() + TAG_LEN) as u16;
        let nonce = data_nonce(&session_id, tx_seq);
        let aad = data_aad(&session_id, tx_seq, cipher_len);
        // The key and the nonce have a fixed length, a failed encryption can only be a defect of the implementation
        let ciphertext = aes_gcm_encrypt(&key, &nonce, &aad, &bytes).expect(
            "the key and the nonce have a fixed length, the AES-256-GCM encryption cannot fail",
        );
        if let State::Established { tx_seq, .. } = &mut self.state {
            *tx_seq += 1;
        }
        vec![Action::Send(Packet::Data {
            session_id,
            seq: tx_seq,
            ciphertext,
        })]
    }

    /// The user disconnects: when the session is established a Close is sent (unencrypted), otherwise there is no packet to send
    fn on_user_disconnect(&mut self) -> Vec<Action> {
        let (state, actions) = match std::mem::replace(&mut self.state, State::Idle) {
            State::Established {
                session_id, tx_seq, ..
            } => (
                State::Closed,
                vec![
                    Action::Send(Packet::Close {
                        session_id,
                        seq: tx_seq,
                    }),
                    Action::Closed,
                ],
            ),
            State::Wait { .. } => (State::Closed, vec![Action::Closed]),
            state => (state, Vec::new()),
        };
        self.state = state;
        actions
    }

    /// A bad datagram in an established session: a warning, but the state does not change
    fn warn_bad_datagram(&self) -> Vec<Action> {
        if matches!(&self.state, State::Established { .. }) {
            vec![Action::Warn("bad datagram".to_string())]
        } else {
            Vec::new()
        }
    }

    /// For the tests: push the outgoing sequence number to a value (only in the established state)
    #[cfg(test)]
    fn test_set_tx_seq(&mut self, seq: u64) {
        if let State::Established { tx_seq, .. } = &mut self.state {
            *tx_seq = seq;
        }
    }
}

impl Default for Machine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Machine {
    /// Print the state name and the sequence numbers only: the psk, the key, the nonce and the proof never reach the log
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.state {
            State::Idle => write!(f, "Machine(Idle)"),
            State::Wait { tries_left, .. } => write!(f, "Machine(Wait, tries_left={tries_left})"),
            State::Established { tx_seq, rx_seq, .. } => {
                write!(f, "Machine(Established, tx_seq={tx_seq}, rx_seq={rx_seq})")
            }
            State::Closed => write!(f, "Machine(Closed)"),
            State::Failed => write!(f, "Machine(Failed)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_udp::codec::{Packet, data_aad, data_nonce};
    use crate::session_udp::crypto::{TAG_LEN, aes_gcm_encrypt, hkdf_sha256, hmac_sha256};

    const PSK: &str = "super-secret-psk";
    fn nonce_a() -> [u8; 16] {
        [7u8; 16]
    }

    /// HKDF salt = nonce_a || nonce_b
    fn salt() -> Vec<u8> {
        nonce_a().into_iter().chain([4u8; 16]).collect()
    }

    fn start(m: &mut Machine, retries: u8) -> Vec<Action> {
        m.handle(Command::Start {
            nonce_a: nonce_a(),
            psk: PSK.into(),
            hello_retries: retries,
        })
    }

    fn hello_of(actions: &[Action]) -> Packet {
        match &actions[0] {
            Action::Send(p @ Packet::Hello { .. }) => p.clone(),
            other => panic!("expected Hello, got {other:?}"),
        }
    }

    fn session_ok_for(hello: &Packet) -> Packet {
        let Packet::Hello { .. } = hello else {
            unreachable!()
        };
        let session_id = [3u8; 16];
        let nonce_b = [4u8; 16];
        let proof_b = hmac_sha256(
            PSK.as_bytes(),
            &crate::session_udp::codec::session_ok_mac_input(&session_id, &nonce_b),
        );
        Packet::SessionOk {
            session_id,
            nonce_b,
            proof_b,
        }
    }

    fn establish(m: &mut Machine) -> [u8; 16] {
        let hello = hello_of(&start(m, 3));
        let ok = session_ok_for(&hello);
        let actions = m.handle(Command::Packet(ok));
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::Established { .. }))
        );
        [3u8; 16]
    }

    #[test]
    fn happy_path_delivers_plaintext() {
        let mut m = Machine::new();
        let session_id = establish(&mut m);
        let actions = m.handle(Command::UserBytes(b"ping".to_vec()));
        let Action::Send(Packet::Data {
            seq,
            ciphertext,
            session_id: sid,
            ..
        }) = &actions[0]
        else {
            panic!("expected Data");
        };
        assert_eq!(*seq, 1);
        assert_eq!(*sid, session_id);
        let key = hkdf_sha256(
            PSK.as_bytes(),
            &salt(),
            crate::session_udp::codec::HKDF_INFO,
        );
        let plain = crate::session_udp::crypto::aes_gcm_decrypt(
            &key,
            &data_nonce(&session_id, 1),
            &data_aad(&session_id, 1, ciphertext.len() as u16),
            ciphertext,
        )
        .unwrap();
        assert_eq!(plain, b"ping");

        let ct = aes_gcm_encrypt(
            &key,
            &data_nonce(&session_id, 1),
            &data_aad(&session_id, 1, (b"{\"a\":1}".len() + TAG_LEN) as u16),
            b"{\"a\":1}",
        )
        .unwrap();
        let actions = m.handle(Command::Packet(Packet::Data {
            session_id,
            seq: 1,
            ciphertext: ct,
        }));
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::Deliver(p) if p == b"{\"a\":1}"))
        );
    }

    #[test]
    fn retry_keeps_nonce_then_fails() {
        let mut m = Machine::new();
        let first = hello_of(&start(&mut m, 3));
        for _ in 0..3 {
            let again = hello_of(&m.handle(Command::Tick));
            assert_eq!(first, again);
        }
        let failed = m.handle(Command::Tick);
        assert!(
            failed
                .iter()
                .any(|a| matches!(a, Action::Failed(s) if s == "handshake timeout"))
        );
        assert!(!format!("{failed:?}").contains(PSK));
    }

    #[test]
    fn bad_proof_does_not_echo_psk() {
        let mut m = Machine::new();
        let hello = hello_of(&start(&mut m, 3));
        let mut ok = session_ok_for(&hello);
        let Packet::SessionOk { proof_b, .. } = &mut ok else {
            unreachable!()
        };
        *proof_b = [9u8; 32];
        let actions = m.handle(Command::Packet(ok));
        match &actions[..] {
            [Action::Failed(text)] => {
                assert_eq!(text, "bad proof");
                assert!(!text.contains(PSK));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn session_err_and_bad_utf8() {
        let mut m = Machine::new();
        let _ = start(&mut m, 1);
        let actions = m.handle(Command::Packet(Packet::SessionErr {
            code: 7,
            message: "nope".into(),
        }));
        assert!(matches!(&actions[..], [Action::Failed(t)] if t == "session err 7: nope"));

        let mut m = Machine::new();
        let _ = start(&mut m, 1);
        let mut raw = crate::session_udp::codec::encode(&Packet::SessionErr {
            code: 1,
            message: "a".into(),
        });
        // Appendix A: SessionErr = code u16 + len u16 + message, the first byte of the message is at offset 8
        raw[8] = 0xFF;
        let actions = m.on_datagram(&raw);
        assert!(matches!(&actions[..], [Action::Failed(t)] if t == "bad session err"));
        assert!(!actions.iter().any(|a| format!("{a:?}").contains("FF")));
    }

    #[test]
    fn replay_and_gap_warn_then_next_seq_delivers() {
        let mut m = Machine::new();
        let session_id = establish(&mut m);
        let key = hkdf_sha256(
            PSK.as_bytes(),
            &salt(),
            crate::session_udp::codec::HKDF_INFO,
        );
        let seal = |seq: u64, plain: &[u8]| {
            aes_gcm_encrypt(
                &key,
                &data_nonce(&session_id, seq),
                &data_aad(&session_id, seq, (plain.len() + TAG_LEN) as u16),
                plain,
            )
            .unwrap()
        };
        let gap = m.handle(Command::Packet(Packet::Data {
            session_id,
            seq: 2,
            ciphertext: seal(2, b"b"),
        }));
        assert!(matches!(&gap[..], [Action::Warn(t)] if t == "bad seq"));
        let replay = m.handle(Command::Packet(Packet::Data {
            session_id,
            seq: 2,
            ciphertext: seal(2, b"b"),
        }));
        assert!(matches!(&replay[..], [Action::Warn(t)] if t == "bad seq"));
        let ok = m.handle(Command::Packet(Packet::Data {
            session_id,
            seq: 1,
            ciphertext: seal(1, b"a"),
        }));
        assert!(
            ok.iter()
                .any(|a| matches!(a, Action::Deliver(p) if p == b"a"))
        );
    }

    #[test]
    fn close_ignores_seq_foreign_close_warns() {
        let mut m = Machine::new();
        let session_id = establish(&mut m);
        let foreign = m.handle(Command::Packet(Packet::Close {
            session_id: [9u8; 16],
            seq: 1,
        }));
        assert!(matches!(&foreign[..], [Action::Warn(t)] if t == "foreign session"));
        let closed = m.handle(Command::Packet(Packet::Close {
            session_id,
            seq: 99,
        }));
        assert!(matches!(&closed[..], [Action::Closed]));
        assert!(!closed.iter().any(|a| matches!(a, Action::Send(_))));
    }

    #[test]
    fn empty_user_bytes_do_not_spend_seq() {
        let mut m = Machine::new();
        let _ = establish(&mut m);
        assert!(m.handle(Command::UserBytes(vec![])).is_empty());
        let actions = m.handle(Command::UserBytes(b"a".to_vec()));
        assert!(matches!(
            &actions[0],
            Action::Send(Packet::Data { seq: 1, .. })
        ));
    }

    #[test]
    fn seq_max_fails_without_data() {
        let mut m = Machine::new();
        let _ = establish(&mut m);
        // tx_seq cannot be driven to MAX in a loop in a reasonable time: the test
        // calls the crate-visible way to set the next seq. Add
        // #[cfg(test)] pub fn test_set_tx_seq(&mut self, seq: u64) only in Established.
        m.test_set_tx_seq(u64::MAX);
        let actions = m.handle(Command::UserBytes(b"a".to_vec()));
        assert!(matches!(&actions[..], [Action::Failed(t)] if t == "seq exhausted"));
        assert!(!actions.iter().any(|a| matches!(a, Action::Send(_))));
    }

    #[test]
    fn second_start_ignored_and_bytes_before_established_not_sent() {
        let mut m = Machine::new();
        let _ = establish(&mut m);
        assert!(
            m.handle(Command::Start {
                nonce_a: nonce_a(),
                psk: PSK.into(),
                hello_retries: 3,
            })
            .is_empty()
        );

        let mut early = Machine::new();
        let _ = start(&mut early, 3);
        let actions = early.handle(Command::UserBytes(b"open text".to_vec()));
        assert!(matches!(&actions[..], [Action::Warn(t)] if t == "not established"));
        assert!(!format!("{actions:?}").contains("open text"));
    }

    #[test]
    fn empty_psk_fails_before_hello() {
        let mut m = Machine::new();
        let actions = m.handle(Command::Start {
            nonce_a: nonce_a(),
            psk: String::new(),
            hello_retries: 3,
        });
        assert!(matches!(&actions[..], [Action::Failed(t)] if t == "empty psk"));
        assert!(m.handle(Command::Tick).is_empty());
    }

    #[test]
    fn debug_omits_psk() {
        let mut m = Machine::new();
        let _ = start(&mut m, 3);
        assert!(!format!("{m:?}").contains(PSK));
    }

    #[test]
    fn user_bytes_before_established_sends_nothing() {
        let mut m = Machine::new();
        let actions = m.handle(Command::UserBytes(b"clear".to_vec()));
        assert!(matches!(&actions[..], [Action::Warn(t)] if t == "not established"));
    }
}
