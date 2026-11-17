//! UDP Session 握手状态机。
//!
//! 纯逻辑模块：不引 gpui，不引 tokio，也不自己取时间与随机数。
//! 时间由外部计时器推进（`Command::Tick`），随机 nonce 由外部给（`Command::Start`），
//! 因此整台状态机是确定性的，可脚本化测试。

use crate::session_udp::codec::{
    DecodeError, HKDF_INFO, Packet, data_aad, data_nonce, decode, hello_mac_input,
    session_ok_mac_input,
};
use crate::session_udp::crypto::{
    TAG_LEN, aes_gcm_decrypt, aes_gcm_encrypt, hkdf_sha256, hmac_sha256, hmac_verify,
};
use std::fmt;

/// 状态机输入
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// 开始握手：客户端随机 nonce、预共享密钥、HELLO 重发次数
    Start {
        nonce_a: [u8; 16],
        psk: String,
        hello_retries: u8,
    },
    /// 握手超时（由外部计时器触发）
    Tick,
    /// 收到一个已解析的协议包
    Packet(Packet),
    /// 用户发送的字节
    UserBytes(Vec<u8>),
    /// 用户主动断开
    UserDisconnect,
}

/// 状态机输出
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// 需要发出的协议包
    Send(Packet),
    /// 解密后的明文载荷
    Deliver(Vec<u8>),
    /// 握手完成，会话建立
    Established { session_id: [u8; 16] },
    /// 致命失败：连接终止
    Failed(String),
    /// 会话关闭
    Closed,
    /// 非致命告警：连接保持
    Warn(String),
}

/// 内部状态
enum State {
    Idle,
    /// 等待 SessionOk
    Wait {
        nonce_a: [u8; 16],
        psk: String,
        tries_left: u8,
        /// 已发出的 Hello 原样保存：重发必须带同一个 nonce 与 proof，
        /// 换 nonce 会让服务端开出并行握手
        hello: Packet,
    },
    /// 会话已建立
    Established {
        session_id: [u8; 16],
        key: [u8; 32],
        tx_seq: u64,
        rx_seq: u64,
    },
    Closed,
    Failed,
}

/// UDP Session 握手状态机
pub struct Machine {
    state: State,
}

impl Machine {
    pub fn new() -> Self {
        Machine { state: State::Idle }
    }

    /// 处理一条输入，返回状态机的动作列表
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

    /// 处理一个收到的数据报：先解析，解析失败按状态决定是失败还是静默丢弃
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

    /// 开始握手：只在 Idle 生效
    fn on_start(&mut self, nonce_a: [u8; 16], psk: String, hello_retries: u8) -> Vec<Action> {
        if !matches!(&self.state, State::Idle) {
            return Vec::new();
        }
        // 空 PSK 不是合法密钥：直接失败，一个字节都不上线
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

    /// 握手超时：重发同一个 Hello；次数用尽则失败
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

    /// 收到协议包：按当前状态分派
    fn on_packet(&mut self, packet: Packet) -> Vec<Action> {
        // 先把状态取出来，算完再放回去：处理函数需要改写状态
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

    /// 等待期的包处理
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
                // salt = nonce_a || nonce_b；info 固定；OKM 就是 AES-256 密钥
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
            // 其余包（Hello / Data / Close）在等待期只是路过的数据报，静默忽略
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

    /// 建立后的包处理
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
                // 先比 session_id，再比 seq，最后才解密：
                // 别人的包与错序的包不能被"坏标签"掩盖成同一类错误
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
                    // Close 不加密也不认证；它的 seq 不参与校验
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

    /// 用户发送：建立之前一律拒绝（明文不能上线）
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
        // 空载荷不占序号
        if bytes.is_empty() {
            return Vec::new();
        }
        // 序号用尽：不再加密，编号也不上线
        if tx_seq == u64::MAX {
            self.state = State::Failed;
            return vec![Action::Failed("seq exhausted".to_string())];
        }
        debug_assert!(bytes.len() + TAG_LEN <= u16::MAX as usize);
        let cipher_len = (bytes.len() + TAG_LEN) as u16;
        let nonce = data_nonce(&session_id, tx_seq);
        let aad = data_aad(&session_id, tx_seq, cipher_len);
        // 密钥与 nonce 长度固定，加密失败只可能是实现缺陷
        let ciphertext = aes_gcm_encrypt(&key, &nonce, &aad, &bytes)
            .expect("AES-256-GCM 密钥与 nonce 长度固定，加密不会失败");
        if let State::Established { tx_seq, .. } = &mut self.state {
            *tx_seq += 1;
        }
        vec![Action::Send(Packet::Data {
            session_id,
            seq: tx_seq,
            ciphertext,
        })]
    }

    /// 用户断开：已建立则发 Close（不加密），未建立则无从发包
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

    /// 已建立会话里的坏数据报：告警但不改变状态
    fn warn_bad_datagram(&self) -> Vec<Action> {
        if matches!(&self.state, State::Established { .. }) {
            vec![Action::Warn("bad datagram".to_string())]
        } else {
            Vec::new()
        }
    }

    /// 测试用：把发送序号直接推到某个值（只在已建立时生效）
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
    /// 只打印状态名与序号：psk、密钥、nonce、proof 都不进日志
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

    /// HKDF 的 salt = nonce_a || nonce_b
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
        // 附录 A: SessionErr = code u16 + len u16 + 消息，消息首字节在偏移 8
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
        // довести tx_seq до MAX нельзя циклом за вменяемое время: тест зовёт
        // crate-visible способ выставить следующий seq. Добавить
        // #[cfg(test)] pub fn test_set_tx_seq(&mut self, seq: u64) только в Established.
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
