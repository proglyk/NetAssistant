//! UDP Session client: own HELLO / SESSION_OK handshake + AES-256-GCM session.
//!
//! Differences from the plain UDP client:
//! - the handshake completes in the protocol layer; user bytes never reach the wire before it is over (clear text must not leak);
//! - the data of the session travels in DATA packets (ciphertext + 16-byte GCM tag), and only the decrypted plain text appears in the log;
//! - reply rules stay out: rules on plain text would bypass GCM authentication.
//!
//! See the byte contract in `src/session_udp/codec.rs` and appendix A of the design document.

use crate::config::connection::{ClientConfig, ServerConfig, TrailerSetting};
use crate::message::{Message, MessageDirection, MessageType};
use crate::network::events::{ConnectionEvent, NetCounters, ReceivedBatch, WireMessage};
use crate::network::interfaces::{NetworkConnection, NetworkServer};
use crate::reply::ReplyRulesStore;
use crate::session_udp::codec::{MAX_DATAGRAM, Packet, encode};
use crate::session_udp::machine::{Action, Command, Machine};
use log::{debug, error, info, warn};
use rust_i18n::t;
use smol::channel::{Sender, unbounded as smol_unbounded};
use std::any::Any;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

/// Buffer size of a single recv call. The UDP datagram limit is 65507 bytes, the buffer takes 65535.
const RECV_BUFFER_SIZE: usize = 65535;

/// Translate a failure token of the state machine into interface text.
///
/// The tokens are fixed English phrases (see `session_udp::machine`); this function only maps them and never echoes a key.
fn fail_text(token: &str) -> String {
    if let Some(detail) = token.strip_prefix("session err ") {
        return t!("udp_session.err_session", detail = detail).to_string();
    }
    match token {
        "empty psk" => t!("udp_session.err_empty_psk").to_string(),
        "handshake timeout" => t!("udp_session.err_handshake_timeout").to_string(),
        "bad proof" => t!("udp_session.err_bad_proof").to_string(),
        "bad session err" => t!("udp_session.err_bad_session_err").to_string(),
        "seq exhausted" => t!("udp_session.err_seq_exhausted").to_string(),
        other => other.to_string(),
    }
}

/// Translate a warning token of the state machine into interface text.
fn warn_text(token: &str) -> String {
    match token {
        "not established" => t!("udp_session.warn_not_established").to_string(),
        "foreign session" => t!("udp_session.warn_foreign_session").to_string(),
        "bad tag" => t!("udp_session.warn_bad_tag").to_string(),
        "bad seq" => t!("udp_session.warn_bad_seq").to_string(),
        "unexpected packet" => t!("udp_session.warn_unexpected_packet").to_string(),
        "bad datagram" => t!("udp_session.warn_bad_datagram").to_string(),
        other => other.to_string(),
    }
}

/// UDP Session client.
pub struct UdpSessionClient {
    config: ClientConfig,
    event_sender: Option<Sender<ConnectionEvent>>,
    net_counters: Option<NetCounters>,
    is_connected: bool,
    cancel_token: CancellationToken,
    /// Runtime "append trailer" setting: this connection does not read it (the DATA payload must not be polluted with appended bytes).
    _trailer: TrailerSetting,
    /// Shared reply rules state: this connection does not call them (rules must not act on ciphertext).
    _reply_rules: Arc<ReplyRulesStore>,
}

impl UdpSessionClient {
    pub fn new(
        config: ClientConfig,
        event_sender: Option<Sender<ConnectionEvent>>,
        net_counters: Option<NetCounters>,
        trailer: TrailerSetting,
        reply_rules: Arc<ReplyRulesStore>,
    ) -> Self {
        UdpSessionClient {
            config,
            event_sender,
            net_counters,
            is_connected: false,
            cancel_token: CancellationToken::new(),
            _trailer: trailer,
            _reply_rules: reply_rules,
        }
    }
}

impl NetworkConnection for UdpSessionClient {
    fn connect(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<(), Box<dyn std::error::Error>>> + Send>> {
        if self.is_connected {
            return Pin::from(Box::new(async move { Ok(()) }));
        }

        let config = self.config.clone();
        let settings = config.udp_session.clone().unwrap_or_default();
        // An empty PSK is rejected before the connection: not a single byte goes on the wire, and the event channel reports no Error.
        if settings.psk.is_empty() {
            return Pin::from(Box::new(async move {
                Err(Box::<dyn std::error::Error>::from(fail_text("empty psk")))
            }));
        }
        let event_sender = self.event_sender.clone();
        let net_counters = self.net_counters.clone();
        let cancel_token = self.cancel_token.clone();
        self.is_connected = true;

        Pin::from(Box::new(async move {
            let server_host = config.server_address.clone();
            // The address is assembled like in the UDP client: IPv6 needs brackets.
            let address = if server_host.contains(':') && !server_host.contains('[') {
                format!("[{}]:{}", server_host, config.server_port)
            } else {
                format!("{}:{}", server_host, config.server_port)
            };
            let server_addr = SocketAddr::from_str(&address)
                .map_err(|e| format!("invalid UDP Session server address {}: {}", address, e))?;

            info!("UDP Session client connects to: {}", server_addr);

            // Local bind: without a configured address the wildcard address of the remote address family is used, with an automatic port.
            let bind_addr = match crate::network::bind::resolve_local_bind(&config, server_addr)? {
                Some(addr) => addr,
                None if server_addr.is_ipv4() => {
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                }
                None => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            };
            let socket = UdpSocket::bind(bind_addr).await.map_err(|e| {
                format!(
                    "failed to bind the local address {}: {} (the local port may be taken, or the address is not a local one)",
                    bind_addr, e
                )
            })?;
            let local_addr = socket
                .local_addr()
                .map_err(|e| format!("failed to get the local UDP Session address: {}", e))?;
            // connect makes the kernel receive the datagrams of the peer only: packets of others cannot enter the handshake.
            socket.connect(server_addr).await.map_err(|e| {
                format!(
                    "failed to connect to the UDP Session server {}: {}",
                    server_addr, e
                )
            })?;

            // nonce_a comes from outside: the state machine has no random source of its own
            let mut nonce_a = [0u8; 16];
            getrandom::fill(&mut nonce_a)
                .map_err(|e| format!("failed to generate the handshake random bytes: {}", e))?;

            let mut machine = Machine::new();
            let actions = machine.handle(Command::Start {
                nonce_a,
                psk: settings.psk.clone(),
                hello_retries: settings.hello_retries,
            });

            let socket = Arc::new(socket);
            // The first HELLO goes on the wire right away: even a failed handshake has to make the peer see us.
            for action in &actions {
                if let Action::Send(packet) = action {
                    let bytes = encode(packet);
                    socket
                        .send(&bytes)
                        .await
                        .map_err(|e| format!("failed to send HELLO: {}", e))?;
                    if let Some(c) = &net_counters {
                        c.add_sent(1);
                        c.add_sent_bytes(bytes.len() as u64);
                    }
                }
            }

            let (tx, rx) = smol_unbounded::<WireMessage>();
            let id = config.id.clone();
            if let Some(sender) = &event_sender {
                let _ = sender
                    .send(ConnectionEvent::Connected(id.clone(), local_addr))
                    .await;
                let _ = sender
                    .send(ConnectionEvent::ClientWriteSenderReady(
                        id.clone(),
                        tx.clone(),
                    ))
                    .await;
                let _ = sender
                    .send(ConnectionEvent::StatusHint(
                        id.clone(),
                        t!("udp_session.hint_waiting").to_string(),
                    ))
                    .await;
            }
            drop(tx);

            let cancel = cancel_token.clone();
            let event_sender_loop = event_sender.clone();
            let net_counters_loop = net_counters.clone();
            let peer = server_addr;
            tokio::spawn(async move {
                let mut buf = [0u8; RECV_BUFFER_SIZE];
                // The handshake timer is armed while waiting only: after the session is established no HELLO is repeated.
                let mut waiting = true;
                let timeout = Duration::from_millis(settings.handshake_timeout_ms.max(1));
                let sleep = tokio::time::sleep(timeout);
                tokio::pin!(sleep);
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => {
                            let actions = machine.handle(Command::UserDisconnect);
                            let _ = apply(&actions, &socket, &event_sender_loop, &id, &peer, &net_counters_loop).await;
                            break;
                        }
                        _ = &mut sleep, if waiting => {
                            let actions = machine.handle(Command::Tick);
                            sleep.as_mut().reset(tokio::time::Instant::now() + timeout);
                            let flow = apply(&actions, &socket, &event_sender_loop, &id, &peer, &net_counters_loop).await;
                            if flow == Flow::Established {
                                waiting = false;
                            }
                            if flow == Flow::Stop {
                                break;
                            }
                        }
                        n = socket.recv(&mut buf) => {
                            match n {
                                Ok(n) => {
                                    // An oversized datagram does not reach the state machine: only a warning, the session continues.
                                    if n > MAX_DATAGRAM {
                                        if let Some(sender) = &event_sender_loop {
                                            let _ = sender.send(ConnectionEvent::Warning(
                                                id.clone(),
                                                t!("udp_session.warn_too_long").to_string(),
                                            )).await;
                                        }
                                        continue;
                                    }
                                    let actions = machine.on_datagram(&buf[..n]);
                                    let flow = apply(&actions, &socket, &event_sender_loop, &id, &peer, &net_counters_loop).await;
                                    if flow == Flow::Established {
                                        waiting = false;
                                    }
                                    if flow == Flow::Stop {
                                        break;
                                    }
                                }
                                Err(e) => {
                                    error!("UDP Session failed to receive a datagram: {:?}", e);
                                    if let Some(sender) = &event_sender_loop {
                                        let _ = sender.send(ConnectionEvent::Error(
                                            id.clone(),
                                            format!("failed to receive a datagram: {}", e),
                                        )).await;
                                    }
                                    break;
                                }
                            }
                        }
                        incoming = rx.recv() => {
                            match incoming {
                                Ok(wire) => {
                                    // The user bytes enter the state machine as they are: no trailer is appended, the finalized flag is not read.
                                    let actions = machine.handle(Command::UserBytes(wire.data().to_vec()));
                                    let flow = apply(&actions, &socket, &event_sender_loop, &id, &peer, &net_counters_loop).await;
                                    if flow == Flow::Established {
                                        waiting = false;
                                    }
                                    if flow == Flow::Stop {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    }
                }
                debug!("UDP Session client loop finished");
            });

            Ok(())
        }))
    }

    fn disconnect(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<(), Box<dyn std::error::Error>>> + Send>> {
        if !self.is_connected {
            return Pin::from(Box::new(async move { Ok(()) }));
        }
        self.is_connected = false;
        self.cancel_token.cancel();
        Pin::from(Box::new(async move { Ok(()) }))
    }
}

impl Drop for UdpSessionClient {
    /// Fallback for a drop that bypasses disconnect(): stop the background task, so that no orphan task keeps the socket.
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

/// Result of processing the actions.
#[derive(Debug, PartialEq, Eq)]
enum Flow {
    /// Continue the loop.
    Continue,
    /// The session is established: the handshake timer can stop.
    Established,
    /// Stop the loop.
    Stop,
}

/// Translate the actions of the state machine into protocol packets and UI events.
async fn apply(
    actions: &[Action],
    socket: &UdpSocket,
    event_sender: &Option<Sender<ConnectionEvent>>,
    id: &str,
    peer: &SocketAddr,
    net_counters: &Option<NetCounters>,
) -> Flow {
    let mut flow = Flow::Continue;
    for action in actions {
        match action {
            Action::Send(packet) => {
                let bytes = encode(packet);
                match socket.send(&bytes).await {
                    Ok(_) => {
                        if let Some(c) = net_counters {
                            c.add_sent(1);
                            c.add_sent_bytes(bytes.len() as u64);
                        }
                    }
                    Err(e) => {
                        // A failed Close send does not change the outcome: the session was over anyway.
                        if matches!(packet, Packet::Close { .. }) {
                            debug!("[UDP Session] failed to send Close: {:?}", e);
                            continue;
                        }
                        error!("[UDP Session] failed to send a packet: {:?}", e);
                        if let Some(sender) = event_sender {
                            let _ = sender
                                .send(ConnectionEvent::Error(
                                    id.to_string(),
                                    format!("failed to send a UDP Session packet: {}", e),
                                ))
                                .await;
                        }
                        flow = Flow::Stop;
                    }
                }
            }
            Action::Deliver(plain) => {
                // The decrypted plain text goes into the message list; handshake packets do not.
                let mut batch = ReceivedBatch::with_capacity(1);
                let len = plain.len() as u64;
                batch.count = 1;
                batch.bytes = len;
                batch.messages.push(
                    Message::new(MessageDirection::Received, plain.clone(), MessageType::Text)
                        .with_source(peer.to_string()),
                );
                if let Some(c) = net_counters {
                    c.add_received(1);
                    c.add_received_bytes(len);
                }
                if let Some(sender) = event_sender {
                    let _ = sender
                        .send(ConnectionEvent::MessagesReceived(id.to_string(), batch))
                        .await;
                }
            }
            Action::Established { .. } => {
                if let Some(sender) = event_sender {
                    let _ = sender
                        .send(ConnectionEvent::StatusHint(
                            id.to_string(),
                            t!("udp_session.hint_established").to_string(),
                        ))
                        .await;
                }
                flow = Flow::Established;
            }
            Action::Failed(token) => {
                error!("[UDP Session] session failed: {}", token);
                if let Some(sender) = event_sender {
                    let _ = sender
                        .send(ConnectionEvent::Error(id.to_string(), fail_text(token)))
                        .await;
                }
                flow = Flow::Stop;
            }
            Action::Closed => {
                if let Some(sender) = event_sender {
                    let _ = sender
                        .send(ConnectionEvent::Disconnected(id.to_string()))
                        .await;
                }
                flow = Flow::Stop;
            }
            Action::Warn(token) => {
                warn!("[UDP Session] {}", token);
                if let Some(sender) = event_sender {
                    let _ = sender
                        .send(ConnectionEvent::Warning(id.to_string(), warn_text(token)))
                        .await;
                }
            }
        }
        if flow == Flow::Stop {
            break;
        }
    }
    flow
}

/// UDP Session has no server role (the same as MQTT): `start` reports an error right away.
pub struct UdpSessionServer {
    _config: ServerConfig,
    _event_sender: Option<Sender<ConnectionEvent>>,
    _net_counters: Option<NetCounters>,
    _trailer: TrailerSetting,
}

impl UdpSessionServer {
    pub fn new(
        config: ServerConfig,
        event_sender: Option<Sender<ConnectionEvent>>,
        net_counters: Option<NetCounters>,
        trailer: TrailerSetting,
    ) -> Self {
        UdpSessionServer {
            _config: config,
            _event_sender: event_sender,
            _net_counters: net_counters,
            _trailer: trailer,
        }
    }
}

impl NetworkServer for UdpSessionServer {
    fn start(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<(), Box<dyn std::error::Error>>> + Send + '_>> {
        Box::pin(async { Err(t!("udp_session.err_no_server").to_string().into()) })
    }

    fn stop(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<(), Box<dyn std::error::Error>>> + Send>> {
        Box::pin(async { Ok(()) })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::connection::{ConnectionType, TrailerKind, UdpSessionSettings};
    use crate::reply::model::{ReplyPayload, ReplyRule, ReplyRulesConfig};
    use crate::session_udp::codec::{
        HKDF_INFO, data_aad, data_nonce, decode, hello_mac_input, session_ok_mac_input,
    };
    use crate::session_udp::crypto::{
        aes_gcm_decrypt, aes_gcm_encrypt, hkdf_sha256, hmac_sha256, hmac_verify,
    };
    use smol::channel::Receiver;
    use std::collections::HashMap;

    const PSK: &str = "loopback-psk";
    const CONN_ID: &str = "udp-session-loopback";
    const SESSION_ID: [u8; 16] = [3u8; 16];
    const NONCE_B: [u8; 16] = [4u8; 16];
    const TAG_LEN: usize = 16;

    /// Client configuration: connects to a local peer, binds the loopback address explicitly (the Connected event carries the real local port).
    fn client_config(peer_port: u16) -> ClientConfig {
        ClientConfig {
            id: CONN_ID.to_string(),
            protocol: ConnectionType::UdpSession,
            server_address: "127.0.0.1".to_string(),
            server_port: peer_port,
            local_address: Some("127.0.0.1".to_string()),
            udp_session: Some(UdpSessionSettings {
                psk: PSK.to_string(),
                handshake_timeout_ms: 1000,
                hello_retries: 3,
            }),
            ..Default::default()
        }
    }

    /// Build a rule set that answers "RULE" to every frame: the client must never call it.
    fn rules_store() -> Arc<ReplyRulesStore> {
        let store = ReplyRulesStore::new();
        let mut rule = ReplyRule::new("loopback", 0);
        rule.payload = ReplyPayload {
            text: "RULE".to_string(),
            ..Default::default()
        };
        let mut config = ReplyRulesConfig::default();
        config.connections.insert(CONN_ID.to_string(), vec![rule]);
        store.replace(&config);
        store.set_connection_gates(HashMap::from([(CONN_ID.to_string(), true)]));
        store
    }

    async fn next_event(rx: &Receiver<ConnectionEvent>) -> ConnectionEvent {
        tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timed out waiting for an event")
            .expect("the event channel is closed")
    }

    /// Wait for an event that matches the condition; the other events of the period are returned as well (used to assert that unwanted events did not appear).
    async fn wait_for<F>(
        rx: &Receiver<ConnectionEvent>,
        mut pred: F,
    ) -> (ConnectionEvent, Vec<ConnectionEvent>)
    where
        F: FnMut(&ConnectionEvent) -> bool,
    {
        let mut others = Vec::new();
        loop {
            let ev = next_event(rx).await;
            if pred(&ev) {
                return (ev, others);
            }
            others.push(ev);
        }
    }

    /// Collect the events of the window (without waiting for a match).
    async fn collect_for(rx: &Receiver<ConnectionEvent>, dur: Duration) -> Vec<ConnectionEvent> {
        let mut out = Vec::new();
        let deadline = tokio::time::Instant::now() + dur;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, rx.recv()).await {
                Ok(Ok(ev)) => out.push(ev),
                _ => break,
            }
        }
        out
    }

    /// The peer receives a HELLO: returns (nonce_a, client address, raw bytes).
    async fn recv_hello(peer: &UdpSocket) -> ([u8; 16], SocketAddr, Vec<u8>) {
        let mut buf = [0u8; 2048];
        let (n, src) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buf))
            .await
            .expect("timed out waiting for HELLO")
            .expect("failed to receive HELLO");
        let bytes = buf[..n].to_vec();
        match decode(&bytes).expect("HELLO should parse") {
            Packet::Hello { nonce_a, proof_a } => {
                assert!(
                    hmac_verify(PSK.as_bytes(), &hello_mac_input(&nonce_a), &proof_a),
                    "the HELLO proof should be computed from the same PSK"
                );
                (nonce_a, src, bytes)
            }
            other => panic!("expected HELLO, got {other:?}"),
        }
    }

    /// HKDF salt = nonce_a || nonce_b
    fn salt(nonce_a: [u8; 16]) -> Vec<u8> {
        nonce_a.into_iter().chain(NONCE_B).collect()
    }

    fn session_key(nonce_a: [u8; 16]) -> [u8; 32] {
        hkdf_sha256(PSK.as_bytes(), &salt(nonce_a), HKDF_INFO)
    }

    /// The peer sends a DATA packet.
    async fn peer_send_data(
        peer: &UdpSocket,
        client_addr: SocketAddr,
        nonce_a: [u8; 16],
        seq: u64,
        plain: &[u8],
    ) {
        let key = session_key(nonce_a);
        let cipher_len = (plain.len() + TAG_LEN) as u16;
        let ct = aes_gcm_encrypt(
            &key,
            &data_nonce(&SESSION_ID, seq),
            &data_aad(&SESSION_ID, seq, cipher_len),
            plain,
        )
        .unwrap();
        peer.send_to(
            &encode(&Packet::Data {
                session_id: SESSION_ID,
                seq,
                ciphertext: ct,
            }),
            client_addr,
        )
        .await
        .unwrap();
    }

    /// Establish the session: handshake plus the write channel.
    async fn establish(
        peer: &UdpSocket,
        rx: &Receiver<ConnectionEvent>,
    ) -> ([u8; 16], SocketAddr, Sender<WireMessage>) {
        let (nonce_a, client_addr, _hello) = recv_hello(peer).await;
        let proof_b = hmac_sha256(PSK.as_bytes(), &session_ok_mac_input(&SESSION_ID, &NONCE_B));
        peer.send_to(
            &encode(&Packet::SessionOk {
                session_id: SESSION_ID,
                nonce_b: NONCE_B,
                proof_b,
            }),
            client_addr,
        )
        .await
        .unwrap();

        // Event order: Connected → ClientWriteSenderReady → StatusHint(waiting) → StatusHint(established).
        let write_tx = loop {
            if let ConnectionEvent::ClientWriteSenderReady(_, s) = next_event(rx).await {
                break s;
            }
        };
        let hint_established = t!("udp_session.hint_established").to_string();
        let (ev, _) = wait_for(
            rx,
            |e| matches!(e, ConnectionEvent::StatusHint(_, t) if *t == hint_established),
        )
        .await;
        assert!(matches!(ev, ConnectionEvent::StatusHint(..)));
        (nonce_a, client_addr, write_tx)
    }

    #[tokio::test]
    async fn loopback_handshake_delivers_plaintext_and_ignores_rules() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let (tx, rx) = smol_unbounded::<ConnectionEvent>();
        let mut client = UdpSessionClient::new(
            client_config(peer_addr.port()),
            Some(tx),
            None,
            TrailerSetting::default(),
            rules_store(),
        );
        client.connect().await.unwrap();

        // 1) The peer receives a HELLO: neither PSK bytes nor JSON.
        let (nonce_a, client_addr, hello_bytes) = recv_hello(&peer).await;
        assert!(
            !hello_bytes.windows(PSK.len()).any(|w| w == PSK.as_bytes()),
            "the PSK must not appear in HELLO"
        );
        assert!(!hello_bytes.starts_with(b"{"), "HELLO is not JSON");

        // 2) The peer answers with SessionOk → the session is established.
        let proof_b = hmac_sha256(PSK.as_bytes(), &session_ok_mac_input(&SESSION_ID, &NONCE_B));
        peer.send_to(
            &encode(&Packet::SessionOk {
                session_id: SESSION_ID,
                nonce_b: NONCE_B,
                proof_b,
            }),
            client_addr,
        )
        .await
        .unwrap();

        let hint_established = t!("udp_session.hint_established").to_string();
        let hint_waiting = t!("udp_session.hint_waiting").to_string();
        let mut write_tx = None;
        let mut seen_established = false;
        for _ in 0..4 {
            let ev = next_event(&rx).await;
            match ev {
                ConnectionEvent::Connected(_, _) => {}
                ConnectionEvent::ClientWriteSenderReady(_, s) => write_tx = Some(s),
                ConnectionEvent::StatusHint(_, text) => {
                    if text == hint_established {
                        assert!(
                            !text.contains(PSK),
                            "the PSK must not appear in the status hint"
                        );
                        seen_established = true;
                    } else {
                        assert_eq!(
                            text, hint_waiting,
                            "only the waiting hint is expected during the handshake"
                        );
                    }
                }
                other => panic!("unexpected event: {other:?}"),
            }
            if seen_established {
                break;
            }
        }
        assert!(
            seen_established,
            "a status hint is expected after the session is established"
        );
        let write_tx = write_tx.expect("there should be a write channel");

        // 3) The user sends "ping" → the peer receives a DATA, the decrypted plain text is "ping".
        write_tx
            .send(WireMessage::inherit(b"ping".to_vec()))
            .await
            .unwrap();
        let mut buf = [0u8; 2048];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let (seq, ciphertext) = match decode(&buf[..n]).unwrap() {
            Packet::Data {
                session_id,
                seq,
                ciphertext,
            } => {
                assert_eq!(session_id, SESSION_ID);
                (seq, ciphertext)
            }
            other => panic!("expected DATA, got {other:?}"),
        };
        let key = session_key(nonce_a);
        let plain = aes_gcm_decrypt(
            &key,
            &data_nonce(&SESSION_ID, seq),
            &data_aad(&SESSION_ID, seq, ciphertext.len() as u16),
            &ciphertext,
        )
        .unwrap();
        assert_eq!(plain, b"ping");

        // The rules must not be called: there is no second datagram.
        let mut buf2 = [0u8; 2048];
        assert!(
            tokio::time::timeout(Duration::from_millis(300), peer.recv_from(&mut buf2))
                .await
                .is_err(),
            "the reply rules must not be called"
        );

        // 4) The peer sends DATA seq=1 → the client gets one MessagesReceived, the plain text is JSON.
        peer_send_data(&peer, client_addr, nonce_a, 1, b"{\"a\":1}").await;
        let (ev, others) =
            wait_for(&rx, |e| matches!(e, ConnectionEvent::MessagesReceived(..))).await;
        assert!(
            others
                .iter()
                .all(|e| !matches!(e, ConnectionEvent::MessagesReceived(..))),
            "the handshake packets must not enter the message list"
        );
        match ev {
            ConnectionEvent::MessagesReceived(_, batch) => {
                assert_eq!(batch.count, 1);
                assert_eq!(batch.bytes, 7);
                assert_eq!(batch.messages.len(), 1);
                assert_eq!(&*batch.messages[0].raw_data, b"{\"a\":1}");
                assert_eq!(
                    batch.messages[0].source.as_deref(),
                    Some(peer_addr.to_string().as_str())
                );
            }
            other => panic!("expected MessagesReceived, got {other:?}"),
        }

        // 5) The peer sends Close → Disconnected, no Error.
        peer.send_to(
            &encode(&Packet::Close {
                session_id: SESSION_ID,
                seq: 0,
            }),
            client_addr,
        )
        .await
        .unwrap();
        let (ev, others) = wait_for(&rx, |e| matches!(e, ConnectionEvent::Disconnected(..))).await;
        assert!(matches!(ev, ConnectionEvent::Disconnected(..)));
        assert!(
            others
                .iter()
                .all(|e| !matches!(e, ConnectionEvent::Error(..))),
            "Close must not produce an Error"
        );
    }

    #[tokio::test]
    async fn loopback_send_during_handshake_is_not_plaintext() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let (tx, rx) = smol_unbounded::<ConnectionEvent>();
        let mut client = UdpSessionClient::new(
            client_config(peer_addr.port()),
            Some(tx),
            None,
            TrailerSetting::default(),
            rules_store(),
        );
        client.connect().await.unwrap();

        // Take the write channel (the handshake is not over yet).
        let write_tx = loop {
            if let ConnectionEvent::ClientWriteSenderReady(_, s) = next_event(&rx).await {
                break s;
            }
        };
        write_tx
            .send(WireMessage::inherit(b"open text".to_vec()))
            .await
            .unwrap();

        // The events carry a Warning(not established), and no plain text.
        let (ev, _) = wait_for(&rx, |e| matches!(e, ConnectionEvent::Warning(..))).await;
        match ev {
            ConnectionEvent::Warning(_, text) => {
                assert_eq!(text, t!("udp_session.warn_not_established").to_string());
                assert!(
                    !text.contains("open text"),
                    "the plain text must not appear in the warning"
                );
            }
            other => panic!("expected Warning, got {other:?}"),
        }

        // The peer side only sees a HELLO.
        let mut buf = [0u8; 2048];
        let (_n, _) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(buf[3], 1, "only HELLO (type=1) should be seen");

        // Within 200 ms there is no second datagram: the plain text did not go on the wire.
        let mut buf2 = [0u8; 2048];
        assert!(
            tokio::time::timeout(Duration::from_millis(200), peer.recv_from(&mut buf2))
                .await
                .is_err(),
            "the plain text must not go on the wire before the handshake is over"
        );
    }

    #[tokio::test]
    async fn loopback_foreign_sender_does_not_establish() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let (tx, rx) = smol_unbounded::<ConnectionEvent>();
        let mut client = UdpSessionClient::new(
            client_config(peer_addr.port()),
            Some(tx),
            None,
            TrailerSetting::default(),
            rules_store(),
        );
        client.connect().await.unwrap();

        // Take the local address (the Connected event carries the real local port).
        let local = loop {
            if let ConnectionEvent::Connected(_, addr) = next_event(&rx).await {
                break addr;
            }
        };

        // A SessionOk from another address must not establish a session.
        let foreign = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let proof_b = hmac_sha256(PSK.as_bytes(), &session_ok_mac_input(&SESSION_ID, &NONCE_B));
        foreign
            .send_to(
                &encode(&Packet::SessionOk {
                    session_id: SESSION_ID,
                    nonce_b: NONCE_B,
                    proof_b,
                }),
                local,
            )
            .await
            .unwrap();

        let hint_established = t!("udp_session.hint_established").to_string();
        let events = collect_for(&rx, Duration::from_millis(300)).await;
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, ConnectionEvent::StatusHint(_, t) if *t == hint_established)),
            "a packet of another peer must not establish a session"
        );

        // The real peer answers afterwards → hint_established arrives.
        let (_, client_addr, _) = recv_hello(&peer).await;
        peer.send_to(
            &encode(&Packet::SessionOk {
                session_id: SESSION_ID,
                nonce_b: NONCE_B,
                proof_b: hmac_sha256(PSK.as_bytes(), &session_ok_mac_input(&SESSION_ID, &NONCE_B)),
            }),
            client_addr,
        )
        .await
        .unwrap();
        let (ev, _) = wait_for(
            &rx,
            |e| matches!(e, ConnectionEvent::StatusHint(_, t) if *t == hint_established),
        )
        .await;
        assert!(matches!(ev, ConnectionEvent::StatusHint(..)));
    }

    #[tokio::test]
    async fn loopback_trailer_is_not_appended() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let (tx, rx) = smol_unbounded::<ConnectionEvent>();
        let mut config = client_config(peer_addr.port());
        config.send_trailer = TrailerKind::CrLf;
        let mut client = UdpSessionClient::new(
            config,
            Some(tx),
            None,
            TrailerSetting::new(TrailerKind::CrLf),
            rules_store(),
        );
        client.connect().await.unwrap();

        let (nonce_a, _client_addr, write_tx) = establish(&peer, &rx).await;
        write_tx
            .send(WireMessage::inherit(b"hi".to_vec()))
            .await
            .unwrap();

        let mut buf = [0u8; 2048];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let (seq, ciphertext) = match decode(&buf[..n]).unwrap() {
            Packet::Data {
                session_id,
                seq,
                ciphertext,
            } => {
                assert_eq!(session_id, SESSION_ID);
                (seq, ciphertext)
            }
            other => panic!("expected DATA, got {other:?}"),
        };
        let key = session_key(nonce_a);
        let plain = aes_gcm_decrypt(
            &key,
            &data_nonce(&SESSION_ID, seq),
            &data_aad(&SESSION_ID, seq, ciphertext.len() as u16),
            &ciphertext,
        )
        .unwrap();
        assert_eq!(
            plain, b"hi",
            "the DATA payload must not be appended with a trailer"
        );
    }

    #[tokio::test]
    async fn loopback_oversize_warns_and_session_stays() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let (tx, rx) = smol_unbounded::<ConnectionEvent>();
        let mut client = UdpSessionClient::new(
            client_config(peer_addr.port()),
            Some(tx),
            None,
            TrailerSetting::default(),
            rules_store(),
        );
        client.connect().await.unwrap();

        let (nonce_a, client_addr, _write_tx) = establish(&peer, &rx).await;

        // A datagram longer than 2048 bytes: a warning, it does not reach the state machine.
        peer.send_to(&vec![0u8; 2049], client_addr).await.unwrap();
        let (ev, _) = wait_for(&rx, |e| matches!(e, ConnectionEvent::Warning(..))).await;
        match ev {
            ConnectionEvent::Warning(_, text) => {
                assert_eq!(text, t!("udp_session.warn_too_long").to_string());
            }
            other => panic!("expected Warning, got {other:?}"),
        }

        // The session is still alive: the next DATA is delivered as usual.
        peer_send_data(&peer, client_addr, nonce_a, 1, b"ok").await;
        let (ev, others) =
            wait_for(&rx, |e| matches!(e, ConnectionEvent::MessagesReceived(..))).await;
        assert!(
            others
                .iter()
                .all(|e| !matches!(e, ConnectionEvent::Error(..)))
        );
        match ev {
            ConnectionEvent::MessagesReceived(_, batch) => {
                assert_eq!(batch.messages.len(), 1);
                assert_eq!(&*batch.messages[0].raw_data, b"ok");
            }
            other => panic!("expected MessagesReceived, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn empty_psk_returns_before_bind() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let mut config = client_config(peer_addr.port());
        config.udp_session = Some(UdpSessionSettings {
            psk: String::new(),
            ..Default::default()
        });
        let (tx, _rx) = smol_unbounded::<ConnectionEvent>();
        let mut client = UdpSessionClient::new(
            config,
            Some(tx),
            None,
            TrailerSetting::default(),
            rules_store(),
        );

        let err = client.connect().await.unwrap_err();
        assert_eq!(err.to_string(), t!("udp_session.err_empty_psk").to_string());
        assert!(!err.to_string().is_empty());

        // Not a single byte goes on the wire.
        let mut buf = [0u8; 2048];
        assert!(
            tokio::time::timeout(Duration::from_millis(200), peer.recv_from(&mut buf))
                .await
                .is_err(),
            "no datagram should be sent with an empty PSK"
        );
    }

    #[tokio::test]
    async fn server_start_errors() {
        let mut server = UdpSessionServer::new(
            ServerConfig::default(),
            None,
            None,
            TrailerSetting::default(),
        );
        let err = server.start().await.unwrap_err();
        assert_eq!(err.to_string(), t!("udp_session.err_no_server").to_string());
    }
}
