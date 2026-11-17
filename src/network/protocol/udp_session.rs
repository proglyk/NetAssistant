//! UDP Session client: the HELLO / CHALLENGE / RESPONSE / SESSION_OK
//! handshake.
//!
//! Differences from the plain UDP client:
//! - the handshake runs in the protocol layer; user bytes never reach the wire
//!   before it is over (clear text must not leak).
//!
//! The byte contract lives in `src/session_udp/codec.rs` and in
//! `docs-dev/specs/2026-11-17-udp-session-b-handshake.md` (handshake).

use crate::config::connection::{ClientConfig, ServerConfig, TrailerSetting};
use crate::network::events::{ConnectionEvent, NetCounters};
use crate::network::interfaces::{NetworkConnection, NetworkServer};
use crate::reply::ReplyRulesStore;
use crate::session_udp::codec::{HANDSHAKE_NONCE_LEN, MAX_DATAGRAM, encode};
use crate::session_udp::machine::{Action, Command, Machine};
use log::{debug, error, info};
use rust_i18n::t;
use smol::channel::{Sender, unbounded as smol_unbounded};
use std::any::Any;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

/// Buffer size of a single recv call. The UDP datagram limit is 65507 bytes, the buffer takes 65535.
const RECV_BUFFER_SIZE: usize = 65535;

/// The current time in Unix seconds: it fills the header timestamp.
///
/// The state machine has no clock of its own: time arrives from outside, so
/// the tests stay deterministic.
fn unix_now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().min(u32::MAX as u64) as u32)
        .unwrap_or(0)
}

/// Translate a failure token of the state machine into interface text.
///
/// The tokens are fixed English phrases (see `session_udp::machine`); this function only
/// maps them and never echoes a key.
fn fail_text(token: &str) -> String {
    // The SESSION_ERR reason code (protocol §5.10) is a single byte; the
    // machine reports it in decimal.
    if let Some(detail) = token.strip_prefix("session err ") {
        return match detail {
            "1" => t!("udp_session.err_auth_failed").to_string(),
            "2" => t!("udp_session.err_max_sessions").to_string(),
            "3" => t!("udp_session.err_not_bound").to_string(),
            "4" => t!("udp_session.err_rate_limited").to_string(),
            "5" => t!("udp_session.err_version_mismatch").to_string(),
            other => t!("udp_session.err_session", detail = other).to_string(),
        };
    }
    match token {
        "empty psk" => t!("udp_session.err_empty_psk").to_string(),
        "handshake timeout" => t!("udp_session.err_handshake_timeout").to_string(),
        "bad proof" => t!("udp_session.err_bad_proof").to_string(),
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
    /// Runtime "append trailer" setting: this connection does not read it (the session payload
    /// must not be polluted with appended bytes).
    _trailer: TrailerSetting,
    /// Shared reply rules state: this connection does not call them (rules must not act on
    /// session data).
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
        // An empty PSK is rejected before the connection: not a single byte goes on the wire,
        // and the event channel reports no Error.
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

            // Local bind: without a configured address the wildcard address of the remote address
            // family is used, with an automatic port.
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
            // connect makes the kernel receive the datagrams of the peer only: packets of others
            // cannot enter the handshake.
            socket.connect(server_addr).await.map_err(|e| {
                format!(
                    "failed to connect to the UDP Session server {}: {}",
                    server_addr, e
                )
            })?;

            // nonce_a comes from outside: the state machine has no random
            // source of its own
            let mut nonce_a = [0u8; HANDSHAKE_NONCE_LEN];
            getrandom::fill(&mut nonce_a)
                .map_err(|e| format!("failed to generate the handshake random bytes: {}", e))?;

            let mut machine = Machine::new();
            let actions = machine.handle(
                Command::Start {
                    nonce_a,
                    psk: settings.psk.clone(),
                    hello_retries: settings.hello_retries,
                },
                unix_now(),
            );

            let socket = Arc::new(socket);
            // The first HELLO goes on the wire right away: even a failed handshake has to make the
            // peer see us.
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

            let id = config.id.clone();
            if let Some(sender) = &event_sender {
                let _ = sender
                    .send(ConnectionEvent::Connected(id.clone(), local_addr))
                    .await;
                let _ = sender
                    .send(ConnectionEvent::StatusHint(
                        id.clone(),
                        t!("udp_session.hint_waiting").to_string(),
                    ))
                    .await;
            }

            let cancel = cancel_token.clone();
            let event_sender_loop = event_sender.clone();
            let net_counters_loop = net_counters.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; RECV_BUFFER_SIZE];
                // The handshake timer is armed while waiting only: after the session is established
                // no HELLO is repeated.
                let mut waiting = true;
                let timeout = Duration::from_millis(settings.handshake_timeout_ms.max(1));
                let sleep = tokio::time::sleep(timeout);
                tokio::pin!(sleep);
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => {
                            break;
                        }
                        _ = &mut sleep, if waiting => {
                            let actions = machine.handle(Command::Tick, unix_now());
                            sleep.as_mut().reset(tokio::time::Instant::now() + timeout);
                            let flow = apply(&actions, &socket, &event_sender_loop, &id, &net_counters_loop).await;
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
                                    // An oversized datagram does not reach the state machine: only a warning, the
                                                                        // session continues.
                                    if n > MAX_DATAGRAM {
                                        if let Some(sender) = &event_sender_loop {
                                            let _ = sender.send(ConnectionEvent::Warning(
                                                id.clone(),
                                                t!("udp_session.warn_too_long").to_string(),
                                            )).await;
                                        }
                                        continue;
                                    }
                                    let actions = machine.on_datagram(&buf[..n], unix_now());
                                    let flow = apply(&actions, &socket, &event_sender_loop, &id, &net_counters_loop).await;
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
    /// Fallback for a drop that bypasses disconnect(): stop the background task, so that
    /// no orphan task keeps the socket.
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
    net_counters: &Option<NetCounters>,
) -> Flow {
    let mut flow = Flow::Continue;
    for action in actions {
        match action {
            Action::Send(frame) => {
                let bytes = encode(&frame);
                match socket.send(&bytes).await {
                    Ok(_) => {
                        if let Some(c) = net_counters {
                            c.add_sent(1);
                            c.add_sent_bytes(bytes.len() as u64);
                        }
                    }
                    Err(e) => {
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
    use crate::config::connection::{ConnectionType, UdpSessionSettings};
    use crate::reply::model::{ReplyPayload, ReplyRule, ReplyRulesConfig};
    use crate::session_udp::codec::{
        Body, Frame, Header, PacketType, decode, proof_a_input, proof_b_input,
    };
    use crate::session_udp::crypto::hmac_sha256;
    use smol::channel::Receiver;
    use std::collections::HashMap;

    const PSK: &str = "loopback-psk";
    const CONN_ID: &str = "udp-session-loopback";
    const SESSION_ID: u16 = 0x1234;
    const NONCE_B: [u8; HANDSHAKE_NONCE_LEN] = [4u8; HANDSHAKE_NONCE_LEN];

    /// Client configuration: connects to a local peer, binds the loopback address explicitly
    /// (the Connected event carries the real local port).
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

    /// Wait for an event that matches the condition; the other events of the period are
    /// returned as well (used to assert that unwanted events did not appear).
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
    async fn recv_hello(peer: &UdpSocket) -> ([u8; HANDSHAKE_NONCE_LEN], SocketAddr, Vec<u8>) {
        let mut buf = [0u8; 2048];
        let (n, src) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buf))
            .await
            .expect("timed out waiting for HELLO")
            .expect("failed to receive HELLO");
        let bytes = buf[..n].to_vec();
        let frame = decode(&bytes).expect("HELLO should parse");
        assert_eq!(frame.header.packet_type, PacketType::Hello);
        assert_eq!(frame.header.session_id, 0);
        let Body::Hello { nonce_a } = frame.body else {
            panic!("expected a HELLO body")
        };
        (nonce_a, src, bytes)
    }

    /// The peer sends a CHALLENGE: nonce_b ‖ proof_b.
    async fn peer_send_challenge(
        peer: &UdpSocket,
        client_addr: SocketAddr,
        nonce_a: [u8; HANDSHAKE_NONCE_LEN],
    ) {
        let proof_b = hmac_sha256(PSK.as_bytes(), &proof_b_input(&nonce_a, &NONCE_B));
        let frame = Frame {
            header: Header {
                packet_type: PacketType::Challenge,
                session_id: 0,
                seq: 0,
                timestamp: unix_now(),
            },
            body: Body::Challenge {
                nonce_b: NONCE_B,
                proof_b,
            },
        };
        peer.send_to(&encode(&frame), client_addr).await.unwrap();
    }

    /// The peer receives a RESPONSE: checks proof_a.
    async fn peer_recv_response(peer: &UdpSocket, nonce_a: [u8; HANDSHAKE_NONCE_LEN]) {
        let mut buf = [0u8; 2048];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buf))
            .await
            .expect("timed out waiting for RESPONSE")
            .expect("failed to receive RESPONSE");
        let frame = decode(&buf[..n]).expect("RESPONSE should parse");
        assert_eq!(frame.header.packet_type, PacketType::Response);
        assert_eq!(frame.header.session_id, 0);
        let Body::Response { proof_a } = frame.body else {
            panic!("expected a RESPONSE body")
        };
        let expected = hmac_sha256(PSK.as_bytes(), &proof_a_input(&NONCE_B, &nonce_a));
        assert_eq!(
            proof_a, expected,
            "the RESPONSE proof should be computed from the same PSK"
        );
    }

    /// The peer sends a SESSION_OK: the session opens.
    async fn peer_send_session_ok(peer: &UdpSocket, client_addr: SocketAddr) {
        let frame = Frame {
            header: Header {
                packet_type: PacketType::SessionOk,
                session_id: SESSION_ID,
                seq: 0,
                timestamp: unix_now(),
            },
            body: Body::SessionOk,
        };
        peer.send_to(&encode(&frame), client_addr).await.unwrap();
    }

    #[tokio::test]
    async fn loopback_handshake_opens_the_session() {
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
        assert_eq!(hello_bytes.len(), 12 + HANDSHAKE_NONCE_LEN);

        // 2) The handshake: CHALLENGE → RESPONSE → SESSION_OK.
        peer_send_challenge(&peer, client_addr, nonce_a).await;
        peer_recv_response(&peer, nonce_a).await;
        peer_send_session_ok(&peer, client_addr).await;

        // Event order: Connected → StatusHint(waiting) → StatusHint(established).
        let hint_established = t!("udp_session.hint_established").to_string();
        let hint_waiting = t!("udp_session.hint_waiting").to_string();
        let mut seen_established = false;
        for _ in 0..3 {
            let ev = next_event(&rx).await;
            match ev {
                ConnectionEvent::Connected(_, _) => {}
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

        // A CHALLENGE from another address must not establish a session.
        let foreign = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let proof_b = hmac_sha256(PSK.as_bytes(), &proof_b_input(&[1u8; 32], &NONCE_B));
        let challenge = Frame {
            header: Header {
                packet_type: PacketType::Challenge,
                session_id: 0,
                seq: 0,
                timestamp: unix_now(),
            },
            body: Body::Challenge {
                nonce_b: NONCE_B,
                proof_b,
            },
        };
        foreign.send_to(&encode(&challenge), local).await.unwrap();

        let hint_established = t!("udp_session.hint_established").to_string();
        let events = collect_for(&rx, Duration::from_millis(300)).await;
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, ConnectionEvent::StatusHint(_, t) if *t == hint_established)),
            "a packet of another peer must not establish a session"
        );

        // The real peer answers afterwards → hint_established arrives.
        let (nonce_a, client_addr, _) = recv_hello(&peer).await;
        peer_send_challenge(&peer, client_addr, nonce_a).await;
        peer_recv_response(&peer, nonce_a).await;
        peer_send_session_ok(&peer, client_addr).await;
        let (ev, _) = wait_for(
            &rx,
            |e| matches!(e, ConnectionEvent::StatusHint(_, t) if *t == hint_established),
        )
        .await;
        assert!(matches!(ev, ConnectionEvent::StatusHint(..)));
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
