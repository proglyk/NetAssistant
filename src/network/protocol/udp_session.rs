//! UDP Session client: HELLO / CHALLENGE / RESPONSE / SESSION_OK handshake plus
//! an AES-256-GCM session.
//!
//! Differences from the plain UDP client:
//! - the handshake runs in the protocol layer; user bytes never reach the wire
//!   before it is over (clear text must not leak);
//! - session data travels in DATA frames (ciphertext plus a 16-byte GCM tag);
//!   the log gets one staged line per stage a frame passed, and the open
//!   text is the `payload` field of the decoder line;
//! - reply rules stay out: rules on plain text would bypass GCM authentication.
//!
//! The byte contract lives in `src/session_udp/codec.rs` and in
//! `docs-dev/specs/2026-11-17-udp-session-b-handshake.md` (handshake) and
//! `docs-dev/specs/2026-11-17-udp-session-c-data-close.md` (DATA / CLOSE).

use crate::config::connection::{ClientConfig, ServerConfig, TrailerSetting};
use crate::message::{Message, MessageDirection, MessageStage, MessageType};
use crate::network::events::{ConnectionEvent, NetCounters, WireMessage};
use crate::network::interfaces::{NetworkConnection, NetworkServer};
use crate::reply::ReplyRulesStore;
use crate::session_udp::codec::{
    Frame, HANDSHAKE_NONCE_LEN, PacketType, encode, format_frame_fields,
};
use crate::session_udp::machine::{
    Action, Command, CommandReply, Machine, PendingCommand, ReplyOutcome, Trace,
};
use log::{debug, error, info, warn};
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

/// The placeholder of a value the device did not send (a malformed answer).
const EMPTY_VALUE: &str = "—";

/// The current time in Unix seconds: it fills the header timestamp and bounds
/// the replay window.
///
/// The state machine has no clock of its own: time arrives from outside, so
/// the tests stay deterministic.
fn unix_now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().min(u32::MAX as u64) as u32)
        .unwrap_or(0)
}

/// The five random bytes of the nonce tail.
///
/// The random source is outside the state machine too: the machine is pure
/// logic.
fn nonce_tail() -> Option<[u8; 5]> {
    let mut tail = [0u8; 5];
    match getrandom::fill(&mut tail) {
        Ok(()) => Some(tail),
        Err(e) => {
            error!("[UDP Session] failed to generate random bytes: {:?}", e);
            None
        }
    }
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
        "seq exhausted" => t!("udp_session.err_seq_exhausted").to_string(),
        other => other.to_string(),
    }
}

/// Translate a warning token of the state machine into interface text.
fn warn_text(token: &str) -> String {
    match token {
        "not established" => t!("udp_session.warn_not_established").to_string(),
        "foreign session" => t!("udp_session.warn_foreign_session").to_string(),
        "bad nonce" => t!("udp_session.warn_bad_nonce").to_string(),
        "timestamp out of window" => t!("udp_session.warn_timestamp_out_of_window").to_string(),
        "bad tag" => t!("udp_session.warn_bad_tag").to_string(),
        "bad seq" => t!("udp_session.warn_bad_seq").to_string(),
        "payload too large" => t!("udp_session.warn_payload_too_large").to_string(),
        "unexpected packet" => t!("udp_session.warn_unexpected_packet").to_string(),
        "bad datagram" => t!("udp_session.warn_bad_datagram").to_string(),
        "too long" => t!("udp_session.warn_too_long").to_string(),
        other => other.to_string(),
    }
}

/// Translate a protocol event into the lines of the session window.
///
/// Every line carries a stage (the scheme of `docs-dev/pictures/udp-path.png`);
/// a frame produces exactly one line per stage it passed.
fn trace_lines(trace: &Trace) -> Vec<(MessageStage, MessageDirection, String)> {
    let line = match trace {
        Trace::Datagram { len } => (
            MessageStage::Socket,
            MessageDirection::Received,
            t!("udp_session.trace_datagram", len = *len).to_string(),
        ),
        Trace::NotAFrame => (
            MessageStage::Decoder,
            MessageDirection::Received,
            t!("udp_session.trace_not_a_frame").to_string(),
        ),
        Trace::Decoded {
            frame,
            plain,
            tag_failed,
        } => {
            let mut text = format_frame_fields(frame, plain.as_deref());
            if *tag_failed {
                text.push('\n');
                text.push_str(&t!("udp_session.trace_tag_failed"));
            }
            (MessageStage::Decoder, MessageDirection::Received, text)
        }
        Trace::ProofB { valid } => (
            MessageStage::Handshake,
            MessageDirection::Received,
            if *valid {
                t!("udp_session.trace_proof_b_ok").to_string()
            } else {
                t!("udp_session.trace_proof_b_bad").to_string()
            },
        ),
        Trace::SessionOpen => (
            MessageStage::Session,
            MessageDirection::Received,
            t!("udp_session.trace_open_session").to_string(),
        ),
    };
    vec![line]
}

/// The sender stage: what goes out, with which cipher, and with what result.
async fn send_trace(
    event_sender: &Option<Sender<ConnectionEvent>>,
    id: &str,
    direction: MessageDirection,
    stage: MessageStage,
    text: String,
) {
    let Some(sender) = event_sender else {
        return;
    };
    let message = Message::new(direction, text.into_bytes(), MessageType::Text).with_stage(stage);
    let _ = sender
        .send(ConnectionEvent::MessageReceived(id.to_string(), message))
        .await;
}

/// The sender stage line of a frame that goes out: the fields of the frame.
///
/// The open text of an encrypted frame is the `payload` field of the same
/// line; the ciphertext is never written.
async fn sender_stage_lines(
    event_sender: &Option<Sender<ConnectionEvent>>,
    id: &str,
    frame: &Frame,
    plain: Option<&[u8]>,
) {
    let text = format_frame_fields(frame, plain);
    send_trace(
        event_sender,
        id,
        MessageDirection::Sent,
        MessageStage::Sender,
        text,
    )
    .await;
}

/// The close reason of the peer, in interface text (protocol §5.9).
fn close_reason_text(reason: &str) -> String {
    match reason {
        "user_disconnect" => t!("udp_session.close_user_disconnect").to_string(),
        "timeout" => t!("udp_session.close_timeout").to_string(),
        "secret_rotated" => t!("udp_session.close_secret_rotated").to_string(),
        "error" => t!("udp_session.close_error").to_string(),
        "" => t!("udp_session.close_unknown_reason").to_string(),
        other => t!("udp_session.close_unknown", reason = other).to_string(),
    }
}

/// The answer of the device, in interface text (protocol §2.5.2, §2.5.3).
///
/// The plain text of the answer stays in the message list: this text is the
/// short summary next to it.
fn reply_text(reply: &CommandReply) -> String {
    let command = reply.command.as_ref().map(command_label);
    match (&reply.outcome, command) {
        (ReplyOutcome::Ack { result }, Some(command)) => t!(
            "udp_session.reply_ack_command",
            command = command.as_str(),
            result = result.as_deref().unwrap_or(EMPTY_VALUE)
        )
        .to_string(),
        (ReplyOutcome::Ack { result }, None) => t!(
            "udp_session.reply_ack",
            result = result.as_deref().unwrap_or(EMPTY_VALUE)
        )
        .to_string(),
        (ReplyOutcome::Error { code }, Some(command)) => t!(
            "udp_session.reply_error_command",
            command = command.as_str(),
            code = code.as_deref().unwrap_or(EMPTY_VALUE)
        )
        .to_string(),
        (ReplyOutcome::Error { code }, None) => t!(
            "udp_session.reply_error",
            code = code.as_deref().unwrap_or(EMPTY_VALUE)
        )
        .to_string(),
    }
}

/// The label of a command: the name with the identifier, when the name is
/// known.
fn command_label(command: &PendingCommand) -> String {
    match &command.cmd {
        Some(cmd) => format!("{cmd} ({})", command.msg_id),
        None => command.msg_id.clone(),
    }
}

/// UDP Session client.
pub struct UdpSessionClient {
    config: ClientConfig,
    event_sender: Option<Sender<ConnectionEvent>>,
    net_counters: Option<NetCounters>,
    is_connected: bool,
    cancel_token: CancellationToken,
    /// Runtime "append trailer" setting: this connection does not read it (the DATA payload
    /// must not be polluted with appended bytes).
    _trailer: TrailerSetting,
    /// Shared reply rules state: this connection does not call them (rules must not act on
    /// ciphertext).
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
                if let Action::Send(packet, plain) = action {
                    // The sender stage shows the frame before it goes out.
                    sender_stage_lines(&event_sender, &config.id, packet, plain.as_deref()).await;
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
                            // An encrypted CLOSE goes out first, so the peer
                            // knows the user left
                            let tail = nonce_tail().unwrap_or([0u8; 5]);
                            let actions = machine.handle(Command::UserDisconnect { nonce_tail: tail }, unix_now());
                            let _ = apply(&actions, &socket, &event_sender_loop, &id, &net_counters_loop).await;
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
                                    // Every datagram reaches the state machine: an
                                    // oversized one is not a frame, and the journal
                                    // says so.
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
                        incoming = rx.recv() => {
                            match incoming {
                                Ok(wire) => {
                                    // The nonce tail needs five random bytes:
                                    // without a random source nothing is sent
                                    let Some(tail) = nonce_tail() else {
                                        if let Some(sender) = &event_sender_loop {
                                            let _ = sender.send(ConnectionEvent::Warning(
                                                id.clone(),
                                                t!("udp_session.warn_random_failed").to_string(),
                                            )).await;
                                        }
                                        continue;
                                    };
                                    // The user bytes enter the state machine as they are: no trailer is appended, the
                                                                        // finalized flag is not read. A marked wire is a command name.
                                    let actions = machine.handle(
                                        command_for_wire(wire.is_session_command(), wire.data(), tail),
                                        unix_now(),
                                    );
                                    let flow = apply(&actions, &socket, &event_sender_loop, &id, &net_counters_loop).await;
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

/// The command of a wire message: a marked wire carries a command name for
/// the state machine, a plain wire carries the editor bytes.
fn command_for_wire(session_command: bool, bytes: &[u8], nonce_tail: [u8; 5]) -> Command {
    if session_command {
        let cmd = String::from_utf8(bytes.to_vec()).unwrap_or_default();
        Command::SendCommand { cmd, nonce_tail }
    } else {
        Command::UserBytes {
            bytes: bytes.to_vec(),
            nonce_tail,
        }
    }
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
            Action::Send(frame, plain) => {
                // The sender stage shows what goes out: the fields of the
                // frame and the open text it carries.
                sender_stage_lines(event_sender, id, &frame, plain.as_deref()).await;
                let bytes = encode(&frame);
                match socket.send(&bytes).await {
                    Ok(_) => {
                        if let Some(c) = net_counters {
                            c.add_sent(1);
                            c.add_sent_bytes(bytes.len() as u64);
                        }
                    }
                    Err(e) => {
                        // A failed Close send does not change the outcome: the session was over anyway.
                        if frame.header.packet_type == PacketType::Close {
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
            Action::Trace(trace) => {
                for (stage, direction, text) in trace_lines(trace) {
                    send_trace(event_sender, id, direction, stage, text).await;
                }
            }
            Action::Deliver(plain) => {
                // The decrypted plain text is already the `payload` field of
                // the decoder line, so only the counters move here.
                let len = plain.len() as u64;
                if let Some(c) = net_counters {
                    c.add_received(1);
                    c.add_received_bytes(len);
                }
            }
            Action::Established { .. } => {
                if let Some(sender) = event_sender {
                    // The session is open: the UI may send commands now.
                    let _ = sender
                        .send(ConnectionEvent::SessionReady(id.to_string()))
                        .await;
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
            Action::Closed { reason } => {
                if let Some(sender) = event_sender {
                    let _ = sender
                        .send(ConnectionEvent::Disconnected(id.to_string()))
                        .await;
                    // The close reason goes after the disconnect: the disconnect handling clears the
                    // status hint.
                    if let Some(reason) = reason {
                        let _ = sender
                            .send(ConnectionEvent::StatusHint(
                                id.to_string(),
                                close_reason_text(&reason),
                            ))
                            .await;
                    }
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
            Action::Reply(reply) => {
                // The plain text of the answer is already in the message list:
                // this is the short summary next to it. A confirmation is a
                // transient hint, a refusal stays as a warning.
                if let Some(sender) = event_sender {
                    let text = reply_text(&reply);
                    let event = if matches!(reply.outcome, ReplyOutcome::Ack { .. }) {
                        ConnectionEvent::StatusHint(id.to_string(), text)
                    } else {
                        ConnectionEvent::Warning(id.to_string(), text)
                    };
                    let _ = sender.send(event).await;
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
        Body, DIRECTION_ESP_TO_APP, Frame, HKDF_INFO, Header, MAX_DATAGRAM, build_nonce, decode,
        header_bytes, proof_a_input, proof_b_input,
    };
    use crate::session_udp::crypto::{aes_gcm_decrypt, aes_gcm_encrypt, hkdf_sha256, hmac_sha256};
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
                seq_num: 0,
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
                seq_num: 0,
                timestamp: unix_now(),
            },
            body: Body::SessionOk,
        };
        peer.send_to(&encode(&frame), client_addr).await.unwrap();
    }

    /// HKDF salt = nonce_a ‖ nonce_b.
    fn salt(nonce_a: [u8; HANDSHAKE_NONCE_LEN]) -> Vec<u8> {
        nonce_a.into_iter().chain(NONCE_B).collect()
    }

    fn session_key(nonce_a: [u8; HANDSHAKE_NONCE_LEN]) -> [u8; 32] {
        hkdf_sha256(PSK.as_bytes(), &salt(nonce_a), HKDF_INFO)
    }

    /// The peer sends an encrypted session frame (DATA or CLOSE).
    async fn peer_send_encrypted(
        peer: &UdpSocket,
        client_addr: SocketAddr,
        nonce_a: [u8; HANDSHAKE_NONCE_LEN],
        packet_type: PacketType,
        seq_num: u32,
        plain: &[u8],
    ) {
        let header = Header {
            packet_type,
            session_id: SESSION_ID,
            seq_num,
            timestamp: unix_now(),
        };
        let nonce = build_nonce(SESSION_ID, DIRECTION_ESP_TO_APP, seq_num, [0xCD; 5]);
        let aad = header_bytes(&header);
        let ciphertext = aes_gcm_encrypt(&session_key(nonce_a), &nonce, &aad, plain).unwrap();
        let frame = Frame {
            header,
            body: Body::Encrypted { nonce, ciphertext },
        };
        peer.send_to(&encode(&frame), client_addr).await.unwrap();
    }

    /// The peer sends a DATA packet.
    async fn peer_send_data(
        peer: &UdpSocket,
        client_addr: SocketAddr,
        nonce_a: [u8; HANDSHAKE_NONCE_LEN],
        seq_num: u32,
        plain: &[u8],
    ) {
        peer_send_encrypted(peer, client_addr, nonce_a, PacketType::Data, seq_num, plain).await;
    }

    /// Establish the session: handshake plus the write channel.
    async fn establish(
        peer: &UdpSocket,
        rx: &Receiver<ConnectionEvent>,
    ) -> ([u8; HANDSHAKE_NONCE_LEN], SocketAddr, Sender<WireMessage>) {
        let (nonce_a, client_addr, _) = recv_hello(peer).await;
        peer_send_challenge(peer, client_addr, nonce_a).await;
        peer_recv_response(peer, nonce_a).await;
        peer_send_session_ok(peer, client_addr).await;

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
        assert_eq!(hello_bytes.len(), 12 + HANDSHAKE_NONCE_LEN);

        // 2) The handshake: CHALLENGE → RESPONSE → SESSION_OK.
        peer_send_challenge(&peer, client_addr, nonce_a).await;
        peer_recv_response(&peer, nonce_a).await;
        peer_send_session_ok(&peer, client_addr).await;

        // Event order: Connected → ClientWriteSenderReady → StatusHint(waiting) →
        // StatusHint(established).
        let hint_established = t!("udp_session.hint_established").to_string();
        let hint_waiting = t!("udp_session.hint_waiting").to_string();
        let mut write_tx = None;
        let mut seen_established = false;
        // The trace of the session stages also comes as events: they are informational
        // and do not change the protocol order.
        for _ in 0..32 {
            let ev = next_event(&rx).await;
            match ev {
                ConnectionEvent::Connected(_, _) => {}
                ConnectionEvent::ClientWriteSenderReady(_, s) => write_tx = Some(s),
                ConnectionEvent::MessageReceived(_, m) if m.stage.is_some() => {}
                // The session is open: the UI may send commands now.
                ConnectionEvent::SessionReady(_) => {}
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
        let frame = decode(&buf[..n]).unwrap();
        assert_eq!(frame.header.packet_type, PacketType::Data);
        assert_eq!(frame.header.session_id, SESSION_ID);
        let Body::Encrypted { nonce, ciphertext } = frame.body else {
            panic!("expected an encrypted body")
        };
        let plain = aes_gcm_decrypt(
            &session_key(nonce_a),
            &nonce,
            &header_bytes(&frame.header),
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

        // 4) The peer sends DATA seq=1 → the plain text is the payload field
        // of the decoder line, and no second message carries it.
        peer_send_data(&peer, client_addr, nonce_a, 1, b"{\"a\":1}").await;
        let (ev, others) = wait_for(&rx, |event| {
            matches!(
                event,
                ConnectionEvent::MessageReceived(_, message)
                    if message.stage == Some(MessageStage::Decoder)
                        && message.get_content_by_type().contains("payload: {\"a\":1}")
            )
        })
        .await;
        assert!(
            others
                .iter()
                .all(|e| !matches!(e, ConnectionEvent::MessagesReceived(..))),
            "the plain text must not enter the message list a second time"
        );
        match ev {
            ConnectionEvent::MessageReceived(_, message) => {
                assert_eq!(message.stage, Some(MessageStage::Decoder));
            }
            other => panic!("expected a decoder line, got {other:?}"),
        }

        // 5) The peer sends Close → Disconnected, no Error.
        peer_send_encrypted(
            &peer,
            client_addr,
            nonce_a,
            PacketType::Close,
            2,
            br#"{"reason":"timeout"}"#,
        )
        .await;
        let (ev, others) = wait_for(&rx, |e| matches!(e, ConnectionEvent::Disconnected(..))).await;
        assert!(matches!(ev, ConnectionEvent::Disconnected(..)));
        assert!(
            others
                .iter()
                .all(|e| !matches!(e, ConnectionEvent::Error(..))),
            "Close must not produce an Error"
        );
        assert!(
            others
                .iter()
                .all(|e| !matches!(e, ConnectionEvent::MessagesReceived(..))),
            "the plain text must not enter the message list a second time"
        );
    }

    #[tokio::test]
    async fn loopback_incoming_close_shows_the_reason() {
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

        peer_send_encrypted(
            &peer,
            client_addr,
            nonce_a,
            PacketType::Close,
            1,
            br#"{"reason":"timeout"}"#,
        )
        .await;

        let (ev, _) = wait_for(&rx, |e| matches!(e, ConnectionEvent::Disconnected(..))).await;
        assert!(matches!(ev, ConnectionEvent::Disconnected(..)));
        let hint = t!("udp_session.close_timeout").to_string();
        let (ev, _) = wait_for(
            &rx,
            |e| matches!(e, ConnectionEvent::StatusHint(_, text) if *text == hint),
        )
        .await;
        assert!(matches!(ev, ConnectionEvent::StatusHint(..)));
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
        assert_eq!(buf[1], 0x01, "only HELLO (type=0x01) should be seen");

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

        // A CHALLENGE from another address must not establish a session.
        let foreign = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let proof_b = hmac_sha256(PSK.as_bytes(), &proof_b_input(&[1u8; 32], &NONCE_B));
        let challenge = Frame {
            header: Header {
                packet_type: PacketType::Challenge,
                session_id: 0,
                seq_num: 0,
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
        let frame = decode(&buf[..n]).unwrap();
        assert_eq!(frame.header.packet_type, PacketType::Data);
        let Body::Encrypted { nonce, ciphertext } = frame.body else {
            panic!("expected an encrypted body")
        };
        let plain = aes_gcm_decrypt(
            &session_key(nonce_a),
            &nonce,
            &header_bytes(&frame.header),
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

        // A datagram longer than 1400 bytes: it is not a frame, so the socket
        // stage sees it and the decoder stage says that it is not a frame.
        peer.send_to(&vec![0u8; MAX_DATAGRAM + 1], client_addr)
            .await
            .unwrap();
        let (ev, others) = wait_for(&rx, |event| {
            matches!(
                event,
                ConnectionEvent::MessageReceived(_, message)
                    if message.stage == Some(MessageStage::Decoder)
            )
        })
        .await;
        assert!(
            others.iter().any(|event| {
                matches!(
                    event,
                    ConnectionEvent::MessageReceived(_, message)
                        if message.stage == Some(MessageStage::Socket)
                )
            }),
            "the oversized datagram has a socket line"
        );
        let not_a_frame = t!("udp_session.trace_not_a_frame").to_string();
        match ev {
            ConnectionEvent::MessageReceived(_, message) => {
                assert!(
                    message.get_content_by_type().contains(&not_a_frame),
                    "the decoder line says that the datagram is not a frame"
                );
            }
            other => panic!("expected a decoder line, got {other:?}"),
        }

        // The warning names the reason.
        let (ev, _) = wait_for(&rx, |e| matches!(e, ConnectionEvent::Warning(..))).await;
        match ev {
            ConnectionEvent::Warning(_, text) => {
                assert_eq!(text, t!("udp_session.warn_too_long").to_string());
            }
            other => panic!("expected Warning, got {other:?}"),
        }

        // The session is still alive: the next DATA is decoded as usual.
        peer_send_data(&peer, client_addr, nonce_a, 1, b"ok").await;
        let (ev, others) = wait_for(&rx, |event| {
            matches!(
                event,
                ConnectionEvent::MessageReceived(_, message)
                    if message.stage == Some(MessageStage::Decoder)
                        && message.get_content_by_type().contains("payload: ok")
            )
        })
        .await;
        assert!(
            others
                .iter()
                .all(|e| !matches!(e, ConnectionEvent::Error(..)))
        );
        assert!(
            others
                .iter()
                .all(|e| !matches!(e, ConnectionEvent::MessagesReceived(..))),
            "the plain text must not enter the message list a second time"
        );
        match ev {
            ConnectionEvent::MessageReceived(_, message) => {
                assert_eq!(message.stage, Some(MessageStage::Decoder));
            }
            other => panic!("expected a decoder line, got {other:?}"),
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

    /// The command envelope of the user: the client sends it as it is.
    const COMMAND: &[u8] = br#"{"protocol_version":"1.0","msg_type":"command","msg_id":"cmd-1","ts_utc":"2026-11-17T18:00:00.000Z","seq":1,"source":"app","payload":{"cmd":"get_status","scope":"device","ttl_sec":30,"params":{}}}"#;

    /// The refusal of the device: the answer to a text that is not a command.
    const ERROR: &[u8] = br#"{"protocol_version":"1.0","msg_type":"error","device_id":"","ts_utc":"1970-01-01T00:00:00.000Z","seq":1,"source":"device","payload":{"code":"E_INVALID_CMD","severity":"error","message":"The command is not a valid message","retryable":false}}"#;

    /// The confirmation of the device: the answer that names the command.
    const ACK: &[u8] = br#"{"protocol_version":"1.0","msg_type":"ack","correlation_id":"cmd-1","device_id":"dev_1","ts_utc":"2026-11-17T18:00:01.000Z","seq":1,"source":"device","payload":{"result":"applied","device_state":"idle"}}"#;

    #[tokio::test]
    async fn loopback_device_error_is_shown_as_a_warning() {
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

        peer_send_data(&peer, client_addr, nonce_a, 1, ERROR).await;

        // The plain text of the answer is the payload field of the decoder line.
        let (ev, others) = wait_for(&rx, |event| {
            matches!(
                event,
                ConnectionEvent::MessageReceived(_, message)
                    if message.stage == Some(MessageStage::Decoder)
                        && message.get_content_by_type().contains("E_INVALID_CMD")
            )
        })
        .await;
        assert!(
            others
                .iter()
                .all(|e| !matches!(e, ConnectionEvent::MessagesReceived(..))),
            "the plain text must not enter the message list a second time"
        );
        match ev {
            ConnectionEvent::MessageReceived(_, message) => {
                assert_eq!(message.stage, Some(MessageStage::Decoder));
            }
            other => panic!("expected a decoder line, got {other:?}"),
        }

        // The parsed refusal is a warning: the session stays alive.
        let (ev, others) = wait_for(&rx, |e| matches!(e, ConnectionEvent::Warning(..))).await;
        match ev {
            ConnectionEvent::Warning(_, text) => {
                let code = "E_INVALID_CMD";
                assert_eq!(
                    text,
                    t!("udp_session.reply_error", code = code).to_string(),
                    "the code of the error is shown"
                );
            }
            other => panic!("expected Warning, got {other:?}"),
        }
        assert!(
            others
                .iter()
                .all(|e| !matches!(e, ConnectionEvent::Error(..))),
            "a refusal of the device is not a failure of the client"
        );
    }

    #[tokio::test]
    async fn loopback_ack_is_correlated_with_the_command() {
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
        let (nonce_a, client_addr, write_tx) = establish(&peer, &rx).await;

        // The user sends the command envelope: it goes to the wire as it is.
        write_tx
            .send(WireMessage::inherit(COMMAND.to_vec()))
            .await
            .unwrap();
        let mut buf = [0u8; 2048];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let frame = decode(&buf[..n]).unwrap();
        assert_eq!(frame.header.packet_type, PacketType::Data);
        let Body::Encrypted { nonce, ciphertext } = &frame.body else {
            panic!("expected an encrypted body")
        };
        let plain = aes_gcm_decrypt(
            &session_key(nonce_a),
            nonce,
            &header_bytes(&frame.header),
            ciphertext,
        )
        .unwrap();
        assert_eq!(plain, COMMAND, "the envelope must not be rebuilt");

        // The device confirms the command and names it.
        peer_send_data(&peer, client_addr, nonce_a, 1, ACK).await;
        let (ev, others) = wait_for(&rx, |event| {
            matches!(
                event,
                ConnectionEvent::MessageReceived(_, message)
                    if message.stage == Some(MessageStage::Decoder)
                        && message.get_content_by_type().contains("cmd-1")
            )
        })
        .await;
        assert!(
            others
                .iter()
                .all(|e| !matches!(e, ConnectionEvent::MessagesReceived(..))),
            "the plain text must not enter the message list a second time"
        );
        match ev {
            ConnectionEvent::MessageReceived(_, message) => {
                assert_eq!(message.stage, Some(MessageStage::Decoder));
            }
            other => panic!("expected a decoder line, got {other:?}"),
        }

        // The confirmation names the command it belongs to.
        let (ev, _) = wait_for(&rx, |e| matches!(e, ConnectionEvent::StatusHint(..))).await;
        match ev {
            ConnectionEvent::StatusHint(_, text) => {
                let command = "get_status (cmd-1)";
                let result = "applied";
                assert_eq!(
                    text,
                    t!(
                        "udp_session.reply_ack_command",
                        command = command,
                        result = result
                    )
                    .to_string()
                );
            }
            other => panic!("expected StatusHint, got {other:?}"),
        }
    }

    /// The session log lines: the messages that carry a stage.
    fn stage_lines(events: &[ConnectionEvent]) -> Vec<(MessageStage, String)> {
        events
            .iter()
            .filter_map(|event| match event {
                ConnectionEvent::MessageReceived(_, message) => message
                    .stage
                    .map(|stage| (stage, message.get_content_by_type().to_string())),
                _ => None,
            })
            .collect()
    }

    /// A frame with a broken tag: the line names the header and the length of
    /// the payload, and the ciphertext stays out of the log.
    #[test]
    fn a_bad_tag_decoder_line_has_the_header_and_no_ciphertext() {
        let mut ciphertext = b"secret-body".to_vec();
        ciphertext.extend_from_slice(&[0xab; 16]);
        let frame = Frame {
            header: Header {
                packet_type: PacketType::Data,
                session_id: 0x5353,
                seq_num: 4,
                timestamp: 30,
            },
            body: Body::Encrypted {
                nonce: [0x22; 12],
                ciphertext,
            },
        };
        let lines = trace_lines(&Trace::Decoded {
            frame,
            plain: None,
            tag_failed: true,
        });
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].0, MessageStage::Decoder);
        let text = &lines[0].2;
        assert!(text.contains("session_id: 0x5353\n"));
        assert!(text.contains("payload_length: 11\n"));
        assert!(text.contains(t!("udp_session.trace_tag_failed").as_ref()));
        assert!(!text.contains("payload:"));
        assert!(!text.contains("secret-body"));
        assert!(!text.contains("abababab"));
    }

    #[tokio::test]
    async fn loopback_the_session_frames_are_visible_in_the_log() {
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

        let (nonce_a, client_addr, _) = recv_hello(&peer).await;
        peer_send_challenge(&peer, client_addr, nonce_a).await;
        peer_recv_response(&peer, nonce_a).await;
        peer_send_session_ok(&peer, client_addr).await;
        // The peer closes the session: the CLOSE frame belongs to the log too.
        peer_send_encrypted(
            &peer,
            client_addr,
            nonce_a,
            PacketType::Close,
            1,
            br#"{"reason":"user_disconnect"}"#,
        )
        .await;

        // The frames are logged as they arrive: wait for the last one instead
        // of a fixed window, so a loaded machine does not fail the test.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut lines: Vec<(MessageStage, String)> = Vec::new();
        while !lines
            .iter()
            .any(|(_, text)| text.contains("packet_type: CLOSE"))
        {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let events = collect_for(&rx, remaining.min(Duration::from_millis(200))).await;
            lines.extend(stage_lines(&events));
        }

        // The outgoing HELLO: one sender line that names the nonce of the client.
        let hello: Vec<&String> = lines
            .iter()
            .filter(|(stage, text)| {
                *stage == MessageStage::Sender && text.contains("packet_type: HELLO")
            })
            .map(|(_, text)| text)
            .collect();
        assert_eq!(hello.len(), 1, "exactly one sender line for the HELLO");
        assert!(
            hello[0].contains("nonce_a:"),
            "the sender line names the nonce of the client"
        );

        // The incoming CHALLENGE: one decoder line with the fields of the frame.
        let challenge: Vec<&String> = lines
            .iter()
            .filter(|(stage, text)| {
                *stage == MessageStage::Decoder && text.contains("packet_type: CHALLENGE")
            })
            .map(|(_, text)| text)
            .collect();
        assert_eq!(
            challenge.len(),
            1,
            "exactly one decoder line for the CHALLENGE"
        );
        for field in [
            "session_id:",
            "seq_num:",
            "timestamp:",
            "nonce_b:",
            "proof_b:",
        ] {
            assert!(
                challenge[0].contains(field),
                "the decoder line must name {field}"
            );
        }

        // The proof check of the device has its own stage: one line.
        let handshake: Vec<&String> = lines
            .iter()
            .filter(|(stage, _)| *stage == MessageStage::Handshake)
            .map(|(_, text)| text)
            .collect();
        assert_eq!(
            handshake.len(),
            1,
            "exactly one handshake line for the challenge of the device"
        );

        // The old cipher line is gone.
        assert!(
            lines
                .iter()
                .all(|(_, text)| !text.contains("cipher = NULL")),
            "the log must not carry the old cipher line"
        );

        // The session stage: the green line is a short text, not a field dump.
        let session: Vec<&String> = lines
            .iter()
            .filter(|(stage, _)| *stage == MessageStage::Session)
            .map(|(_, text)| text)
            .collect();
        assert_eq!(session.len(), 1, "exactly one session line");
        assert!(
            !session[0].contains("session_id:"),
            "the session line is not a field dump"
        );

        // The SESSION_OK: the decoder line has no nonce of the client.
        let session_ok: Vec<&String> = lines
            .iter()
            .filter(|(stage, text)| {
                *stage == MessageStage::Decoder && text.contains("packet_type: SESSION_OK")
            })
            .map(|(_, text)| text)
            .collect();
        assert_eq!(
            session_ok.len(),
            1,
            "exactly one decoder line for the SESSION_OK"
        );
        assert!(
            !session_ok[0].contains("nonce_a:"),
            "the SESSION_OK carries no nonce of the client"
        );

        // The CLOSE of the peer: the reason is the payload of the decoder line.
        let close: Vec<&String> = lines
            .iter()
            .filter(|(stage, text)| {
                *stage == MessageStage::Decoder && text.contains("packet_type: CLOSE")
            })
            .map(|(_, text)| text)
            .collect();
        assert_eq!(close.len(), 1, "exactly one decoder line for the CLOSE");
        assert!(
            close[0].contains("payload: {\"reason\":\"user_disconnect\"}"),
            "the close reason is the payload of the decoder line"
        );
    }

    /// A marked wire carries a command name; a plain wire carries editor bytes.
    #[test]
    fn a_marked_wire_is_a_send_command_and_a_plain_wire_is_user_bytes() {
        let tail = [1u8, 2, 3, 4, 5];
        match command_for_wire(true, b"get_status", tail) {
            Command::SendCommand { cmd, nonce_tail } => {
                assert_eq!(cmd, "get_status");
                assert_eq!(nonce_tail, tail);
            }
            other => panic!("expected SendCommand, got {other:?}"),
        }
        match command_for_wire(false, b"{\"a\":1}", tail) {
            Command::UserBytes { bytes, .. } => assert_eq!(bytes, b"{\"a\":1}"),
            other => panic!("expected UserBytes, got {other:?}"),
        }
    }
}
