//! UDP Session 客户端：自有 HELLO / SESSION_OK 握手 + AES-256-GCM 会话。
//!
//! 与普通 UDP 客户端的差别：
//! - 握手在协议层自动完成；握手完成前用户字节一律不上线（明文不得泄漏）；
//! - 会话内的数据走 DATA 包（密文 + 16 字节 GCM 标签），日志里只出现解密后的明文；
//! - 回复规则不参与：规则作用在明文上会绕过 GCM 认证。
//!
//! 字节契约见 `src/session_udp/codec.rs` 与设计文档附录 A。

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

/// 单个 recv 调用的缓冲区大小。UDP 数据报上限 65507 字节，缓冲区取 65535。
const RECV_BUFFER_SIZE: usize = 65535;

/// 把状态机的失败令牌翻译成界面文案。
///
/// 令牌是固定英文短语（见 `session_udp::machine`），此处只做映射，不回显任何密钥。
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

/// 把状态机的告警令牌翻译成界面文案
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

/// UDP Session 客户端
pub struct UdpSessionClient {
    config: ClientConfig,
    event_sender: Option<Sender<ConnectionEvent>>,
    net_counters: Option<NetCounters>,
    is_connected: bool,
    cancel_token: CancellationToken,
    /// 运行期「结尾追加字符」设置：本连接不读（DATA 载荷不可被追加字节污染）
    _trailer: TrailerSetting,
    /// 回复规则共享状态：本连接不调用（规则不应作用于密文）
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
        // 空 PSK 在建连前就被拒绝：一个字节都不上线，事件通道也不另报 Error
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
            // 地址拼装与 UDP 客户端一致：IPv6 需要方括号
            let address = if server_host.contains(':') && !server_host.contains('[') {
                format!("[{}]:{}", server_host, config.server_port)
            } else {
                format!("{}:{}", server_host, config.server_port)
            };
            let server_addr = SocketAddr::from_str(&address)
                .map_err(|e| format!("无效的UDP Session服务器地址 {}: {}", address, e))?;

            info!("UDP Session 客户端连接到地址: {}", server_addr);

            // 本地绑定：未配置时按远端地址族用通配地址 + 自动端口
            let bind_addr = match crate::network::bind::resolve_local_bind(&config, server_addr)? {
                Some(addr) => addr,
                None if server_addr.is_ipv4() => {
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                }
                None => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            };
            let socket = UdpSocket::bind(bind_addr).await.map_err(|e| {
                format!(
                    "绑定本地地址 {} 失败: {}（本地端口可能已被占用，或地址不属于本机）",
                    bind_addr, e
                )
            })?;
            let local_addr = socket
                .local_addr()
                .map_err(|e| format!("获取UDP Session本地地址失败: {}", e))?;
            // connect 让内核只接收对端地址的数据报：别人的包进不了握手
            socket
                .connect(server_addr)
                .await
                .map_err(|e| format!("连接UDP Session服务器 {} 失败: {}", server_addr, e))?;

            // nonce_a 由外部给：状态机内部没有随机源
            let mut nonce_a = [0u8; 16];
            getrandom::fill(&mut nonce_a).map_err(|e| format!("生成握手随机数失败: {}", e))?;

            let mut machine = Machine::new();
            let actions = machine.handle(Command::Start {
                nonce_a,
                psk: settings.psk.clone(),
                hello_retries: settings.hello_retries,
            });

            let socket = Arc::new(socket);
            // 首个 HELLO 直接上线：握手失败也要让对端看到我们的存在
            for action in &actions {
                if let Action::Send(packet) = action {
                    let bytes = encode(packet);
                    socket
                        .send(&bytes)
                        .await
                        .map_err(|e| format!("发送HELLO失败: {}", e))?;
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
                // 握手计时器只在等待期有效：会话建立后不再重发 HELLO
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
                                    // 超长数据报不进自动机：只告警，会话继续
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
                                    error!("UDP Session 接收数据报失败: {:?}", e);
                                    if let Some(sender) = &event_sender_loop {
                                        let _ = sender.send(ConnectionEvent::Error(
                                            id.clone(),
                                            format!("接收数据报失败: {}", e),
                                        )).await;
                                    }
                                    break;
                                }
                            }
                        }
                        incoming = rx.recv() => {
                            match incoming {
                                Ok(wire) => {
                                    // 用户字节原样进自动机：不追加 trailer，不读 finalized
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
                debug!("UDP Session 客户端循环结束");
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
    /// 绕过 disconnect() 直接 drop 时兜底停掉后台任务，避免孤儿任务持有 socket
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

/// 动作处理的结果
#[derive(Debug, PartialEq, Eq)]
enum Flow {
    /// 继续循环
    Continue,
    /// 会话已建立：握手计时器可以停了
    Established,
    /// 终止循环
    Stop,
}

/// 把状态机动作翻译成协议包与 UI 事件
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
                        // Close 的发送失败不改变结局：会话本来就结束了
                        if matches!(packet, Packet::Close { .. }) {
                            debug!("[UDP Session] 发送 Close 失败: {:?}", e);
                            continue;
                        }
                        error!("[UDP Session] 发送数据包失败: {:?}", e);
                        if let Some(sender) = event_sender {
                            let _ = sender
                                .send(ConnectionEvent::Error(
                                    id.to_string(),
                                    format!("发送UDP Session数据包失败: {}", e),
                                ))
                                .await;
                        }
                        flow = Flow::Stop;
                    }
                }
            }
            Action::Deliver(plain) => {
                // 解密后的明文进消息列表；握手包不进
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
                error!("[UDP Session] 会话失败: {}", token);
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

/// UDP Session 没有服务端角色（与 MQTT 同理）：`start` 立刻报错。
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

    /// 客户端配置：连到本地 peer，本地显式绑定回环地址（Connected 事件带真实本地端口）
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

    /// 造一个"对任意帧都回 RULE"的规则集：客户端绝不能调用它
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
            .expect("等待事件超时")
            .expect("事件通道已关闭")
    }

    /// 等到满足条件的事件；期间的其他事件一并返回（用于断言"不该出现的事件没出现"）
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

    /// 窗口期内收集事件（不等匹配）
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

    /// peer 收到 HELLO：返回 (nonce_a, 客户端地址, 原始字节)
    async fn recv_hello(peer: &UdpSocket) -> ([u8; 16], SocketAddr, Vec<u8>) {
        let mut buf = [0u8; 2048];
        let (n, src) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buf))
            .await
            .expect("等待 HELLO 超时")
            .expect("接收 HELLO 失败");
        let bytes = buf[..n].to_vec();
        match decode(&bytes).expect("HELLO 应能解析") {
            Packet::Hello { nonce_a, proof_a } => {
                assert!(
                    hmac_verify(PSK.as_bytes(), &hello_mac_input(&nonce_a), &proof_a),
                    "HELLO 的 proof 应由同一 PSK 算出"
                );
                (nonce_a, src, bytes)
            }
            other => panic!("期望 HELLO, 得到 {other:?}"),
        }
    }

    /// HKDF 的 salt = nonce_a || nonce_b
    fn salt(nonce_a: [u8; 16]) -> Vec<u8> {
        nonce_a.into_iter().chain(NONCE_B).collect()
    }

    fn session_key(nonce_a: [u8; 16]) -> [u8; 32] {
        hkdf_sha256(PSK.as_bytes(), &salt(nonce_a), HKDF_INFO)
    }

    /// peer 发一个 DATA 包
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

    /// 建立会话：握手 + 拿到写通道
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

        // 事件顺序: Connected → ClientWriteSenderReady → StatusHint(waiting) → StatusHint(established)
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

        // 1) peer 收到 HELLO：不是 PSK 字节，也不是 JSON
        let (nonce_a, client_addr, hello_bytes) = recv_hello(&peer).await;
        assert!(
            !hello_bytes.windows(PSK.len()).any(|w| w == PSK.as_bytes()),
            "HELLO 里不应出现 PSK"
        );
        assert!(!hello_bytes.starts_with(b"{"), "HELLO 不是 JSON");

        // 2) peer 回 SessionOk → 会话建立
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
                        assert!(!text.contains(PSK), "状态提示里不应出现 PSK");
                        seen_established = true;
                    } else {
                        assert_eq!(text, hint_waiting, "握手期只应有等待提示");
                    }
                }
                other => panic!("意外事件: {other:?}"),
            }
            if seen_established {
                break;
            }
        }
        assert!(seen_established, "会话建立后应有状态提示");
        let write_tx = write_tx.expect("应有写通道");

        // 3) 用户发送 "ping" → peer 收到 DATA，解密后是 "ping"
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
            other => panic!("期望 DATA, 得到 {other:?}"),
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

        // 规则不应被调用：不会再有第二个数据报
        let mut buf2 = [0u8; 2048];
        assert!(
            tokio::time::timeout(Duration::from_millis(300), peer.recv_from(&mut buf2))
                .await
                .is_err(),
            "回复规则不应被调用"
        );

        // 4) peer 发 DATA seq=1 → 客户端一条 MessagesReceived，明文是 JSON
        peer_send_data(&peer, client_addr, nonce_a, 1, b"{\"a\":1}").await;
        let (ev, others) =
            wait_for(&rx, |e| matches!(e, ConnectionEvent::MessagesReceived(..))).await;
        assert!(
            others
                .iter()
                .all(|e| !matches!(e, ConnectionEvent::MessagesReceived(..))),
            "握手包不应进消息列表"
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
            other => panic!("期望 MessagesReceived, 得到 {other:?}"),
        }

        // 5) peer 发 Close → Disconnected，没有 Error
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
            "Close 不应产生 Error"
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

        // 取写通道（此时握手尚未完成）
        let write_tx = loop {
            if let ConnectionEvent::ClientWriteSenderReady(_, s) = next_event(&rx).await {
                break s;
            }
        };
        write_tx
            .send(WireMessage::inherit(b"open text".to_vec()))
            .await
            .unwrap();

        // 事件里有 Warning(not established)，且不含明文
        let (ev, _) = wait_for(&rx, |e| matches!(e, ConnectionEvent::Warning(..))).await;
        match ev {
            ConnectionEvent::Warning(_, text) => {
                assert_eq!(text, t!("udp_session.warn_not_established").to_string());
                assert!(!text.contains("open text"), "告警里不应出现明文");
            }
            other => panic!("期望 Warning, 得到 {other:?}"),
        }

        // peer 侧只看到 HELLO
        let mut buf = [0u8; 2048];
        let (_n, _) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(buf[3], 1, "只应看到 HELLO(type=1)");

        // 200 ms 内没有第二个数据报：明文没有上线
        let mut buf2 = [0u8; 2048];
        assert!(
            tokio::time::timeout(Duration::from_millis(200), peer.recv_from(&mut buf2))
                .await
                .is_err(),
            "握手完成前明文不应上线"
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

        // 取本地地址（Connected 事件带上真实本地端口）
        let local = loop {
            if let ConnectionEvent::Connected(_, addr) = next_event(&rx).await {
                break addr;
            }
        };

        // 别的地址发来的 SessionOk 不应建立会话
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
            "别人的包不应建立会话"
        );

        // 真正的对端随后应答 → hint_established 到来
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
            other => panic!("期望 DATA, 得到 {other:?}"),
        };
        let key = session_key(nonce_a);
        let plain = aes_gcm_decrypt(
            &key,
            &data_nonce(&SESSION_ID, seq),
            &data_aad(&SESSION_ID, seq, ciphertext.len() as u16),
            &ciphertext,
        )
        .unwrap();
        assert_eq!(plain, b"hi", "DATA 载荷不应被追加 trailer");
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

        // 超过 2048 字节的数据报：告警，不进自动机
        peer.send_to(&vec![0u8; 2049], client_addr).await.unwrap();
        let (ev, _) = wait_for(&rx, |e| matches!(e, ConnectionEvent::Warning(..))).await;
        match ev {
            ConnectionEvent::Warning(_, text) => {
                assert_eq!(text, t!("udp_session.warn_too_long").to_string());
            }
            other => panic!("期望 Warning, 得到 {other:?}"),
        }

        // 会话仍然活着：下一个 DATA 照常送达
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
            other => panic!("期望 MessagesReceived, 得到 {other:?}"),
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

        // 一个字节都不上线
        let mut buf = [0u8; 2048];
        assert!(
            tokio::time::timeout(Duration::from_millis(200), peer.recv_from(&mut buf))
                .await
                .is_err(),
            "空 PSK 时不应发出任何数据报"
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
