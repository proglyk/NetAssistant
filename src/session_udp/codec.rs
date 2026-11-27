//! UDP Session datagram codec.
//!
//! Byte contract (protocol §§5.2–5.8, specs
//! `docs-dev/specs/2026-11-17-udp-session-b-handshake.md` and
//! `docs-dev/specs/2026-11-17-udp-session-c-data-close.md`):
//!
//! - every frame starts with a 12-byte header: version, packet type, session id,
//!   sequence number, timestamp — all big-endian;
//! - handshake frames (type < 0x10) carry an unencrypted body whose layout
//!   depends on the type;
//! - encrypted frames (type >= 0x10) carry nonce, payload length, ciphertext and
//!   the GCM tag; the AAD is the header, bytes 0..11.
//!
//! The frame boundary is one datagram: there is no total-length field, and
//! trailing bytes are never trimmed — a frame with trailing bytes is a bad
//! frame.
//!
//! The JSON envelope of a business message (protocol §2.1) lives here too: it
//! is not a separate packet, but the plain text of a `DATA` frame, and the
//! client needs its fields to recognise answers and to correlate them.

use crate::session_udp::crypto::{NONCE_LEN, TAG_LEN};
use std::fmt;

/// Protocol version byte (protocol §5.2).
pub const VERSION: u8 = 0x01;
/// Header length in bytes: version, type, session id, seq_num, timestamp.
pub const HEADER_LEN: usize = 12;
/// Largest datagram accepted by the parser (protocol §5.1, §5.8.1).
///
/// The limit is one datagram of the compact profile, 1400 bytes — not the
/// 2048 bytes the client accepted before the byte contract was replaced.
pub const MAX_DATAGRAM: usize = 1400;
/// Handshake nonce length: `nonce_a` and `nonce_b` are 32 bytes each.
pub const HANDSHAKE_NONCE_LEN: usize = 32;
/// Proof length: HMAC-SHA256 digest.
pub const PROOF_LEN: usize = 32;
/// Length of the plaintext-length field of an encrypted frame.
pub const LENGTH_LEN: usize = 4;
/// Overhead of an encrypted frame: header, nonce, length field, GCM tag.
pub const ENCRYPTED_OVERHEAD: usize = HEADER_LEN + NONCE_LEN + LENGTH_LEN + TAG_LEN;
/// Largest plaintext that still fits into one datagram.
pub const MAX_PLAINTEXT: usize = MAX_DATAGRAM - ENCRYPTED_OVERHEAD;
/// HKDF info string of the session key (protocol §5.5).
///
/// 23 ASCII bytes, without the terminating null byte: the firmware keeps the
/// null byte in its array and passes `SESSION_KEY_INFO.size() - 1` to HKDF.
pub const HKDF_INFO: &[u8] = b"hiot-udp-v1-session-key";
/// Replay window of the header timestamp, in seconds (protocol §5.7).
pub const TIMESTAMP_WINDOW_SECONDS: u32 = 300;
/// Nonce direction byte: application to device.
pub const DIRECTION_APP_TO_ESP: u8 = 0x00;
/// Nonce direction byte: device to application.
pub const DIRECTION_ESP_TO_APP: u8 = 0x01;
/// Context byte appended to the nonce pair in the server proof.
pub const PROOF_B_CONTEXT: u8 = 0x01;
/// Context byte appended to the nonce pair in the client proof.
pub const PROOF_A_CONTEXT: u8 = 0x02;

/// Packet type (protocol §5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    /// Client opens the handshake: body is `nonce_a`.
    Hello = 0x01,
    /// Device answers with a challenge: body is `nonce_b` ‖ `proof_b`.
    Challenge = 0x02,
    /// Client proves its secret: body is `proof_a`.
    Response = 0x03,
    /// Device opens the session: body is empty, the header names the session.
    SessionOk = 0x04,
    /// Device refuses the handshake: body is the error code.
    SessionErr = 0x05,
    /// Encrypted command or answer.
    Data = 0x10,
    /// Encrypted status snapshot or event, device to application.
    Push = 0x11,
    /// Encrypted session close.
    Close = 0x1F,
}

impl PacketType {
    /// Map a wire byte to a packet type, or `None` for an unknown type.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(PacketType::Hello),
            0x02 => Some(PacketType::Challenge),
            0x03 => Some(PacketType::Response),
            0x04 => Some(PacketType::SessionOk),
            0x05 => Some(PacketType::SessionErr),
            0x10 => Some(PacketType::Data),
            0x11 => Some(PacketType::Push),
            0x1F => Some(PacketType::Close),
            _ => None,
        }
    }

    /// Whether the body of this type is encrypted.
    pub fn is_encrypted(self) -> bool {
        matches!(
            self,
            PacketType::Data | PacketType::Push | PacketType::Close
        )
    }

    /// The name of the type on the wire (protocol §5.3), for the session log.
    pub fn name(self) -> &'static str {
        match self {
            PacketType::Hello => "HELLO",
            PacketType::Challenge => "CHALLENGE",
            PacketType::Response => "RESPONSE",
            PacketType::SessionOk => "SESSION_OK",
            PacketType::SessionErr => "SESSION_ERR",
            PacketType::Data => "DATA",
            PacketType::Push => "PUSH",
            PacketType::Close => "CLOSE",
        }
    }
}

/// Frame header (protocol §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Packet type.
    pub packet_type: PacketType,
    /// Session id: 0 during the handshake, except in `SESSION_OK`.
    pub session_id: u16,
    /// Sequence number (`seq_num` in protocol §5.2): 0 during the handshake.
    pub seq_num: u32,
    /// Unix seconds.
    pub timestamp: u32,
}

/// Frame body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    /// `HELLO`: the client nonce.
    Hello {
        /// 32 random bytes generated by the client.
        nonce_a: [u8; HANDSHAKE_NONCE_LEN],
    },
    /// `CHALLENGE`: the device nonce and its proof.
    Challenge {
        /// 32 random bytes generated by the device.
        nonce_b: [u8; HANDSHAKE_NONCE_LEN],
        /// HMAC-SHA256(secret, nonce_a ‖ nonce_b ‖ 0x01).
        proof_b: [u8; PROOF_LEN],
    },
    /// `RESPONSE`: the client proof.
    Response {
        /// HMAC-SHA256(secret, nonce_b ‖ nonce_a ‖ 0x02).
        proof_a: [u8; PROOF_LEN],
    },
    /// `SESSION_OK`: empty body, the header carries the session id.
    SessionOk,
    /// `SESSION_ERR`: the reason code (protocol §5.10).
    SessionErr {
        /// 0x01 auth failed, 0x02 max sessions, 0x03 not bound,
        /// 0x04 rate limited, 0x05 version mismatch.
        code: u8,
    },
    /// Encrypted body of `DATA`, `PUSH` and `CLOSE`.
    Encrypted {
        /// Nonce on the wire: session id, direction, seq_num, 5 random bytes.
        nonce: [u8; NONCE_LEN],
        /// Ciphertext with the GCM tag appended.
        ciphertext: Vec<u8>,
    },
}

/// A whole frame: header plus body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Header fields.
    pub header: Header,
    /// Body.
    pub body: Body,
}

/// Reason a datagram was rejected.
#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The frame is shorter than its type requires.
    Truncated,
    /// The version byte is not `0x01`.
    BadVersion,
    /// The packet type is unknown.
    UnknownType,
    /// The session id is not allowed for this packet type.
    BadSessionId,
    /// The length field disagrees with the actual frame length.
    BadLength,
    /// The datagram is longer than `MAX_DATAGRAM`.
    TooLong,
}

impl fmt::Display for DecodeError {
    /// The text names the reason only; it never echoes input bytes (the frame
    /// may carry session data).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            DecodeError::Truncated => "truncated datagram",
            DecodeError::BadVersion => "bad version",
            DecodeError::UnknownType => "unknown packet type",
            DecodeError::BadSessionId => "bad session id",
            DecodeError::BadLength => "bad length",
            DecodeError::TooLong => "datagram too long",
        };
        write!(f, "{text}")
    }
}

/// Header bytes of a frame: the 12 bytes that are also the GCM AAD.
pub fn header_bytes(header: &Header) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[0] = VERSION;
    out[1] = header.packet_type as u8;
    out[2..4].copy_from_slice(&header.session_id.to_be_bytes());
    out[4..8].copy_from_slice(&header.seq_num.to_be_bytes());
    out[8..12].copy_from_slice(&header.timestamp.to_be_bytes());
    out
}

/// Encode a frame into datagram bytes.
pub fn encode(frame: &Frame) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + 64);
    out.extend_from_slice(&header_bytes(&frame.header));
    match &frame.body {
        Body::Hello { nonce_a } => out.extend_from_slice(nonce_a),
        Body::Challenge { nonce_b, proof_b } => {
            out.extend_from_slice(nonce_b);
            out.extend_from_slice(proof_b);
        }
        Body::Response { proof_a } => out.extend_from_slice(proof_a),
        Body::SessionOk => {}
        Body::SessionErr { code } => out.push(*code),
        Body::Encrypted { nonce, ciphertext } => {
            out.extend_from_slice(nonce);
            // The length field counts the open text; the tag is not part of it.
            let plain_len = ciphertext.len().saturating_sub(TAG_LEN);
            out.extend_from_slice(&(plain_len as u32).to_be_bytes());
            out.extend_from_slice(ciphertext);
        }
    }
    out
}

/// Journal text of one frame: protocol §5.2 fields, one `name: value` per line.
///
/// `plain` is the open text of an encrypted frame. The ciphertext and the
/// GCM tag are never written. Handshake frames ignore `plain`.
pub fn format_frame_fields(frame: &Frame, plain: Option<&[u8]>) -> String {
    let header = &frame.header;
    let mut lines = vec![
        "version: 1".to_string(),
        format!(
            "packet_type: {} (0x{:02X})",
            header.packet_type.name(),
            header.packet_type as u8
        ),
        format!("session_id: 0x{:04x}", header.session_id),
        format!("seq_num: {}", header.seq_num),
        format!("timestamp: {}", header.timestamp),
    ];
    match &frame.body {
        Body::Hello { nonce_a } => lines.push(format!("nonce_a: {}", hex_bytes(nonce_a))),
        Body::Challenge { nonce_b, proof_b } => {
            lines.push(format!("nonce_b: {}", hex_bytes(nonce_b)));
            lines.push(format!("proof_b: {}", hex_bytes(proof_b)));
        }
        Body::Response { proof_a } => lines.push(format!("proof_a: {}", hex_bytes(proof_a))),
        Body::SessionOk => {}
        Body::SessionErr { code } => lines.push(format!("error_code: 0x{code:02x}")),
        Body::Encrypted { nonce, ciphertext } => {
            lines.push(format!("nonce: {}", hex_bytes(nonce)));
            let payload_length = ciphertext.len().saturating_sub(TAG_LEN);
            lines.push(format!("payload_length: {payload_length}"));
            if let Some(plain) = plain {
                let text = String::from_utf8_lossy(plain);
                lines.push(format!("payload: {text}"));
            }
        }
    }
    lines.join("\n")
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Parse datagram bytes into a frame.
pub fn decode(buf: &[u8]) -> Result<Frame, DecodeError> {
    if buf.len() > MAX_DATAGRAM {
        return Err(DecodeError::TooLong);
    }
    if buf.len() < HEADER_LEN {
        return Err(DecodeError::Truncated);
    }
    if buf[0] != VERSION {
        return Err(DecodeError::BadVersion);
    }
    let packet_type = PacketType::from_u8(buf[1]).ok_or(DecodeError::UnknownType)?;
    let session_id = u16::from_be_bytes([buf[2], buf[3]]);
    // The session id rules mirror the device parser: encrypted frames and
    // SESSION_OK must name a session, the other handshake frames must not.
    if packet_type.is_encrypted() || packet_type == PacketType::SessionOk {
        if session_id == 0 {
            return Err(DecodeError::BadSessionId);
        }
    } else if session_id != 0 {
        return Err(DecodeError::BadSessionId);
    }
    let header = Header {
        packet_type,
        session_id,
        seq_num: u32::from_be_bytes(buf[4..8].try_into().unwrap()),
        timestamp: u32::from_be_bytes(buf[8..12].try_into().unwrap()),
    };
    let body = &buf[HEADER_LEN..];
    let body = match packet_type {
        PacketType::Hello => {
            let nonce_a: [u8; HANDSHAKE_NONCE_LEN] = body.try_into().map_err(|_| {
                // A body of the wrong size is a truncated frame, not a
                // trimmed one: trailing bytes are never cut off.
                DecodeError::Truncated
            })?;
            Body::Hello { nonce_a }
        }
        PacketType::Challenge => {
            if body.len() != HANDSHAKE_NONCE_LEN * 2 {
                return Err(DecodeError::Truncated);
            }
            let nonce_b: [u8; HANDSHAKE_NONCE_LEN] =
                body[..HANDSHAKE_NONCE_LEN].try_into().unwrap();
            let proof_b: [u8; PROOF_LEN] = body[HANDSHAKE_NONCE_LEN..].try_into().unwrap();
            Body::Challenge { nonce_b, proof_b }
        }
        PacketType::Response => {
            let proof_a: [u8; PROOF_LEN] = body.try_into().map_err(|_| DecodeError::Truncated)?;
            Body::Response { proof_a }
        }
        PacketType::SessionOk => {
            if !body.is_empty() {
                return Err(DecodeError::Truncated);
            }
            Body::SessionOk
        }
        PacketType::SessionErr => {
            if body.len() != 1 {
                return Err(DecodeError::Truncated);
            }
            Body::SessionErr { code: body[0] }
        }
        PacketType::Data | PacketType::Push | PacketType::Close => {
            if body.len() < NONCE_LEN + LENGTH_LEN + TAG_LEN {
                return Err(DecodeError::Truncated);
            }
            let nonce: [u8; NONCE_LEN] = body[..NONCE_LEN].try_into().unwrap();
            let plain_len =
                u32::from_be_bytes(body[NONCE_LEN..NONCE_LEN + LENGTH_LEN].try_into().unwrap());
            let ciphertext = &body[NONCE_LEN + LENGTH_LEN..];
            // The length field counts the open text; the ciphertext has the
            // same length and the tag follows it.
            if plain_len as usize != ciphertext.len() - TAG_LEN {
                return Err(DecodeError::BadLength);
            }
            Body::Encrypted {
                nonce,
                ciphertext: ciphertext.to_vec(),
            }
        }
    };
    Ok(Frame { header, body })
}

/// Build the nonce of an encrypted frame (protocol §5.6).
///
/// The first seven bytes are the frame identity: session id, direction and
/// sequence number. The last five bytes are random, given by the caller — the
/// state machine has no random source of its own.
pub fn build_nonce(session_id: u16, direction: u8, seq_num: u32, tail: [u8; 5]) -> [u8; NONCE_LEN] {
    let mut out = [0u8; NONCE_LEN];
    out[..2].copy_from_slice(&session_id.to_be_bytes());
    out[2] = direction;
    out[3..7].copy_from_slice(&seq_num.to_be_bytes());
    out[7..].copy_from_slice(&tail);
    out
}

/// Check the identity prefix of a nonce: session id, direction and seq_num.
///
/// The random tail is not checked — the device does not check it either.
pub fn nonce_matches(
    nonce: &[u8; NONCE_LEN],
    session_id: u16,
    direction: u8,
    seq_num: u32,
) -> bool {
    nonce[..2] == session_id.to_be_bytes()
        && nonce[2] == direction
        && nonce[3..7] == seq_num.to_be_bytes()
}

/// HMAC input of the server proof: `nonce_a ‖ nonce_b ‖ 0x01`.
///
/// The context byte keeps the server proof from being replayed as the client
/// proof.
pub fn proof_b_input(
    nonce_a: &[u8; HANDSHAKE_NONCE_LEN],
    nonce_b: &[u8; HANDSHAKE_NONCE_LEN],
) -> [u8; HANDSHAKE_NONCE_LEN * 2 + 1] {
    let mut out = [0u8; HANDSHAKE_NONCE_LEN * 2 + 1];
    out[..HANDSHAKE_NONCE_LEN].copy_from_slice(nonce_a);
    out[HANDSHAKE_NONCE_LEN..HANDSHAKE_NONCE_LEN * 2].copy_from_slice(nonce_b);
    out[HANDSHAKE_NONCE_LEN * 2] = PROOF_B_CONTEXT;
    out
}

/// HMAC input of the client proof: `nonce_b ‖ nonce_a ‖ 0x02`.
pub fn proof_a_input(
    nonce_b: &[u8; HANDSHAKE_NONCE_LEN],
    nonce_a: &[u8; HANDSHAKE_NONCE_LEN],
) -> [u8; HANDSHAKE_NONCE_LEN * 2 + 1] {
    let mut out = [0u8; HANDSHAKE_NONCE_LEN * 2 + 1];
    out[..HANDSHAKE_NONCE_LEN].copy_from_slice(nonce_b);
    out[HANDSHAKE_NONCE_LEN..HANDSHAKE_NONCE_LEN * 2].copy_from_slice(nonce_a);
    out[HANDSHAKE_NONCE_LEN * 2] = PROOF_A_CONTEXT;
    out
}

/// Message type of a command (protocol §2.1).
pub const MSG_TYPE_COMMAND: &str = "command";
/// Message type of a positive answer (protocol §2.1).
pub const MSG_TYPE_ACK: &str = "ack";
/// Message type of a negative answer (protocol §2.1).
pub const MSG_TYPE_ERROR: &str = "error";
// The push API (`MSG_TYPE_STATUS`, `MSG_TYPE_EVENT`, `PushKind`, `Push` and
// `parse_push`) is introduced as one cluster and is read by the journal layer
// that follows it; until then the unused-item lint is muted on each item.
/// Message type of a status snapshot of the device (protocol §2.5.4).
#[allow(dead_code)]
pub const MSG_TYPE_STATUS: &str = "status";
/// Message type of an event of the device (protocol §2.5.5).
#[allow(dead_code)]
pub const MSG_TYPE_EVENT: &str = "event";

/// The scope of a command of the application (protocol §2.4.2).
///
/// "device" is the scope that every device supports (protocol §2.4.2).
pub const COMMAND_SCOPE: &str = "device";
/// The lifetime of a command of the application, in seconds (protocol §2.5.1).
pub const COMMAND_TTL_SEC: u32 = 30;

/// JSON body of an outgoing command.
///
/// The envelope fields of protocol §2.1 and the command payload of protocol
/// §2.5.1. The caller supplies the identifier, the device id, the clock
/// string, the JSON sequence, and the already trimmed command name. Key order
/// is not part of the contract.
pub fn command_envelope(
    msg_id: &str,
    device_id: &str,
    ts_utc: &str,
    seq: u32,
    cmd: &str,
) -> Vec<u8> {
    let mut object = serde_json::Map::new();
    object.insert("protocol_version".into(), "1.0".into());
    object.insert("msg_type".into(), MSG_TYPE_COMMAND.into());
    object.insert("msg_id".into(), msg_id.into());
    // The field is always there: the server refuses a command whose device id
    // is empty.
    object.insert("device_id".into(), device_id.into());
    object.insert("ts_utc".into(), ts_utc.into());
    object.insert("seq".into(), seq.into());
    object.insert("source".into(), "app".into());
    object.insert(
        "payload".into(),
        serde_json::json!({
            "cmd": cmd,
            "scope": COMMAND_SCOPE,
            "ttl_sec": COMMAND_TTL_SEC,
            "params": {},
        }),
    );
    serde_json::to_vec(&serde_json::Value::Object(object))
        .expect("command envelope is a fixed JSON object")
}

/// The JSON envelope of a business message (protocol §2.1).
///
/// The envelope is not a separate packet: it is the plain text of a `DATA`
/// frame. Only the fields the client needs are read; the unknown fields are
/// ignored (protocol §2.4.6). The counter `seq` is read as well: the journal
/// shows it next to the message of the device.
#[derive(Debug, Clone, PartialEq)]
pub struct Envelope {
    /// The type of the message: "command", "ack", "error", "status", "event".
    pub msg_type: String,
    /// The identifier of the message.
    pub msg_id: Option<String>,
    /// The identifier of the command the message answers.
    pub correlation_id: Option<String>,
    /// The counter of the messages of the device in one direction
    /// (protocol §2.1).
    pub seq: Option<u64>,
    /// The payload of the message (protocol §2.5).
    pub payload: serde_json::Value,
}

impl Envelope {
    /// Parse the plain text of a frame as an envelope.
    ///
    /// `None` means the text is not an envelope: it is not a JSON object with a
    /// string `msg_type`. Such a text is shown as it is.
    pub fn parse(text: &[u8]) -> Option<Self> {
        let value = serde_json::from_slice::<serde_json::Value>(text).ok()?;
        let object = value.as_object()?;
        // The type is the only mandatory field of the envelope the client
        // reads: without it the text is not an envelope.
        let msg_type = object.get("msg_type")?.as_str()?.to_string();
        let msg_id = object
            .get("msg_id")
            .and_then(|value| value.as_str())
            .map(str::to_string);
        // The correlation may be absent or null: both mean "no command".
        let correlation_id = object
            .get("correlation_id")
            .and_then(|value| value.as_str())
            .map(str::to_string);
        // The counter is optional and is ignored when it is not a number.
        let seq = object.get("seq").and_then(|value| value.as_u64());
        let payload = object
            .get("payload")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        Some(Envelope {
            msg_type,
            msg_id,
            correlation_id,
            seq,
            payload,
        })
    }

    /// Whether the envelope is a command of the application.
    pub fn is_command(&self) -> bool {
        self.msg_type == MSG_TYPE_COMMAND
    }

    /// Whether the envelope is an answer of the device: an ack or an error.
    ///
    /// The machine matches the type itself, because an ack and an error are
    /// different outcomes. The predicate exists for the unit tests, so a
    /// normal build does not keep an unused method.
    #[cfg(test)]
    pub fn is_reply(&self) -> bool {
        self.msg_type == MSG_TYPE_ACK || self.msg_type == MSG_TYPE_ERROR
    }

    /// The name of the command, when the payload carries one (§2.5.1).
    pub fn command_name(&self) -> Option<&str> {
        self.payload.get("cmd").and_then(|value| value.as_str())
    }

    /// The result of an answer (§2.5.2).
    pub fn result(&self) -> Option<&str> {
        self.payload.get("result").and_then(|value| value.as_str())
    }

    /// The state of the device after the command (§2.5.2).
    pub fn device_state(&self) -> Option<&str> {
        self.payload
            .get("device_state")
            .and_then(|value| value.as_str())
    }

    /// The warnings of an answer (§2.5.2).
    ///
    /// The field is an array: a string element is kept as it is, every other
    /// element is the compact JSON of the value, so a warning keeps its shape
    /// whatever the device sent. A field that is not an array is not a list of
    /// warnings: the answer carries none of them.
    pub fn warnings(&self) -> Option<Vec<String>> {
        let items = self.payload.get("warnings")?.as_array()?;
        Some(items.iter().map(field_value).collect())
    }

    /// The product-specific data of an answer (§2.5.2).
    ///
    /// The field is free-form: the profile of the device decides what it
    /// holds, so the value is kept as it is. A null field counts as an absent
    /// one: the device sends the field it has no data for as null, and the
    /// journal must not show "null" where there is nothing to show.
    pub fn data(&self) -> Option<&serde_json::Value> {
        self.payload.get("data").filter(|value| !value.is_null())
    }

    /// The code of an error (§2.5.3).
    ///
    /// The fields of an error lie in the payload itself (§2.5.3), but an ack
    /// that was rejected carries them in a nested error object (§2.5.2): both
    /// shapes are read.
    pub fn error_code(&self) -> Option<&str> {
        self.error_field("code").and_then(|value| value.as_str())
    }

    /// The severity of an error: "info", "warning", "error", "critical"
    /// (§2.5.3).
    ///
    /// The field is read like the code of the error: in the payload itself, or
    /// in the nested error object of a rejected ack (§2.5.2).
    pub fn error_severity(&self) -> Option<&str> {
        self.error_field("severity")
            .and_then(|value| value.as_str())
    }

    /// The human-readable text of an error (§2.5.3).
    ///
    /// The field is read like the code of the error: in the payload itself, or
    /// in the nested error object of a rejected ack (§2.5.2).
    pub fn error_message(&self) -> Option<&str> {
        self.error_field("message").and_then(|value| value.as_str())
    }

    /// Whether the command may be repeated (§2.5.3).
    ///
    /// The field is read like the code of the error: in the payload itself, or
    /// in the nested error object of a rejected ack (§2.5.2).
    pub fn error_retryable(&self) -> Option<bool> {
        self.error_field("retryable")
            .and_then(|value| value.as_bool())
    }

    /// The additional data of an error (§2.5.3).
    ///
    /// The field is read like the code of the error: in the payload itself, or
    /// in the nested error object of a rejected ack (§2.5.2).
    pub fn error_details(&self) -> Option<&serde_json::Value> {
        self.error_field("details")
    }

    /// A field of an error: in the payload itself, or in the nested error
    /// object of a rejected ack (§2.5.2).
    ///
    /// A null field counts as an absent field: the device sends the fields it
    /// has no value for as null, and such a field must neither shadow the
    /// nested error object nor reach the journal as a value.
    fn error_field(&self, name: &str) -> Option<&serde_json::Value> {
        self.payload
            .get(name)
            .filter(|value| !value.is_null())
            .or_else(|| {
                self.error_object()
                    .and_then(|error| error.get(name))
                    .filter(|value| !value.is_null())
            })
    }

    /// The nested error object of the payload (§2.5.2).
    fn error_object(&self) -> Option<&serde_json::Value> {
        self.payload.get("error").filter(|value| value.is_object())
    }
}

/// The kind of a push of the device (protocol §2.5.4, §2.5.5).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushKind {
    /// A status snapshot of the device.
    Status,
    /// An event of the device.
    Event,
}

/// A push of the device: a status snapshot or an event (protocol §2.5.4,
/// §2.5.5).
///
/// The body of the push is flattened into `fields`: the name of the key and
/// the value as text. A nested object is flattened one level, with a dot
/// between the names (`fw.esp`).
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Push {
    /// Whether the push is a status snapshot or an event.
    pub kind: PushKind,
    /// The identifier of the message.
    pub msg_id: Option<String>,
    /// The counter of the envelope (protocol §2.1).
    pub seq: Option<u64>,
    /// The body of the push: the name of the key and the value as text.
    pub fields: Vec<(String, String)>,
}

/// Parse the open text of a `PUSH` frame (protocol §2.5.4, §2.5.5).
///
/// `None` means the text is not a push: the type of the envelope is neither
/// "status" nor "event", or the body is not an object. Such a text is shown
/// as it is.
#[allow(dead_code)]
pub fn parse_push(text: &[u8]) -> Option<Push> {
    let Envelope {
        msg_type,
        msg_id,
        seq,
        payload,
        ..
    } = Envelope::parse(text)?;
    let kind = match msg_type.as_str() {
        MSG_TYPE_STATUS => PushKind::Status,
        MSG_TYPE_EVENT => PushKind::Event,
        _ => return None,
    };
    // The body of a push is an object (protocol §2.5.4, §2.5.5); a body of
    // another shape is not a push.
    let body = payload.as_object()?;
    Some(Push {
        kind,
        msg_id,
        seq,
        fields: body_fields(body),
    })
}

/// The fields of the body of a push: the name of the key and the value.
///
/// A nested object is flattened one level: the key of the inner object is
/// appended to the outer key with a dot (`fw.esp`). A string value is kept as
/// it is, every other value is the compact JSON of the value.
fn body_fields(body: &serde_json::Map<String, serde_json::Value>) -> Vec<(String, String)> {
    let mut fields = Vec::new();
    for (key, value) in body {
        match value {
            serde_json::Value::Object(inner) => {
                for (inner_key, inner_value) in inner {
                    fields.push((format!("{key}.{inner_key}"), field_value(inner_value)));
                }
            }
            value => fields.push((key.clone(), field_value(value))),
        }
    }
    fields
}

/// The value of a field as text: a string as it is, every other value as the
/// compact JSON of the value.
fn field_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A frame of the given type with an empty encrypted body.
    fn encrypted_frame(packet_type: PacketType, session_id: u16, seq_num: u32) -> Frame {
        Frame {
            header: Header {
                packet_type,
                session_id,
                seq_num,
                timestamp: 1_700_000_000,
            },
            body: Body::Encrypted {
                nonce: build_nonce(session_id, DIRECTION_APP_TO_ESP, seq_num, [9u8; 5]),
                // Ciphertext of 3 bytes plus the tag.
                ciphertext: [1u8, 2, 3]
                    .into_iter()
                    .chain(std::iter::repeat_n(0u8, TAG_LEN))
                    .collect(),
            },
        }
    }

    #[test]
    fn round_trip_handshake_frames() {
        let hello = Frame {
            header: Header {
                packet_type: PacketType::Hello,
                session_id: 0,
                seq_num: 0,
                timestamp: 111,
            },
            body: Body::Hello {
                nonce_a: [1u8; HANDSHAKE_NONCE_LEN],
            },
        };
        assert_eq!(decode(&encode(&hello)).unwrap(), hello);

        let challenge = Frame {
            header: Header {
                packet_type: PacketType::Challenge,
                session_id: 0,
                seq_num: 0,
                timestamp: 222,
            },
            body: Body::Challenge {
                nonce_b: [2u8; HANDSHAKE_NONCE_LEN],
                proof_b: [3u8; PROOF_LEN],
            },
        };
        assert_eq!(decode(&encode(&challenge)).unwrap(), challenge);

        let response = Frame {
            header: Header {
                packet_type: PacketType::Response,
                session_id: 0,
                seq_num: 0,
                timestamp: 333,
            },
            body: Body::Response {
                proof_a: [4u8; PROOF_LEN],
            },
        };
        assert_eq!(decode(&encode(&response)).unwrap(), response);

        let ok = Frame {
            header: Header {
                packet_type: PacketType::SessionOk,
                session_id: 7,
                seq_num: 0,
                timestamp: 444,
            },
            body: Body::SessionOk,
        };
        assert_eq!(decode(&encode(&ok)).unwrap(), ok);

        let err = Frame {
            header: Header {
                packet_type: PacketType::SessionErr,
                session_id: 0,
                seq_num: 0,
                timestamp: 555,
            },
            body: Body::SessionErr { code: 0x02 },
        };
        assert_eq!(decode(&encode(&err)).unwrap(), err);
    }

    #[test]
    fn round_trip_encrypted_frames() {
        for packet_type in [PacketType::Data, PacketType::Push, PacketType::Close] {
            let frame = encrypted_frame(packet_type, 0x1234, 42);
            let bytes = encode(&frame);
            assert_eq!(decode(&bytes).unwrap(), frame);
            // 12 header + 12 nonce + 4 length + 3 ciphertext + 16 tag
            assert_eq!(bytes.len(), 47);
            // The length field counts the open text, not the tag.
            assert_eq!(&bytes[24..28], &3u32.to_be_bytes());
        }
    }

    #[test]
    fn header_fields_are_big_endian() {
        let frame = encrypted_frame(PacketType::Data, 0x0102, 0x0304_0506);
        let bytes = encode(&frame);
        assert_eq!(bytes[0], VERSION);
        assert_eq!(bytes[1], 0x10);
        assert_eq!(&bytes[2..4], &0x0102u16.to_be_bytes());
        assert_eq!(&bytes[4..8], &0x0304_0506u32.to_be_bytes());
        assert_eq!(&bytes[8..12], &1_700_000_000u32.to_be_bytes());
        // The header bytes are the AAD: the same 12 bytes come back from the
        // helper that builds them.
        assert_eq!(&bytes[..HEADER_LEN], &header_bytes(&frame.header));
    }

    #[test]
    fn decode_rejects_bad_version_and_unknown_type() {
        let mut bytes = encode(&Frame {
            header: Header {
                packet_type: PacketType::SessionErr,
                session_id: 0,
                seq_num: 0,
                timestamp: 0,
            },
            body: Body::SessionErr { code: 1 },
        });
        bytes[0] = 2;
        assert!(matches!(decode(&bytes), Err(DecodeError::BadVersion)));
        bytes[0] = VERSION;
        bytes[1] = 0x06;
        assert!(matches!(decode(&bytes), Err(DecodeError::UnknownType)));
    }

    #[test]
    fn decode_enforces_session_id_rules() {
        // A handshake frame must not name a session.
        let mut bytes = encode(&Frame {
            header: Header {
                packet_type: PacketType::Hello,
                session_id: 0,
                seq_num: 0,
                timestamp: 0,
            },
            body: Body::Hello {
                nonce_a: [0u8; HANDSHAKE_NONCE_LEN],
            },
        });
        bytes[2] = 1;
        assert!(matches!(decode(&bytes), Err(DecodeError::BadSessionId)));

        // SESSION_OK must name one.
        let bytes = encode(&Frame {
            header: Header {
                packet_type: PacketType::SessionOk,
                session_id: 0,
                seq_num: 0,
                timestamp: 0,
            },
            body: Body::SessionOk,
        });
        assert!(matches!(decode(&bytes), Err(DecodeError::BadSessionId)));

        // The same for encrypted frames.
        let mut bytes = encode(&encrypted_frame(PacketType::Data, 5, 1));
        bytes[2] = 0;
        bytes[3] = 0;
        assert!(matches!(decode(&bytes), Err(DecodeError::BadSessionId)));
    }

    #[test]
    fn decode_rejects_wrong_body_length() {
        // A short HELLO body.
        let mut bytes = encode(&Frame {
            header: Header {
                packet_type: PacketType::Hello,
                session_id: 0,
                seq_num: 0,
                timestamp: 0,
            },
            body: Body::Hello {
                nonce_a: [0u8; HANDSHAKE_NONCE_LEN],
            },
        });
        bytes.pop();
        assert!(matches!(decode(&bytes), Err(DecodeError::Truncated)));

        // A HELLO body with trailing bytes is not trimmed.
        let mut bytes = encode(&Frame {
            header: Header {
                packet_type: PacketType::Hello,
                session_id: 0,
                seq_num: 0,
                timestamp: 0,
            },
            body: Body::Hello {
                nonce_a: [0u8; HANDSHAKE_NONCE_LEN],
            },
        });
        bytes.push(0);
        assert!(matches!(decode(&bytes), Err(DecodeError::Truncated)));

        // SESSION_OK carries no body at all.
        let mut bytes = encode(&Frame {
            header: Header {
                packet_type: PacketType::SessionOk,
                session_id: 3,
                seq_num: 0,
                timestamp: 0,
            },
            body: Body::SessionOk,
        });
        bytes.push(0);
        assert!(matches!(decode(&bytes), Err(DecodeError::Truncated)));

        // SESSION_ERR carries exactly one byte.
        let mut bytes = encode(&Frame {
            header: Header {
                packet_type: PacketType::SessionErr,
                session_id: 0,
                seq_num: 0,
                timestamp: 0,
            },
            body: Body::SessionErr { code: 1 },
        });
        bytes.push(0);
        assert!(matches!(decode(&bytes), Err(DecodeError::Truncated)));
    }

    #[test]
    fn decode_rejects_bad_payload_length() {
        let mut bytes = encode(&encrypted_frame(PacketType::Data, 1, 1));
        bytes[24..28].copy_from_slice(&4u32.to_be_bytes());
        assert!(matches!(decode(&bytes), Err(DecodeError::BadLength)));
        bytes[24..28].copy_from_slice(&3u32.to_be_bytes());
        assert!(decode(&bytes).is_ok());
    }

    #[test]
    fn datagram_over_1400_is_too_long() {
        let raw = vec![0u8; MAX_DATAGRAM + 1];
        assert!(matches!(decode(&raw), Err(DecodeError::TooLong)));
        // The limit itself is still a legal datagram.
        let raw = vec![0u8; MAX_DATAGRAM];
        assert!(decode(&raw).is_err());
        assert_eq!(MAX_PLAINTEXT, 1356);
    }

    #[test]
    fn nonce_layout() {
        let nonce = build_nonce(0x0102, DIRECTION_ESP_TO_APP, 0x0304_0506, [1, 2, 3, 4, 5]);
        assert_eq!(nonce.len(), NONCE_LEN);
        assert_eq!(&nonce[..2], &0x0102u16.to_be_bytes());
        assert_eq!(nonce[2], DIRECTION_ESP_TO_APP);
        assert_eq!(&nonce[3..7], &0x0304_0506u32.to_be_bytes());
        assert_eq!(&nonce[7..], &[1, 2, 3, 4, 5]);
        assert!(nonce_matches(
            &nonce,
            0x0102,
            DIRECTION_ESP_TO_APP,
            0x0304_0506
        ));
        // The direction is part of the identity.
        assert!(!nonce_matches(
            &nonce,
            0x0102,
            DIRECTION_APP_TO_ESP,
            0x0304_0506
        ));
        assert!(!nonce_matches(
            &nonce,
            0x0103,
            DIRECTION_ESP_TO_APP,
            0x0304_0506
        ));
        assert!(!nonce_matches(&nonce, 0x0102, DIRECTION_ESP_TO_APP, 7));
    }

    #[test]
    fn proof_inputs_differ_by_context_and_order() {
        let nonce_a = [1u8; HANDSHAKE_NONCE_LEN];
        let nonce_b = [2u8; HANDSHAKE_NONCE_LEN];
        let b = proof_b_input(&nonce_a, &nonce_b);
        let a = proof_a_input(&nonce_b, &nonce_a);
        assert_eq!(b.len(), HANDSHAKE_NONCE_LEN * 2 + 1);
        assert_eq!(a.len(), HANDSHAKE_NONCE_LEN * 2 + 1);
        assert_eq!(b[HANDSHAKE_NONCE_LEN * 2], PROOF_B_CONTEXT);
        assert_eq!(a[HANDSHAKE_NONCE_LEN * 2], PROOF_A_CONTEXT);
        // The nonce order differs: the proof of one side cannot be replayed
        // as the proof of the other.
        assert_eq!(&b[..HANDSHAKE_NONCE_LEN], &nonce_a);
        assert_eq!(&a[..HANDSHAKE_NONCE_LEN], &nonce_b);
    }

    #[test]
    fn hkdf_info_has_no_null_terminator() {
        assert_eq!(HKDF_INFO.len(), 23);
        assert_eq!(HKDF_INFO, b"hiot-udp-v1-session-key");
        assert!(!HKDF_INFO.contains(&0));
    }

    #[test]
    fn envelope_reads_the_fields_of_the_contract() {
        // The answer of the device (protocol §2.1, §5.12).
        let text = br#"{"protocol_version":"1.0","msg_type":"ack","msg_id":"a-1",
            "correlation_id":"c-1","device_id":"dev_1","ts_utc":"2026-07-19T18:05:01.000Z",
            "seq":2,"source":"device","payload":{"result":"applied","device_state":"idle"}}"#;
        let envelope = Envelope::parse(text).expect("the text is an envelope");
        assert_eq!(envelope.msg_type, MSG_TYPE_ACK);
        assert!(envelope.is_reply());
        assert!(!envelope.is_command());
        assert_eq!(envelope.msg_id.as_deref(), Some("a-1"));
        assert_eq!(envelope.correlation_id.as_deref(), Some("c-1"));
        assert_eq!(envelope.seq, Some(2));
        assert_eq!(envelope.result(), Some("applied"));
        assert_eq!(envelope.command_name(), None);
    }

    #[test]
    fn envelope_of_a_command_carries_the_name() {
        let text = br#"{"protocol_version":"1.0","msg_type":"command","msg_id":"c-1",
            "ts_utc":"2026-07-19T18:05:00.000Z","seq":1,"source":"app",
            "payload":{"cmd":"get_status","scope":"device","ttl_sec":30,"params":{}}}"#;
        let envelope = Envelope::parse(text).expect("the text is an envelope");
        assert!(envelope.is_command());
        assert!(!envelope.is_reply());
        assert_eq!(envelope.command_name(), Some("get_status"));
        assert_eq!(envelope.msg_id.as_deref(), Some("c-1"));
    }

    #[test]
    fn an_error_envelope_carries_the_code() {
        let text = br#"{"protocol_version":"1.0","msg_type":"error","device_id":"",
            "ts_utc":"1970-01-01T00:00:00.000Z","seq":1,"source":"device",
            "payload":{"code":"E_INVALID_CMD","severity":"error",
            "message":"The command is not a valid message","retryable":false}}"#;
        let envelope = Envelope::parse(text).expect("the text is an envelope");
        assert!(envelope.is_reply());
        assert_eq!(envelope.error_code(), Some("E_INVALID_CMD"));
        // The answer to a text that is not a command names no command.
        assert_eq!(envelope.msg_id, None);
        assert_eq!(envelope.correlation_id, None);
    }

    #[test]
    fn the_error_fields_are_read_from_the_flat_payload() {
        let text = br#"{"msg_type":"error","payload":{"code":"E_COMMAND_NOT_ALLOWED",
            "severity":"error","message":"Command not allowed on UDP channel",
            "retryable":false,"details":{"command":"rotate_local_secret"}}}"#;
        let envelope = Envelope::parse(text).expect("the text is an envelope");
        assert_eq!(envelope.error_code(), Some("E_COMMAND_NOT_ALLOWED"));
        assert_eq!(envelope.error_severity(), Some("error"));
        assert_eq!(
            envelope.error_message(),
            Some("Command not allowed on UDP channel")
        );
        assert_eq!(envelope.error_retryable(), Some(false));
        assert_eq!(
            envelope
                .error_details()
                .and_then(|d| d.get("command"))
                .and_then(|c| c.as_str()),
            Some("rotate_local_secret")
        );
    }

    #[test]
    fn the_error_fields_are_read_from_the_nested_error_object() {
        let text = br#"{"msg_type":"ack","payload":{"result":"rejected",
            "error":{"code":"E_POWER_LIMIT","severity":"warning",
            "message":"too hot","retryable":true}}}"#;
        let envelope = Envelope::parse(text).expect("the text is an envelope");
        assert_eq!(envelope.error_code(), Some("E_POWER_LIMIT"));
        assert_eq!(envelope.error_severity(), Some("warning"));
        assert_eq!(envelope.error_message(), Some("too hot"));
        assert_eq!(envelope.error_retryable(), Some(true));
    }

    #[test]
    fn the_ack_fields_are_read() {
        let text = br#"{"msg_type":"ack","payload":{"result":"applied","device_state":"unknown",
            "warnings":[],"data":{"bowls":1}}}"#;
        let envelope = Envelope::parse(text).expect("the text is an envelope");
        assert_eq!(envelope.result(), Some("applied"));
        assert_eq!(envelope.device_state(), Some("unknown"));
        assert_eq!(envelope.warnings(), Some(vec![]));
        assert_eq!(
            envelope
                .data()
                .and_then(|d| d.get("bowls"))
                .and_then(|b| b.as_i64()),
            Some(1)
        );
    }

    #[test]
    fn the_flat_error_field_wins_over_the_nested_one() {
        // The payload carries both shapes: the flat field is the answer, the
        // nested object only fills the fields the payload does not carry.
        let text = br#"{"msg_type":"error","payload":{"code":"E_FLAT",
            "error":{"code":"E_NESTED","severity":"warning"}}}"#;
        let envelope = Envelope::parse(text).expect("the text is an envelope");
        assert_eq!(envelope.error_code(), Some("E_FLAT"));
        assert_eq!(envelope.error_severity(), Some("warning"));
    }

    #[test]
    fn a_null_field_is_read_as_absent() {
        // A null field counts as an absent field: it must not shadow the
        // nested error object and must not reach the journal as a value.
        let text = br#"{"msg_type":"error","payload":{"code":null,"message":null,
            "details":null,"data":null,"error":{"code":"E_NESTED"}}}"#;
        let envelope = Envelope::parse(text).expect("the text is an envelope");
        // The flat code is null, so the lookup falls through to the nested one.
        assert_eq!(envelope.error_code(), Some("E_NESTED"));
        // A null field carries no value.
        assert_eq!(envelope.error_message(), None);
        assert_eq!(envelope.error_severity(), None);
        // The details are absent, not "null".
        assert_eq!(envelope.error_details(), None);
        // The data are absent, not "null".
        assert_eq!(envelope.data(), None);
    }

    #[test]
    fn a_warning_that_is_not_a_string_comes_as_compact_json() {
        let text = br#"{"msg_type":"ack","payload":{"result":"applied",
            "warnings":["hot",3,{"code":1}]}}"#;
        let envelope = Envelope::parse(text).expect("the text is an envelope");
        assert_eq!(
            envelope.warnings(),
            Some(vec![
                "hot".to_string(),
                "3".to_string(),
                r#"{"code":1}"#.to_string(),
            ])
        );
    }

    #[test]
    fn a_text_without_a_type_is_not_an_envelope() {
        // A plain command line is not an envelope.
        assert!(Envelope::parse(b"get_status").is_none());
        // A JSON object without a type is not an envelope either.
        assert!(Envelope::parse(br#"{"a":1}"#).is_none());
        // A type that is not a string is not an envelope.
        assert!(Envelope::parse(br#"{"msg_type":1}"#).is_none());
        // Broken JSON is not an envelope.
        assert!(Envelope::parse(b"{").is_none());
        // An empty body is not an envelope.
        assert!(Envelope::parse(b"").is_none());
    }

    #[test]
    fn a_null_correlation_means_no_command() {
        let text = br#"{"msg_type":"ack","correlation_id":null,"payload":{}}"#;
        let envelope = Envelope::parse(text).expect("the text is an envelope");
        assert_eq!(envelope.correlation_id, None);
        assert_eq!(envelope.result(), None);
    }

    #[test]
    fn format_frame_fields_lists_the_header_and_the_body() {
        let hello = Frame {
            header: Header {
                packet_type: PacketType::Hello,
                session_id: 0,
                seq_num: 0,
                timestamp: 1_794_943_500,
            },
            body: Body::Hello {
                nonce_a: [0xab; HANDSHAKE_NONCE_LEN],
            },
        };
        let text = format_frame_fields(&hello, None);
        assert_eq!(
            text,
            format!(
                "version: 1\npacket_type: HELLO (0x01)\nsession_id: 0x0000\nseq_num: 0\ntimestamp: 1794943500\nnonce_a: {}",
                "ab".repeat(HANDSHAKE_NONCE_LEN)
            )
        );

        let err = Frame {
            header: Header {
                packet_type: PacketType::SessionErr,
                session_id: 0,
                seq_num: 0,
                timestamp: 10,
            },
            body: Body::SessionErr { code: 0x03 },
        };
        assert!(format_frame_fields(&err, None).ends_with("\nerror_code: 0x03"));
        assert!(!format_frame_fields(&err, None).contains("nonce"));

        let mut ciphertext = b"hi".to_vec();
        ciphertext.extend_from_slice(&[0u8; TAG_LEN]);
        let close = Frame {
            header: Header {
                packet_type: PacketType::Close,
                session_id: 0x5353,
                seq_num: 1,
                timestamp: 20,
            },
            body: Body::Encrypted {
                nonce: [0x11; NONCE_LEN],
                ciphertext,
            },
        };
        let text = format_frame_fields(&close, Some(b"hi"));
        assert!(text.contains("packet_type: CLOSE (0x1F)\n"));
        assert!(text.contains("session_id: 0x5353\n"));
        assert!(text.contains("seq_num: 1\n"));
        assert!(text.contains(&format!("nonce: {}\n", "11".repeat(NONCE_LEN))));
        assert!(text.contains("payload_length: 2\n"));
        assert!(text.ends_with("payload: hi"));
        assert!(!text.contains("cipher"));
    }

    #[test]
    fn command_envelope_has_the_fields_of_the_protocol() {
        let bytes = command_envelope(
            "550e8400-e29b-41d4-a716-446655440000",
            "dev_00001A2B3C",
            "2023-11-14T22:13:20.000Z",
            1,
            "get_status",
        );
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(object.len(), 8);
        assert_eq!(object["protocol_version"], "1.0");
        assert_eq!(object["msg_type"], "command");
        assert_eq!(object["msg_id"], "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(object["device_id"], "dev_00001A2B3C");
        assert_eq!(object["ts_utc"], "2023-11-14T22:13:20.000Z");
        assert_eq!(object["seq"], serde_json::json!(1));
        assert_eq!(object["source"], "app");
        assert_eq!(object["payload"]["cmd"], "get_status");
        assert_eq!(object["payload"]["scope"], "device");
        assert_eq!(object["payload"]["ttl_sec"], serde_json::json!(30));
        assert_eq!(object["payload"]["params"], serde_json::json!({}));
        assert_eq!(object["payload"].as_object().unwrap().len(), 4);
        assert!(object.get("correlation_id").is_none());
        assert!(object.get("signature").is_none());
    }

    #[test]
    fn the_device_id_is_always_in_the_envelope() {
        let bytes = command_envelope(
            "550e8400-e29b-41d4-a716-446655440000",
            "",
            "2023-11-14T22:13:20.000Z",
            1,
            "get_status",
        );
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(object.len(), 8);
        assert_eq!(object["device_id"], "");
    }

    #[test]
    fn a_status_push_is_parsed() {
        let text = br#"{"protocol_version":"1.0","msg_type":"status","msg_id":"status-3",
            "device_id":"","ts_utc":"2026-11-27T10:00:00.000Z","seq":12,"source":"device",
            "payload":{"mcu_connected":true,"wifi_rssi":-59,"fw":{"esp":"1.2.3","proto":"1.0"},
            "active_errors":[],"ota":null}}"#;
        let push = parse_push(text).expect("the text is a status push");
        assert_eq!(push.kind, PushKind::Status);
        assert_eq!(push.msg_id.as_deref(), Some("status-3"));
        assert_eq!(push.seq, Some(12));
        assert!(
            push.fields
                .contains(&("mcu_connected".to_string(), "true".to_string()))
        );
        assert!(
            push.fields
                .contains(&("wifi_rssi".to_string(), "-59".to_string()))
        );
        assert!(
            push.fields
                .contains(&("fw.esp".to_string(), "1.2.3".to_string()))
        );
        assert!(
            push.fields
                .contains(&("ota".to_string(), "null".to_string()))
        );
    }

    #[test]
    fn an_event_push_is_parsed() {
        let text = br#"{"protocol_version":"1.0","msg_type":"event","msg_id":"event-7",
            "device_id":"","ts_utc":"2026-11-27T10:00:01.000Z","seq":13,"source":"device",
            "payload":{"event_type":"bowl_overflow","bowl_id":"1"}}"#;
        let push = parse_push(text).expect("the text is an event push");
        assert_eq!(push.kind, PushKind::Event);
        assert!(
            push.fields
                .contains(&("event_type".to_string(), "bowl_overflow".to_string()))
        );
    }

    #[test]
    fn a_status_without_the_optional_keys_is_parsed() {
        // The snapshot does not have to carry device_state or fw.mcu.
        let text = br#"{"msg_type":"status","payload":{"mcu_connected":false}}"#;
        let push = parse_push(text).expect("the text is a status push");
        assert_eq!(push.fields.len(), 1);
        assert_eq!(
            push.fields[0],
            ("mcu_connected".to_string(), "false".to_string())
        );
    }

    #[test]
    fn a_text_that_is_not_a_push_stays_raw() {
        // A body that is not an object, an unknown type, a broken JSON.
        assert!(parse_push(br#"{"msg_type":"ack","payload":{}}"#).is_none());
        assert!(parse_push(br#"{"msg_type":"status","payload":"text"}"#).is_none());
        assert!(parse_push(b"not json").is_none());
    }
}
