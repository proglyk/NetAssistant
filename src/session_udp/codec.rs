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

/// The JSON envelope of a business message (protocol §2.1).
///
/// The envelope is not a separate packet: it is the plain text of a `DATA`
/// frame. Only the fields the client needs are read; the unknown fields are
/// ignored (protocol §2.4.6).
#[derive(Debug, Clone, PartialEq)]
pub struct Envelope {
    /// The type of the message: "command", "ack", "error", "status", "event".
    pub msg_type: String,
    /// The identifier of the message.
    pub msg_id: Option<String>,
    /// The identifier of the command the message answers.
    pub correlation_id: Option<String>,
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
        let payload = object
            .get("payload")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        Some(Envelope {
            msg_type,
            msg_id,
            correlation_id,
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

    /// The code of an error (§2.5.3).
    pub fn error_code(&self) -> Option<&str> {
        self.payload.get("code").and_then(|value| value.as_str())
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
}
