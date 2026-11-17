//! UDP Session datagram codec.
//!
//! The byte contract is in appendix A of the design document: all integers are big-endian, the common header is
//! `magic u16 = 0xDA75` / `version u8 = 1` / `type u8`.
//!
//! The frame boundary is one datagram: the frame has no total-length field, trailing bytes always make the frame bad (they are never trimmed).

use crate::session_udp::crypto::{NONCE_LEN, TAG_LEN};
use std::fmt;

/// Frame magic.
pub const MAGIC: u16 = 0xDA75;
/// Protocol version.
pub const VERSION: u8 = 1;
/// Largest datagram (in bytes). A longer datagram is dropped before it reaches the state machine.
pub const MAX_DATAGRAM: usize = 2048;
/// The HKDF info string (the context separator of the key derivation).
pub const HKDF_INFO: &[u8] = b"netassistant-udp-session-v1";

/// Packet type: Hello
const TYPE_HELLO: u8 = 1;
/// Packet type: SessionOk
const TYPE_SESSION_OK: u8 = 2;
/// Packet type: SessionErr
const TYPE_SESSION_ERR: u8 = 3;
/// Packet type: Data
const TYPE_DATA: u8 = 4;
/// Packet type: Close
const TYPE_CLOSE: u8 = 5;

/// Length of the common header (magic 2 + version 1 + type 1)
const HEADER_LEN: usize = 4;
/// Length of the session id / nonce
const ID_LEN: usize = 16;
/// Length of a proof (HMAC-SHA256)
const PROOF_LEN: usize = 32;
/// Largest SessionErr message
const MAX_SESSION_ERR_MSG: usize = 256;

/// Protocol packet
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    /// First packet of the client handshake: `nonce_a` + `proof_a`
    Hello {
        nonce_a: [u8; ID_LEN],
        proof_a: [u8; PROOF_LEN],
    },
    /// Handshake answer of the server: `session_id` + `nonce_b` + `proof_b`
    SessionOk {
        session_id: [u8; ID_LEN],
        nonce_b: [u8; ID_LEN],
        proof_b: [u8; PROOF_LEN],
    },
    /// The server refuses the handshake
    SessionErr { code: u16, message: String },
    /// Session data (ciphertext with a 16-byte GCM tag)
    Data {
        session_id: [u8; ID_LEN],
        seq: u64,
        ciphertext: Vec<u8>,
    },
    /// Session close (neither encrypted nor authenticated)
    Close { session_id: [u8; ID_LEN], seq: u64 },
}

/// Reason of a decoding failure
#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The frame is shorter than the type requires
    Truncated,
    /// The magic does not match
    BadMagic,
    /// The version does not match
    BadVersion,
    /// Unknown packet type
    UnknownType,
    /// The length field does not match the actual length (or exceeds the protocol limit)
    BadLength,
    /// The frame has trailing bytes
    TrailingBytes,
    /// The datagram is longer than `MAX_DATAGRAM`
    TooLong,
    /// The message of the SessionErr is not valid UTF-8
    BadSessionErrUtf8,
}

impl fmt::Display for DecodeError {
    /// The error text describes the reason only and does not echo the input bytes (the frame may carry session data)
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            DecodeError::Truncated => "truncated datagram",
            DecodeError::BadMagic => "bad magic",
            DecodeError::BadVersion => "bad version",
            DecodeError::UnknownType => "unknown packet type",
            DecodeError::BadLength => "bad length",
            DecodeError::TrailingBytes => "trailing bytes",
            DecodeError::TooLong => "datagram too long",
            DecodeError::BadSessionErrUtf8 => "bad session err",
        };
        write!(f, "{text}")
    }
}

/// Common header
fn header(packet_type: u8) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[0..2].copy_from_slice(&MAGIC.to_be_bytes());
    out[2] = VERSION;
    out[3] = packet_type;
    out
}

/// Encode a protocol packet into datagram bytes
pub fn encode(packet: &Packet) -> Vec<u8> {
    let mut out = Vec::new();
    match packet {
        Packet::Hello { nonce_a, proof_a } => {
            out.extend_from_slice(&header(TYPE_HELLO));
            out.extend_from_slice(nonce_a);
            out.extend_from_slice(proof_a);
        }
        Packet::SessionOk {
            session_id,
            nonce_b,
            proof_b,
        } => {
            out.extend_from_slice(&header(TYPE_SESSION_OK));
            out.extend_from_slice(session_id);
            out.extend_from_slice(nonce_b);
            out.extend_from_slice(proof_b);
        }
        Packet::SessionErr { code, message } => {
            debug_assert!(message.len() <= MAX_SESSION_ERR_MSG);
            out.extend_from_slice(&header(TYPE_SESSION_ERR));
            out.extend_from_slice(&code.to_be_bytes());
            out.extend_from_slice(&(message.len() as u16).to_be_bytes());
            out.extend_from_slice(message.as_bytes());
        }
        Packet::Data {
            session_id,
            seq,
            ciphertext,
        } => {
            out.extend_from_slice(&header(TYPE_DATA));
            out.extend_from_slice(session_id);
            out.extend_from_slice(&seq.to_be_bytes());
            out.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
            out.extend_from_slice(ciphertext);
        }
        Packet::Close { session_id, seq } => {
            out.extend_from_slice(&header(TYPE_CLOSE));
            out.extend_from_slice(session_id);
            out.extend_from_slice(&seq.to_be_bytes());
        }
    }
    out
}

/// Parse datagram bytes
pub fn decode(buf: &[u8]) -> Result<Packet, DecodeError> {
    if buf.len() > MAX_DATAGRAM {
        return Err(DecodeError::TooLong);
    }
    if buf.len() < HEADER_LEN {
        return Err(DecodeError::Truncated);
    }
    let magic = u16::from_be_bytes([buf[0], buf[1]]);
    if magic != MAGIC {
        return Err(DecodeError::BadMagic);
    }
    if buf[2] != VERSION {
        return Err(DecodeError::BadVersion);
    }
    let body = &buf[HEADER_LEN..];
    match buf[3] {
        TYPE_HELLO => {
            const BODY_LEN: usize = ID_LEN + PROOF_LEN;
            if body.len() < BODY_LEN {
                return Err(DecodeError::Truncated);
            }
            if body.len() > BODY_LEN {
                return Err(DecodeError::TrailingBytes);
            }
            let mut nonce_a = [0u8; ID_LEN];
            nonce_a.copy_from_slice(&body[..ID_LEN]);
            let mut proof_a = [0u8; PROOF_LEN];
            proof_a.copy_from_slice(&body[ID_LEN..]);
            Ok(Packet::Hello { nonce_a, proof_a })
        }
        TYPE_SESSION_OK => {
            const BODY_LEN: usize = ID_LEN * 2 + PROOF_LEN;
            if body.len() < BODY_LEN {
                return Err(DecodeError::Truncated);
            }
            if body.len() > BODY_LEN {
                return Err(DecodeError::TrailingBytes);
            }
            let mut session_id = [0u8; ID_LEN];
            session_id.copy_from_slice(&body[..ID_LEN]);
            let mut nonce_b = [0u8; ID_LEN];
            nonce_b.copy_from_slice(&body[ID_LEN..ID_LEN * 2]);
            let mut proof_b = [0u8; PROOF_LEN];
            proof_b.copy_from_slice(&body[ID_LEN * 2..]);
            Ok(Packet::SessionOk {
                session_id,
                nonce_b,
                proof_b,
            })
        }
        TYPE_SESSION_ERR => {
            if body.len() < 4 {
                return Err(DecodeError::Truncated);
            }
            let code = u16::from_be_bytes([body[0], body[1]]);
            let len = u16::from_be_bytes([body[2], body[3]]) as usize;
            if len > MAX_SESSION_ERR_MSG {
                return Err(DecodeError::BadLength);
            }
            let msg = &body[4..];
            if msg.len() < len {
                return Err(DecodeError::Truncated);
            }
            if msg.len() > len {
                return Err(DecodeError::TrailingBytes);
            }
            let message =
                String::from_utf8(msg.to_vec()).map_err(|_| DecodeError::BadSessionErrUtf8)?;
            Ok(Packet::SessionErr { code, message })
        }
        TYPE_DATA => {
            const HEAD_LEN: usize = ID_LEN + 8 + 2;
            if body.len() < HEAD_LEN {
                return Err(DecodeError::Truncated);
            }
            let mut session_id = [0u8; ID_LEN];
            session_id.copy_from_slice(&body[..ID_LEN]);
            let seq = u64::from_be_bytes(body[ID_LEN..ID_LEN + 8].try_into().unwrap());
            let cipher_len = u16::from_be_bytes([body[ID_LEN + 8], body[ID_LEN + 9]]);
            if (cipher_len as usize) < TAG_LEN {
                return Err(DecodeError::BadLength);
            }
            let ciphertext = &body[HEAD_LEN..];
            // cipher_len must equal the number of the remaining bytes: the extra tail is not trimmed, the whole frame is bad
            if ciphertext.len() != cipher_len as usize {
                return Err(DecodeError::BadLength);
            }
            Ok(Packet::Data {
                session_id,
                seq,
                ciphertext: ciphertext.to_vec(),
            })
        }
        TYPE_CLOSE => {
            const BODY_LEN: usize = ID_LEN + 8;
            if body.len() < BODY_LEN {
                return Err(DecodeError::Truncated);
            }
            if body.len() > BODY_LEN {
                return Err(DecodeError::TrailingBytes);
            }
            let mut session_id = [0u8; ID_LEN];
            session_id.copy_from_slice(&body[..ID_LEN]);
            let seq = u64::from_be_bytes(body[ID_LEN..].try_into().unwrap());
            Ok(Packet::Close { session_id, seq })
        }
        _ => Err(DecodeError::UnknownType),
    }
}

/// The HMAC coverage of the Hello: magic + version + type + nonce_a (without the proof)
pub fn hello_mac_input(nonce_a: &[u8; ID_LEN]) -> [u8; HEADER_LEN + ID_LEN] {
    let mut out = [0u8; HEADER_LEN + ID_LEN];
    out[..HEADER_LEN].copy_from_slice(&header(TYPE_HELLO));
    out[HEADER_LEN..].copy_from_slice(nonce_a);
    out
}

/// The HMAC coverage of the SessionOk: magic + version + type + session_id + nonce_b (without the proof)
pub fn session_ok_mac_input(
    session_id: &[u8; ID_LEN],
    nonce_b: &[u8; ID_LEN],
) -> [u8; HEADER_LEN + ID_LEN * 2] {
    let mut out = [0u8; HEADER_LEN + ID_LEN * 2];
    out[..HEADER_LEN].copy_from_slice(&header(TYPE_SESSION_OK));
    out[HEADER_LEN..HEADER_LEN + ID_LEN].copy_from_slice(session_id);
    out[HEADER_LEN + ID_LEN..].copy_from_slice(nonce_b);
    out
}

/// The nonce of the DATA: `session_id[0..4] || seq.to_be_bytes()`
pub fn data_nonce(session_id: &[u8; ID_LEN], seq: u64) -> [u8; NONCE_LEN] {
    let mut out = [0u8; NONCE_LEN];
    out[..4].copy_from_slice(&session_id[..4]);
    out[4..].copy_from_slice(&seq.to_be_bytes());
    out
}

/// The AAD of the DATA: all bytes of the DATA frame before the ciphertext (including cipher_len)
pub fn data_aad(
    session_id: &[u8; ID_LEN],
    seq: u64,
    cipher_len: u16,
) -> [u8; HEADER_LEN + ID_LEN + 8 + 2] {
    let mut out = [0u8; HEADER_LEN + ID_LEN + 8 + 2];
    out[..HEADER_LEN].copy_from_slice(&header(TYPE_DATA));
    out[HEADER_LEN..HEADER_LEN + ID_LEN].copy_from_slice(session_id);
    out[HEADER_LEN + ID_LEN..HEADER_LEN + ID_LEN + 8].copy_from_slice(&seq.to_be_bytes());
    let tail = HEADER_LEN + ID_LEN + 8;
    out[tail..].copy_from_slice(&cipher_len.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_hello_session_ok_close() {
        let hello = Packet::Hello {
            nonce_a: [1u8; 16],
            proof_a: [2u8; 32],
        };
        assert_eq!(decode(&encode(&hello)).unwrap(), hello);
        let ok = Packet::SessionOk {
            session_id: [3u8; 16],
            nonce_b: [4u8; 16],
            proof_b: [5u8; 32],
        };
        assert_eq!(decode(&encode(&ok)).unwrap(), ok);
        let close = Packet::Close {
            session_id: [3u8; 16],
            seq: 9,
        };
        assert_eq!(decode(&encode(&close)).unwrap(), close);
    }

    #[test]
    fn round_trip_session_err_and_data() {
        let err = Packet::SessionErr {
            code: 7,
            message: "nope".into(),
        };
        assert_eq!(decode(&encode(&err)).unwrap(), err);
        let data = Packet::Data {
            session_id: [9u8; 16],
            seq: 1,
            ciphertext: vec![0u8; 16],
        };
        let bytes = encode(&data);
        assert_eq!(decode(&bytes).unwrap(), data);
        assert_eq!(&bytes[..30], &data_aad(&[9u8; 16], 1, 16));
    }

    #[test]
    fn hello_mac_input_excludes_proof() {
        let nonce_a = [7u8; 16];
        let packet = Packet::Hello {
            nonce_a,
            proof_a: [9u8; 32],
        };
        let bytes = encode(&packet);
        let input = hello_mac_input(&nonce_a);
        assert_eq!(input.len(), 20);
        assert_eq!(&bytes[..20], &input);
        assert_ne!(&bytes[20..], &input[..]);
    }

    #[test]
    fn session_ok_mac_input_excludes_proof() {
        let session_id = [3u8; 16];
        let nonce_b = [4u8; 16];
        let packet = Packet::SessionOk {
            session_id,
            nonce_b,
            proof_b: [1u8; 32],
        };
        let bytes = encode(&packet);
        assert_eq!(&bytes[..36], &session_ok_mac_input(&session_id, &nonce_b));
    }

    #[test]
    fn truncated_unknown_magic_version() {
        assert!(matches!(decode(&[0xDA]), Err(DecodeError::Truncated)));
        assert!(matches!(
            decode(&[0x00, 0x00, 1, 1]),
            Err(DecodeError::BadMagic)
        ));
        assert!(matches!(
            decode(&0xDA75u16.to_be_bytes()),
            Err(DecodeError::Truncated)
        ));
        let mut bad_ver = encode(&Packet::Close {
            session_id: [0u8; 16],
            seq: 1,
        });
        bad_ver[2] = 2;
        assert!(matches!(decode(&bad_ver), Err(DecodeError::BadVersion)));
        let mut unknown = encode(&Packet::Close {
            session_id: [0u8; 16],
            seq: 1,
        });
        unknown[3] = 9;
        assert!(matches!(decode(&unknown), Err(DecodeError::UnknownType)));
    }

    #[test]
    fn trailing_byte_is_rejected() {
        let mut bytes = encode(&Packet::Close {
            session_id: [0u8; 16],
            seq: 1,
        });
        bytes.push(0);
        assert!(matches!(decode(&bytes), Err(DecodeError::TrailingBytes)));
    }

    #[test]
    fn data_cipher_len_does_not_truncate() {
        let mut bytes = encode(&Packet::Data {
            session_id: [9u8; 16],
            seq: 1,
            ciphertext: vec![0u8; 17],
        });
        bytes[28..30].copy_from_slice(&16u16.to_be_bytes());
        assert!(
            decode(&bytes).is_err(),
            "cipher_len is smaller than the tail — not Ok"
        );
        let mut short_tag = encode(&Packet::Data {
            session_id: [9u8; 16],
            seq: 1,
            ciphertext: vec![0u8; 16],
        });
        short_tag[28..30].copy_from_slice(&15u16.to_be_bytes());
        assert!(matches!(decode(&short_tag), Err(DecodeError::BadLength)));
        assert!(!DecodeError::BadLength.to_string().contains("00"));
    }

    #[test]
    fn session_err_bad_utf8_and_over_256() {
        let mut bytes = encode(&Packet::SessionErr {
            code: 1,
            message: "a".into(),
        });
        // Appendix A: SessionErr = code u16 + len u16 + message, the first byte of the message is at offset 8
        bytes[8] = 0xFF;
        assert!(matches!(
            decode(&bytes),
            Err(DecodeError::BadSessionErrUtf8)
        ));
        assert!(!DecodeError::BadSessionErrUtf8.to_string().contains("FF"));
        let max = encode(&Packet::SessionErr {
            code: 1,
            message: "a".repeat(256),
        });
        assert!(decode(&max).is_ok());
        let mut raw = vec![0xDA, 0x75, 1, 3, 0, 1];
        raw.extend_from_slice(&257u16.to_be_bytes());
        raw.extend(std::iter::repeat_n(b'a', 257));
        assert!(matches!(decode(&raw), Err(DecodeError::BadLength)));
    }

    #[test]
    fn datagram_over_2048_is_too_long() {
        let mut raw = vec![0u8; MAX_DATAGRAM + 1];
        raw[0..2].copy_from_slice(&MAGIC.to_be_bytes());
        assert!(matches!(decode(&raw), Err(DecodeError::TooLong)));
    }

    #[test]
    fn data_nonce_is_session_prefix_and_seq() {
        let mut session_id = [0u8; 16];
        session_id[0] = 0xAA;
        session_id[3] = 0xBB;
        let nonce = data_nonce(&session_id, 0x0102);
        assert_eq!(&nonce[..4], &session_id[..4]);
        assert_eq!(&nonce[4..], &0x0102u64.to_be_bytes());
        assert_eq!(nonce.len(), 12);
    }
}
