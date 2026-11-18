//! UDP Session 协议的密码学原语。
//!
//! 本模块只提供「算法封装」，不含任何协议常量（magic、HKDF info、nonce 公式等
//! 属于 `codec.rs` 的字节契约）。所有输入都是代码组装出的字节，不是 UI 里的字符串。

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// AES-GCM 认证标签长度（字节）
pub const TAG_LEN: usize = 16;
/// AES-GCM nonce 长度（字节）
pub const NONCE_LEN: usize = 12;
/// AES-256 密钥长度（字节）
pub const KEY_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// AES-256-GCM 的 96 位 nonce 类型
type GcmNonce = aes_gcm::aead::Nonce<Aes256Gcm>;

/// HMAC-SHA256 摘要（32 字节）
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// 校验 HMAC-SHA256 摘要（常量时间比较由 crate 保证）
pub fn hmac_verify(key: &[u8], data: &[u8], expected: &[u8]) -> bool {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.verify_slice(expected).is_ok()
}

/// HKDF-SHA256 派生 32 字节输出密钥
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; KEY_LEN];
    hk.expand(info, &mut okm).expect("32-byte OKM fits SHA-256");
    okm
}

/// AES-256-GCM 加密：返回「密文 || 16 字节标签」
pub fn aes_gcm_encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plain: &[u8],
) -> Result<Vec<u8>, ()> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ())?;
    let nonce = GcmNonce::from(*nonce);
    cipher
        .encrypt(&nonce, Payload { msg: plain, aad })
        .map_err(|_| ())
}

/// AES-256-GCM 解密：认证失败（标签不符）返回 Err
pub fn aes_gcm_decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    cipher_text: &[u8],
) -> Result<Vec<u8>, ()> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ())?;
    let nonce = GcmNonce::from(*nonce);
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: cipher_text,
                aad,
            },
        )
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_sha256_rfc4231_case1() {
        let key = [0x0bu8; 20];
        let mac = hmac_sha256(&key, b"Hi There");
        assert_eq!(
            mac,
            hex_to_32("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
    }

    #[test]
    fn hmac_verify_rejects_other_mac() {
        let mac = hmac_sha256(b"k", b"data");
        assert!(hmac_verify(b"k", b"data", &mac));
        assert!(!hmac_verify(b"k", b"data", &[0u8; 32]));
        assert!(!hmac_verify(b"other", b"data", &mac));
    }

    #[test]
    fn hkdf_sha256_rfc5869_a1_first_32() {
        let ikm = [0x0bu8; 22];
        let salt: [u8; 13] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0u8, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let okm = hkdf_sha256(&ikm, &salt, &info);
        assert_eq!(
            okm,
            hex_to_32("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")
        );
    }

    #[test]
    fn aes_gcm_round_trip_and_tamper() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        let aad = b"aad";
        let ct = aes_gcm_encrypt(&key, &nonce, aad, b"payload").unwrap();
        assert_eq!(ct.len(), b"payload".len() + TAG_LEN);
        assert_eq!(aes_gcm_decrypt(&key, &nonce, aad, &ct).unwrap(), b"payload");
        let mut bad_ct = ct.clone();
        bad_ct[0] ^= 0x01;
        assert!(aes_gcm_decrypt(&key, &nonce, aad, &bad_ct).is_err());
        assert!(aes_gcm_decrypt(&key, &nonce, b"aad!", &ct).is_err());
    }

    fn hex_to_32(s: &str) -> [u8; 32] {
        let bytes = hex::decode(s).unwrap();
        bytes.try_into().unwrap()
    }
}
