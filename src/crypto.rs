//! Crypto helpers. Hash/MAC/Base64 come from audited crates (RustCrypto +
//! `base64`). Only `x_encode` — Srun's reversible XXTEA-style protocol
//! obfuscation, which is not a security primitive — is implemented in-tree.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::engine::{GeneralPurpose, GeneralPurposeConfig};
use base64::{alphabet::Alphabet, Engine};
use hmac::{Hmac, KeyInit, Mac};
use md5::{Digest, Md5};
use sha1::Sha1;

/// Lowercase hex encoding of a byte slice.
pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

/// MD5 digest as raw bytes.
pub fn md5(input: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// MD5 digest as a lowercase hex string.
pub fn md5_hex(input: &[u8]) -> String {
    to_hex(&md5(input))
}

/// SHA-1 digest as a lowercase hex string.
pub fn sha1_hex(input: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(input);
    to_hex(&hasher.finalize())
}

/// HMAC-MD5 digest as a lowercase hex string (Srun password encryption).
pub fn hmac_md5_hex(key: &[u8], msg: &[u8]) -> String {
    let mut mac = Hmac::<Md5>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    to_hex(&mac.finalize().into_bytes())
}

/// Standard Base64 (used for the self-service SSO auth token).
pub fn base64_standard(data: &[u8]) -> String {
    BASE64_STANDARD.encode(data)
}

/// Srun custom-alphabet Base64. `alphabet` must be 64 unique chars; Srun pads
/// with `=` like standard Base64.
pub fn custom_base64(data: &[u8], alphabet: &str) -> String {
    let alpha = Alphabet::new(alphabet).expect("Srun alphabet is valid (64 unique chars)");
    let engine = GeneralPurpose::new(&alpha, GeneralPurposeConfig::default());
    engine.encode(data)
}

// ---------------------------------------------------------------------------
// xEncode (Srun's XXTEA-like routine), porting utils.xEncode
// ---------------------------------------------------------------------------

fn str_to_u32_list(bytes: &[u8], append_len: bool) -> Vec<u32> {
    let len = bytes.len();
    let mut words: Vec<u32> = Vec::new();
    let mut i = 0;
    while i < len {
        let byte0 = bytes[i] as u32;
        let byte1 = if i + 1 < len { bytes[i + 1] as u32 } else { 0 };
        let byte2 = if i + 2 < len { bytes[i + 2] as u32 } else { 0 };
        let byte3 = if i + 3 < len { bytes[i + 3] as u32 } else { 0 };
        // Pack 4 little-endian bytes into one 32-bit word.
        words.push(byte0 | (byte1 << 8) | (byte2 << 16) | (byte3 << 24));
        i += 4;
    }
    if append_len {
        words.push(len as u32);
    }
    words
}

fn u32_list_to_bytes(words: &[u32]) -> Vec<u8> {
    // Mirrors int_list_to_str(a, b=False): emit every byte of every word.
    let mut out = Vec::with_capacity(words.len() * 4);
    for &word in words {
        out.push((word & 0xff) as u8);
        out.push(((word >> 8) & 0xff) as u8);
        out.push(((word >> 16) & 0xff) as u8);
        out.push(((word >> 24) & 0xff) as u8);
    }
    out
}

/// Returns the encoded byte stream. Srun treats it as a latin-1 string before
/// feeding it into the custom Base64 encoder; byte-wise this is identical.
///
/// This is the XXTEA block cipher. The variable names below follow the
/// algorithm's conventional symbols; the mapping to readable names is:
///   words      = `v`  the data block being encrypted (mutated in place)
///   key_words  = `k`  the 4-word key
///   last_idx   = `n`  index of the last word
///   prev       = `z`  previous word in the mixing step
///   curr       = `y`  current word in the mixing step
///   DELTA      = `c`  XXTEA's magic constant (0x9E3779B9)
///   rounds     = `q`  number of mixing rounds
///   sum        = `d`  running key schedule sum
///   e          = `e`  sum-derived index selector
///   p          = loop index over the block
///   mix        = `m`  the per-word mixing value
pub fn x_encode(data: &[u8], key: &[u8]) -> Vec<u8> {
    const DELTA: u32 = 0x9E37_79B9;

    if data.is_empty() {
        return Vec::new();
    }

    let mut words = str_to_u32_list(data, true);
    let mut key_words = str_to_u32_list(key, false);
    while key_words.len() < 4 {
        key_words.push(0);
    }

    let last_idx = words.len() - 1;
    let mut prev = words[last_idx];
    let mut curr;

    let mut rounds = 6 + 52 / (last_idx as u32 + 1);
    let mut sum: u32 = 0;

    while rounds > 0 {
        sum = sum.wrapping_add(DELTA);
        let e = (sum >> 2) & 3;

        for p in 0..last_idx {
            curr = words[p + 1];
            let mut mix = (prev >> 5) ^ (curr << 2);
            mix = mix.wrapping_add(((curr >> 3) ^ (prev << 4)) ^ (sum ^ curr));
            mix = mix.wrapping_add(key_words[(p & 3) ^ e as usize] ^ prev);
            words[p] = words[p].wrapping_add(mix);
            prev = words[p];
        }

        // Final word of the block wraps around to use words[0] as `curr`.
        curr = words[0];
        let mut mix = (prev >> 5) ^ (curr << 2);
        mix = mix.wrapping_add(((curr >> 3) ^ (prev << 4)) ^ (sum ^ curr));
        mix = mix.wrapping_add(key_words[(last_idx & 3) ^ e as usize] ^ prev);
        words[last_idx] = words[last_idx].wrapping_add(mix);
        prev = words[last_idx];

        rounds -= 1;
    }

    u32_list_to_bytes(&words)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_known_vectors() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            md5_hex(b"The quick brown fox jumps over the lazy dog"),
            "9e107d9d372bb6826bd81d3542a419d6"
        );
    }

    #[test]
    fn sha1_known_vectors() {
        assert_eq!(sha1_hex(b""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(sha1_hex(b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn hmac_md5_known_vectors() {
        // RFC 2202 test case 1
        let key = [0x0bu8; 16];
        assert_eq!(
            hmac_md5_hex(&key, b"Hi There"),
            "9294727a3638bb1c13f48ef8158bfc9d"
        );
        // RFC 2202 test case 2
        assert_eq!(
            hmac_md5_hex(b"Jefe", b"what do ya want for nothing?"),
            "750c783e6ab0b503eaa86e310a5db738"
        );
    }

    #[test]
    fn base64_standard_matches() {
        assert_eq!(base64_standard(b""), "");
        assert_eq!(base64_standard(b"f"), "Zg==");
        assert_eq!(base64_standard(b"fo"), "Zm8=");
        assert_eq!(base64_standard(b"foo"), "Zm9v");
        assert_eq!(base64_standard(b"foob"), "Zm9vYg==");
        assert_eq!(base64_standard(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_standard(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn custom_base64_matches_standard_alphabet() {
        // With the standard alphabet, custom_base64 must equal base64_standard.
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        assert_eq!(
            custom_base64(b"foobar", alphabet),
            base64_standard(b"foobar")
        );
        assert_eq!(custom_base64(b"fo", alphabet), base64_standard(b"fo"));
    }

    #[test]
    fn x_encode_matches_python_reference() {
        // Reference output captured from the original Python utils.xEncode +
        // CustomBase64 with deterministic inputs, to prove byte-for-byte parity.
        let info = r#"{"username":"alice","password":"secret","ip":"10.0.0.5","acid":"1","enc_ver":"srun_bx1"}"#;
        let token = "abcdef0123456789token";
        let srun_alphabet = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA";

        let encoded = x_encode(info.as_bytes(), token.as_bytes());
        assert_eq!(
            to_hex(&encoded),
            "10036aa2f6b35eb256e6ee185df64e393ab010c78408148c33ac9f55453eb8f20fdf353918d979dc727cd3ef3eb828feb49f3883ef69af0107c9142af279527f8089cc9451cf7ec1f78d33123732b2e9c027081d87c6f48a869ac4ac"
        );
        assert_eq!(
            custom_base64(&encoded, srun_alphabet),
            "PL0d/wOzclRaeKDZcs1yyFdvP9rPoVm99BxsuHHQKg2g7zHeC0pe7NR4tQ4QKokQfR4DSQ53lvPNxh+d4qpmsDoRzRhhz7EV5DtzPkMxbKqLRvSnT4WtX/OO68v="
        );
    }
}
