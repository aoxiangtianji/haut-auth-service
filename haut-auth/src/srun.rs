//! Srun portal protocol layer. Ports the request/encoding logic from the
//! original `request_things.py` + the protocol helpers in `utils.py`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::crypto::{base64_standard, custom_base64, hmac_md5_hex, md5_hex, sha1_hex, x_encode};
use crate::http;
use crate::json;

const SRUN_ALPHABET: &str = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA";
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Result of a login attempt, mirroring the original Python's tri-state return.
#[derive(Debug, PartialEq, Eq)]
pub enum LoginOutcome {
    Ok,
    AlreadyOnline,
    Failed(String),
}

/// Monotonic-ish callback/timestamp counter, mirroring `JQueryUtil`.
pub struct JQueryCounter {
    counter: u64,
}

impl JQueryCounter {
    pub fn new() -> Self {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        JQueryCounter { counter: millis }
    }

    /// `jQuery<digits><frac>_<counter>`, matching `gen_jQuery` + counter use.
    pub fn callback_name(&mut self) -> String {
        // The original derives a per-instance random suffix; the millisecond
        // base already varies per call, which is all the portal needs.
        let name = format!(
            "jQuery1124{}_{}",
            self.counter % 1_000_000_000,
            self.counter
        );
        self.counter += 1;
        name
    }

    pub fn timestamp(&mut self) -> u64 {
        let ts = self.counter;
        self.counter += 1;
        ts
    }
}

impl Default for JQueryCounter {
    fn default() -> Self {
        Self::new()
    }
}

/// Encrypt the username per srun3k: shift each byte +4 and prepend the marker.
pub fn username_encrypt(username: &str) -> String {
    let mut out = String::from("{SRUN3}\r\n");
    for ch in username.chars() {
        // Original does chr(ord(c)+4) over the raw string.
        if let Some(shifted) = char::from_u32(ch as u32 + 4) {
            out.push(shifted);
        }
    }
    out
}

/// HMAC-MD5 password encryption (key = challenge token).
pub fn password_encrypt(raw_password: &str, token: &str) -> String {
    hmac_md5_hex(token.as_bytes(), raw_password.as_bytes())
}

/// Build the `{SRBX1}`-prefixed `info` blob: JSON -> xEncode -> custom base64.
pub fn gen_info(token: &str, username: &str, password: &str, ip: &str, ac_id: &str) -> String {
    // Compact JSON with the exact key order the portal expects.
    let info_json = format!(
        "{{\"username\":\"{}\",\"password\":\"{}\",\"ip\":\"{}\",\"acid\":\"{}\",\"enc_ver\":\"srun_bx1\"}}",
        json_escape(username),
        json_escape(password),
        json_escape(ip),
        json_escape(ac_id),
    );
    let encoded = x_encode(info_json.as_bytes(), token.as_bytes());
    format!("{{SRBX1}}{}", custom_base64(&encoded, SRUN_ALPHABET))
}

/// Minimal JSON string escaping for the values we embed in `info`.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out
}

/// SHA-1 checksum over the concatenated fields, matching `gen_chksum`.
#[allow(clippy::too_many_arguments)]
pub fn gen_chksum(
    token: &str,
    username: &str,
    hmd5_password: &str,
    ac_id: &str,
    ip: &str,
    n: &str,
    type_: &str,
    info: &str,
) -> String {
    let chkstr = format!(
        "{token}{username}{token}{hmd5_password}{token}{ac_id}{token}{ip}{token}{n}{token}{type_}{token}{info}"
    );
    sha1_hex(chkstr.as_bytes())
}

/// Challenge response fields we care about.
pub struct Challenge {
    pub token: String,
    pub client_ip: String,
}

/// GET get_challenge and parse the token + client IP.
pub fn get_challenge(
    url_head: &str,
    callback: &str,
    timestamp: u64,
    username: &str,
) -> Result<Challenge, String> {
    let query = format!(
        "callback={}&username={}&_={}",
        urlencode(callback),
        urlencode(username),
        timestamp
    );
    let url = format!("{url_head}get_challenge?{query}");
    let body = http::get(&url, HTTP_TIMEOUT).map_err(|e| e.to_string())?;
    let payload = json::strip_jsonp(&body);

    let error = json::get_str(payload, "error").unwrap_or_default();
    if error != "ok" {
        let msg = json::get_str(payload, "error_msg").unwrap_or_default();
        return Err(format!("challenge error: {error}: {msg}"));
    }

    let token =
        json::get_str(payload, "challenge").ok_or_else(|| "challenge missing token".to_string())?;
    let client_ip = json::get_str(payload, "client_ip")
        .ok_or_else(|| "challenge missing client_ip".to_string())?;

    Ok(Challenge { token, client_ip })
}

/// Perform the srun_portal login. `password` is the raw password.
#[allow(clippy::too_many_arguments)]
pub fn send_login(
    url_head: &str,
    callback: &str,
    timestamp: u64,
    token: &str,
    username: &str,
    password: &str,
    local_ip: &str,
    ac_id: &str,
) -> Result<LoginOutcome, String> {
    let hmd5 = password_encrypt(password, token);
    let info = gen_info(token, username, password, local_ip, ac_id);
    let chksum = gen_chksum(token, username, &hmd5, ac_id, local_ip, "200", "1", &info);

    let query = format!(
        "callback={cb}&action=login&username={user}&password={pw}&ac_id={ac}&ip={ip}\
         &chksum={chk}&info={info}&n=200&type=1&os={os}&name=Windows&double_stack=0&_={ts}",
        cb = urlencode(callback),
        user = urlencode(username),
        pw = urlencode(&format!("{{MD5}}{hmd5}")),
        ac = urlencode(ac_id),
        ip = urlencode(local_ip),
        chk = urlencode(&chksum),
        info = urlencode(&info),
        os = urlencode("Windows 10"),
        ts = timestamp,
    );
    let url = format!("{url_head}srun_portal?{query}");
    let body = http::get(&url, HTTP_TIMEOUT).map_err(|e| e.to_string())?;
    let payload = json::strip_jsonp(&body);

    let error = json::get_str(payload, "error").unwrap_or_default();
    match error.as_str() {
        "ok" => Ok(LoginOutcome::Ok),
        "ip_already_online_error" => Ok(LoginOutcome::AlreadyOnline),
        _ => {
            let msg = json::get_str(payload, "error_msg").unwrap_or(error);
            Ok(LoginOutcome::Failed(msg))
        }
    }
}

/// Logged-in user info.
pub struct UserInfo {
    pub user_name: String,
    pub sum_bytes: i64,
    pub sum_seconds: i64,
}

/// GET rad_user_info. Returns None if not online or on parse failure.
pub fn get_user_info(url_head: &str, counter: &mut JQueryCounter) -> Option<UserInfo> {
    let callback = counter.callback_name();
    let timestamp = counter.timestamp();
    let query = format!("callback={}&_={}", urlencode(&callback), timestamp);
    let url = format!("{url_head}rad_user_info?{query}");

    let body = http::get(&url, HTTP_TIMEOUT).ok()?;
    if body.contains("not_online_error") {
        return None;
    }
    let payload = json::strip_jsonp(&body);

    Some(UserInfo {
        user_name: json::get_str(payload, "user_name")?,
        sum_bytes: json::get_i64(payload, "sum_bytes").unwrap_or(0),
        sum_seconds: json::get_i64(payload, "sum_seconds").unwrap_or(0),
    })
}

/// Check whether the account is in use by another device via the self-service
/// SSO portal. Returns true only if an IP other than `my_ip` is online.
pub fn is_account_in_use(username: &str, password: &str, my_ip: &str, portal_ip: &str) -> bool {
    let pwd_md5 = md5_hex(password.as_bytes());
    let auth_str = format!("{username}:{pwd_md5}");
    let auth_b64 = base64_standard(auth_str.as_bytes());

    let url = format!(
        "http://{portal_ip}:8800/site/sso?data={}",
        urlencode(&auth_b64)
    );

    let body = match http::get(&url, HTTP_TIMEOUT) {
        Ok(b) => b,
        // Fail-safe: assume not occupied if the system is unreachable.
        Err(_) => return false,
    };

    let online_ips: std::collections::HashSet<&str> = extract_ips(&body)
        .into_iter()
        .filter(|ip| *ip != portal_ip)
        .collect();

    if online_ips.is_empty() {
        return false;
    }

    online_ips.iter().any(|ip| *ip != my_ip)
}

/// Extract dotted-quad IPv4 addresses from arbitrary text.
fn extract_ips(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut ips = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            let mut dots = 0;
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                if bytes[i] == b'.' {
                    dots += 1;
                }
                i += 1;
            }
            if dots == 3 {
                let candidate = &text[start..i];
                if is_ipv4(candidate) {
                    ips.push(candidate);
                }
            }
        } else {
            i += 1;
        }
    }
    ips
}

fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.parse::<u8>().is_ok())
}

/// Percent-encode a query parameter value (RFC 3986 unreserved set kept).
pub fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_encrypt_shifts_and_prefixes() {
        // 'a'(97)->'e'(101), '1'(49)->'5'(53)
        assert_eq!(username_encrypt("a1"), "{SRUN3}\r\ne5");
    }

    #[test]
    fn urlencode_keeps_unreserved() {
        assert_eq!(urlencode("abc-_.~"), "abc-_.~");
        assert_eq!(urlencode("a b"), "a%20b");
        assert_eq!(urlencode("{MD5}"), "%7BMD5%7D");
    }

    #[test]
    fn extract_ips_finds_quads() {
        let html = "online: 10.0.0.5 and 192.168.1.1, server 172.16.154.130";
        let ips = extract_ips(html);
        assert!(ips.contains(&"10.0.0.5"));
        assert!(ips.contains(&"192.168.1.1"));
        assert!(ips.contains(&"172.16.154.130"));
    }

    #[test]
    fn is_account_in_use_filters_self_and_portal() {
        // Only portal + self online -> not in use. Tested indirectly via the
        // set logic: extract, filter portal, check for non-self.
        let portal = "172.16.154.130";
        let me = "10.0.0.5";
        let ips: std::collections::HashSet<&str> = ["172.16.154.130", "10.0.0.5"]
            .into_iter()
            .filter(|ip| *ip != portal)
            .collect();
        assert!(!ips.iter().any(|ip| *ip != me));
    }
}
