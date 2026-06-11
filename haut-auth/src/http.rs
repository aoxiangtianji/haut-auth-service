//! Minimal plaintext HTTP/1.1 client (no TLS) built on std::net.
//!
//! Srun's portal is plain `http://` on port 80, so we deliberately avoid
//! pulling in a TLS stack. Supports GET, Content-Length and chunked transfer
//! decoding, redirect following, and a tiny cookie jar (needed by the
//! self-service SSO check, which the original Python drove via CookieJar).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

const MAX_REDIRECTS: u32 = 5;

#[derive(Debug)]
pub enum HttpError {
    Url(String),
    Io(std::io::Error),
    TooManyRedirects,
    BadResponse(String),
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::Url(s) => write!(f, "invalid url: {s}"),
            HttpError::Io(e) => write!(f, "io error: {e}"),
            HttpError::TooManyRedirects => write!(f, "too many redirects"),
            HttpError::BadResponse(s) => write!(f, "bad response: {s}"),
        }
    }
}

impl From<std::io::Error> for HttpError {
    fn from(e: std::io::Error) -> Self {
        HttpError::Io(e)
    }
}

struct Url {
    host: String,
    port: u16,
    path: String,
}

fn parse_url(url: &str) -> Result<Url, HttpError> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| HttpError::Url(format!("only http:// supported: {url}")))?;

    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };

    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => {
            let port = p
                .parse::<u16>()
                .map_err(|_| HttpError::Url(format!("bad port: {p}")))?;
            (h.to_string(), port)
        }
        None => (authority.to_string(), 80),
    };

    if host.is_empty() {
        return Err(HttpError::Url(format!("empty host: {url}")));
    }

    Ok(Url {
        host,
        port,
        path: path.to_string(),
    })
}

/// A simple in-memory cookie jar: name -> value. Scope/expiry are ignored,
/// which is sufficient for the short-lived single-host SSO exchange.
type CookieJar = HashMap<String, String>;

fn merge_set_cookie(jar: &mut CookieJar, header_value: &str) {
    // Take only the "name=value" part before the first ';'.
    let pair = header_value.split(';').next().unwrap_or("").trim();
    if let Some((name, value)) = pair.split_once('=') {
        jar.insert(name.trim().to_string(), value.trim().to_string());
    }
}

fn cookie_header(jar: &CookieJar) -> Option<String> {
    if jar.is_empty() {
        return None;
    }
    let joined = jar
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ");
    Some(joined)
}

struct RawResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn header<'a>(resp: &'a RawResponse, name: &str) -> Option<&'a str> {
    resp.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn request_once(url: &Url, jar: &CookieJar, timeout: Duration) -> Result<RawResponse, HttpError> {
    let stream = TcpStream::connect((url.host.as_str(), url.port))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let mut stream = stream;

    let mut req = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: {}\r\n\
         Accept: */*\r\n\
         Connection: close\r\n",
        url.path, url.host, USER_AGENT
    );
    if let Some(cookie) = cookie_header(jar) {
        req.push_str(&format!("Cookie: {cookie}\r\n"));
    }
    req.push_str("\r\n");

    stream.write_all(req.as_bytes())?;
    stream.flush()?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;

    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> Result<RawResponse, HttpError> {
    // Split headers/body on the first CRLFCRLF.
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| HttpError::BadResponse("no header terminator".into()))?;

    let head = &raw[..split];
    let body_start = split + 4;
    let head_str = String::from_utf8_lossy(head);
    let mut lines = head_str.split("\r\n");

    let status_line = lines
        .next()
        .ok_or_else(|| HttpError::BadResponse("empty status line".into()))?;
    // e.g. "HTTP/1.1 302 Found"
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| HttpError::BadResponse(format!("bad status line: {status_line}")))?;

    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    let raw_body = raw[body_start..].to_vec();

    let is_chunked = headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("Transfer-Encoding") && v.to_lowercase().contains("chunked")
    });

    let body = if is_chunked {
        decode_chunked(&raw_body)?
    } else {
        raw_body
    };

    Ok(RawResponse {
        status,
        headers,
        body,
    })
}

fn decode_chunked(data: &[u8]) -> Result<Vec<u8>, HttpError> {
    let mut out = Vec::new();
    let mut pos = 0;

    loop {
        if pos >= data.len() {
            return Err(HttpError::BadResponse("chunked body truncated".into()));
        }

        // Find end of chunk-size line.
        let line_end = data[pos..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| HttpError::BadResponse("chunk size line not terminated".into()))?;
        let size_line = &data[pos..pos + line_end];
        // Chunk size may carry extensions after ';'.
        let size_str = String::from_utf8_lossy(size_line);
        let size_hex = size_str.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| HttpError::BadResponse(format!("bad chunk size: {size_hex}")))?;

        pos += line_end + 2; // skip size line + CRLF

        if size == 0 {
            break;
        }

        // checked_add:防止 32 位 usize 下 chunk size 被破坏导致溢出绕过边界检查。
        let end = pos
            .checked_add(size)
            .filter(|&e| e <= data.len())
            .ok_or_else(|| HttpError::BadResponse("chunk longer than body".into()))?;

        out.extend_from_slice(&data[pos..end]);

        // 跳过数据 + 尾部 CRLF。用 saturating_add 钳住:即便末尾缺 CRLF,
        // 也只是让下一轮的守卫干净报 truncated,而不会 panic。
        pos = end.saturating_add(2);
    }

    Ok(out)
}

/// Perform a GET, following redirects and accumulating cookies. Returns the
/// final response body decoded as a UTF-8 (lossy) string.
pub fn get(url: &str, timeout: Duration) -> Result<String, HttpError> {
    let mut current = url.to_string();
    let mut jar: CookieJar = HashMap::new();

    for _ in 0..MAX_REDIRECTS {
        let parsed = parse_url(&current)?;
        let resp = request_once(&parsed, &jar, timeout)?;

        for (k, v) in &resp.headers {
            if k.eq_ignore_ascii_case("Set-Cookie") {
                merge_set_cookie(&mut jar, v);
            }
        }

        if (300..400).contains(&resp.status) {
            let location = header(&resp, "Location")
                .ok_or_else(|| HttpError::BadResponse("redirect without Location".into()))?;
            current = resolve_redirect(&parsed, location);
            continue;
        }

        return Ok(String::from_utf8_lossy(&resp.body).into_owned());
    }

    Err(HttpError::TooManyRedirects)
}

fn resolve_redirect(base: &Url, location: &str) -> String {
    if location.starts_with("http://") || location.starts_with("https://") {
        location.to_string()
    } else if let Some(rest) = location.strip_prefix('/') {
        format!("http://{}:{}/{}", base.host, base.port, rest)
    } else {
        format!("http://{}:{}/{}", base.host, base.port, location)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_chunked_well_formed() {
        assert_eq!(
            decode_chunked(b"5\r\nhello\r\n0\r\n\r\n").unwrap(),
            b"hello"
        );
    }

    #[test]
    fn decode_chunked_truncated_returns_err_not_panic() {
        // 服务器发完 chunk 数据就断开,缺尾部 CRLF。必须报错,不能 panic。
        assert!(decode_chunked(b"5\r\nhello").is_err());
    }

    #[test]
    fn decode_chunked_oversized_chunk_is_err() {
        // chunk 声明的字节数超过实际 body。
        assert!(decode_chunked(b"ff\r\nhello\r\n0\r\n\r\n").is_err());
    }
}
