//! Thin wrappers around `serde_json` for the flat JSONP objects Srun returns.
//!
//! Srun wraps its JSON in a `callback(...)` JSONP envelope. We strip that
//! wrapper, then pull individual string / integer fields out of the parsed
//! object. Using `serde_json` (rather than a hand-rolled extractor) means
//! `\uXXXX` escapes, key collisions, and odd value contents are handled
//! correctly. Responses are a few hundred bytes, so re-parsing per lookup is
//! cheap and keeps the public API key-oriented.

use serde_json::Value;

/// Strip a JSONP envelope: `callbackName({...})` -> `{...}`.
///
/// Returns the inner payload between the first `(` and the last `)`. If there
/// is no wrapper (already-bare JSON), the input is returned trimmed.
pub fn strip_jsonp(text: &str) -> &str {
    let start = text.find('(');
    let end = text.rfind(')');
    match (start, end) {
        (Some(s), Some(e)) if e > s => text[s + 1..e].trim(),
        _ => text.trim(),
    }
}

/// Parse the payload into an object map, returning `None` on any parse error
/// or if the top-level value is not an object.
fn parse_object(json: &str) -> Option<serde_json::Map<String, Value>> {
    match serde_json::from_str::<Value>(json) {
        Ok(Value::Object(map)) => Some(map),
        _ => None,
    }
}

/// Extract a string field value by key from a flat JSON object.
///
/// Returns `None` if the payload does not parse, the key is absent, or its
/// value is not a string.
pub fn get_str(json: &str, key: &str) -> Option<String> {
    let map = parse_object(json)?;
    map.get(key)?.as_str().map(|s| s.to_string())
}

/// Extract an integer field value by key. Handles both raw numbers
/// (`"sum_bytes":123`) and numeric strings (`"sum_bytes":"123"`).
pub fn get_i64(json: &str, key: &str) -> Option<i64> {
    let map = parse_object(json)?;
    let value = map.get(key)?;
    match value {
        // Raw JSON number.
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
        // Numeric string, e.g. "7890".
        Value::String(s) => s.trim().parse::<i64>().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_jsonp_wrapper() {
        assert_eq!(strip_jsonp("cb123({\"a\":1})"), "{\"a\":1}");
        assert_eq!(strip_jsonp("{\"a\":1}"), "{\"a\":1}");
    }

    #[test]
    fn extracts_strings() {
        let j = r#"{"error":"ok","challenge":"abc123","client_ip":"10.0.0.5"}"#;
        assert_eq!(get_str(j, "error").as_deref(), Some("ok"));
        assert_eq!(get_str(j, "challenge").as_deref(), Some("abc123"));
        assert_eq!(get_str(j, "client_ip").as_deref(), Some("10.0.0.5"));
        assert_eq!(get_str(j, "missing"), None);
    }

    #[test]
    fn key_match_is_exact() {
        // "error" must not accidentally match inside "error_msg".
        let j = r#"{"error_msg":"bad","error":"E001"}"#;
        assert_eq!(get_str(j, "error").as_deref(), Some("E001"));
        assert_eq!(get_str(j, "error_msg").as_deref(), Some("bad"));
    }

    #[test]
    fn extracts_integers_raw_and_quoted() {
        let j = r#"{"sum_bytes":123456,"sum_seconds":"7890"}"#;
        assert_eq!(get_i64(j, "sum_bytes"), Some(123456));
        assert_eq!(get_i64(j, "sum_seconds"), Some(7890));
    }

    // --- Regression tests for the bugs the hand-rolled parser had ---

    #[test]
    fn key_in_a_value_does_not_confuse_lookup() {
        // The old find()-based extractor could match "error" inside a *value*
        // and then fail to read the real "error" key.
        let j = r#"{"note":"see error below","error":"real"}"#;
        assert_eq!(get_str(j, "error").as_deref(), Some("real"));
    }

    #[test]
    fn unicode_escape_is_decoded() {
        // "\u4e2d\u6587" is the Chinese word for "Chinese". The old parser
        // emitted a garbled "u4e2d..." instead of decoding it.
        let j = r#"{"user_name":"\u4e2d\u6587"}"#;
        assert_eq!(get_str(j, "user_name").as_deref(), Some("中文"));
    }

    #[test]
    fn raw_multibyte_utf8_is_preserved() {
        let j = r#"{"user_name":"张三"}"#;
        assert_eq!(get_str(j, "user_name").as_deref(), Some("张三"));
    }

    #[test]
    fn malformed_json_returns_none_not_panic() {
        assert_eq!(get_str("{not valid json", "error"), None);
        assert_eq!(get_i64("{not valid json", "sum_bytes"), None);
    }

    #[test]
    fn negative_integers_parse() {
        let j = r#"{"balance":-42}"#;
        assert_eq!(get_i64(j, "balance"), Some(-42));
    }
}
