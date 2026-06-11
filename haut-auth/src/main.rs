//! HAUT campus-network auth daemon (Rust rewrite).
//!
//! Mirrors the original `main.py` control flow: every 30s check connectivity
//! via a TCP probe; if offline, run the Srun authentication handshake; then
//! periodically report the logged-in user's usage stats.

mod crypto;
mod http;
mod json;
mod srun;

use std::env;
use std::net::{TcpStream, ToSocketAddrs};
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use srun::{
    get_challenge, get_user_info, is_account_in_use, send_login, username_encrypt, JQueryCounter,
    LoginOutcome,
};

const DEFAULT_PING_TARGET: &str = "223.5.5.5";
// Connectivity is probed by opening a TCP connection to this port on the
// target. DNS resolvers (the default 223.5.5.5 is AliDNS) listen on TCP 53,
// so a successful connect proves end-to-end reachability without forking ping.
const PROBE_PORT: u16 = 53;
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const PORTAL_IP: &str = "172.16.154.130";
const LOOP_INTERVAL: Duration = Duration::from_secs(30);
const RETRY_DELAY: Duration = Duration::from_secs(10);
const USER_INFO_INTERVAL: u64 = 3600;

fn main() {
    let username = match env::var("HAUT_USERNAME") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            log_error("HAUT_USERNAME and HAUT_PASSWORD environment variables are required.");
            std::process::exit(1);
        }
    };
    let password = match env::var("HAUT_PASSWORD") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            log_error("HAUT_USERNAME and HAUT_PASSWORD environment variables are required.");
            std::process::exit(1);
        }
    };
    let base_url =
        env::var("HAUT_AUTH_IP").unwrap_or_else(|_| "http://172.16.154.130/".to_string());
    let ping_target = match env::var("HAUT_PING_TARGET") {
        Ok(v) if !v.is_empty() => v,
        _ => DEFAULT_PING_TARGET.to_string(),
    };

    let encrypted_username = username_encrypt(&username);
    let url_head = join_url(&base_url, "cgi-bin/");

    log_info(&format!(
        "haut-auth started. portal={base_url} probe={ping_target}:{PROBE_PORT}"
    ));

    let mut last_user_info_time: u64 = 0;

    loop {
        if test_connection(&ping_target) {
            log_debug("Connection alive.");
        } else {
            log_warning("Not connected to internet. Starting authentication...");
            let outcome = authenticate(&url_head, &encrypted_username, &username, &password);

            let now = now_secs();
            let should_show_info = matches!(outcome, AuthResult::LoggedIn)
                || (matches!(outcome, AuthResult::AlreadyOnline)
                    && now - last_user_info_time > USER_INFO_INTERVAL);

            if should_show_info {
                if matches!(outcome, AuthResult::AlreadyOnline) {
                    log_info("IP is already online. Fetching status...");
                }
                log_info("Waiting 2 seconds to fetch user info...");
                sleep(Duration::from_secs(2));

                let mut counter = JQueryCounter::new();
                match get_user_info(&url_head, &mut counter) {
                    Some(info) => {
                        log_info(&format!(
                            "User: {} | Usage: {} | Time: {}",
                            info.user_name,
                            show_data_usage(info.sum_bytes),
                            show_time_formatted(info.sum_seconds),
                        ));
                        last_user_info_time = now;
                    }
                    None => log_warning("Could not fetch user info (not online?)"),
                }
            }
        }

        sleep(LOOP_INTERVAL);
    }
}

enum AuthResult {
    LoggedIn,
    AlreadyOnline,
    Skipped,
}

/// Run the challenge -> occupancy-check -> login handshake. Retries internally
/// on transient errors, mirroring the Python loop's behaviour.
fn authenticate(
    url_head: &str,
    encrypted_username: &str,
    raw_username: &str,
    password: &str,
) -> AuthResult {
    let mut ac_id = "1".to_string();

    loop {
        let mut counter = JQueryCounter::new();
        let callback = counter.callback_name();
        let timestamp = counter.timestamp();

        // Step 1: challenge
        let challenge = match get_challenge(url_head, &callback, timestamp, encrypted_username) {
            Ok(c) => c,
            Err(e) => {
                log_error(&format!("Get challenge failed: {e}"));
                sleep(RETRY_DELAY);
                continue;
            }
        };
        log_debug(&format!(
            "Got token: {}, IP: {}",
            challenge.token, challenge.client_ip
        ));

        // Step 1.5: occupancy check
        if is_account_in_use(raw_username, password, &challenge.client_ip, PORTAL_IP) {
            log_warning(&format!(
                "Account is currently used by another device (not {}). Skipping login...",
                challenge.client_ip
            ));
            return AuthResult::Skipped;
        }

        // Step 2: login
        log_info(&format!("Attempting login with AC_ID={ac_id}..."));
        match send_login(
            url_head,
            &callback,
            timestamp,
            &challenge.token,
            encrypted_username,
            password,
            &challenge.client_ip,
            &ac_id,
        ) {
            Ok(LoginOutcome::Ok) => {
                log_info("Login successful!");
                return AuthResult::LoggedIn;
            }
            Ok(LoginOutcome::AlreadyOnline) => return AuthResult::AlreadyOnline,
            Ok(LoginOutcome::Failed(msg)) => {
                log_error(&format!("Login failed: {msg}"));
                if ac_id == "1" {
                    log_warning("Retrying with AC_ID=2...");
                    ac_id = "2".to_string();
                    continue;
                }
                log_warning("Waiting 10s before retry...");
                sleep(RETRY_DELAY);
            }
            Err(e) => {
                log_error(&format!("Login exception: {e}"));
                sleep(RETRY_DELAY);
            }
        }
    }
}

/// Test connectivity by opening a TCP connection to the probe target. This
/// replaces forking `ping`, avoiding the fork-time memory spike, and needs no
/// external `ping` binary. A successful connect proves real reachability.
fn test_connection(target: &str) -> bool {
    let addr = (target, PROBE_PORT);
    let socket_addrs = match addr.to_socket_addrs() {
        Ok(addrs) => addrs,
        Err(_) => return false,
    };

    for sa in socket_addrs {
        if TcpStream::connect_timeout(&sa, PROBE_TIMEOUT).is_ok() {
            return true;
        }
    }
    false
}

/// Join a base URL and a path the way `urllib.parse.urljoin` does for our case.
fn join_url(base: &str, path: &str) -> String {
    if base.ends_with('/') {
        format!("{base}{path}")
    } else {
        format!("{base}/{path}")
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Formatting helpers (port of utils.show_data_usage / show_time_formatted)
// ---------------------------------------------------------------------------

fn show_data_usage(data: i64) -> String {
    let d = data as f64;
    if data < 1024 {
        format!("{data} Bytes")
    } else if data < 1024 * 1024 {
        format!("{:.2} KiB", d / 1024.0)
    } else if data < 1024 * 1024 * 1024 {
        format!("{:.2} MiB", d / 1024.0 / 1024.0)
    } else {
        format!("{:.2} GiB", d / 1024.0 / 1024.0 / 1024.0)
    }
}

fn show_time_formatted(seconds: i64) -> String {
    let minutes = seconds / 60;
    let hours = minutes / 60;
    let days = hours / 24;
    if minutes <= 0 {
        format!("{seconds} Seconds")
    } else if hours <= 0 {
        format!("{} Minutes {} Seconds", minutes, seconds % 60)
    } else if days <= 0 {
        format!(
            "{} Hours {} Minutes {} Seconds",
            hours,
            minutes % 60,
            seconds % 60
        )
    } else {
        format!(
            "{} Days {} Hours {} Minutes {} Seconds",
            days,
            hours % 24,
            minutes % 60,
            seconds % 60
        )
    }
}

// ---------------------------------------------------------------------------
// Logging (timestamped, line-buffered to stdout/stderr like procd expects)
// ---------------------------------------------------------------------------

fn timestamp_prefix() -> String {
    // HH:MM:SS in UTC (no chrono dependency). Good enough for service logs.
    let secs = now_secs();
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    let s = secs % 60;
    format!("[{h:02}:{m:02}:{s:02}]")
}

fn log_info(msg: &str) {
    println!("{} {msg}", timestamp_prefix());
}

fn log_warning(msg: &str) {
    println!("{} [WARN] {msg}", timestamp_prefix());
}

fn log_error(msg: &str) {
    eprintln!("{} [ERROR] {msg}", timestamp_prefix());
}

fn log_debug(msg: &str) {
    println!("{} [DEBUG] {msg}", timestamp_prefix());
}
