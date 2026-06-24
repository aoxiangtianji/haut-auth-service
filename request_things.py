import base64
import hashlib
import http.cookiejar
import json
import platform
import re
import subprocess
import urllib.request
from urllib.parse import urlencode, urljoin

from utils import JQueryUtil, gen_chksum, gen_info, log_info, password_encrypt


def is_account_in_use(username, password, my_ip, portal_ip="172.16.154.130") -> bool:
    """
    Check if the account is occupied by another device via self-service system.
    Returns False if only this device (my_ip) is online.
    """
    sso_url = f"http://{portal_ip}:8800/site/sso"
    pwd_md5 = hashlib.md5(password.encode()).hexdigest()
    auth_str = f"{username}:{pwd_md5}"
    auth_b64 = base64.b64encode(auth_str.encode()).decode()

    try:
        # Use CookieJar to handle sessions/redirects properly
        cj = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

        url = f"{sso_url}?{urlencode({'data': auth_b64})}"
        # Some portals might require a User-Agent
        opener.addheaders = [
            (
                "User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            )
        ]

        with opener.open(url, timeout=10) as resp:
            html = resp.read().decode("utf-8")

        # Extract all IPs from HTML
        ip_matches = re.findall(r"\d+\.\d+\.\d+\.\d+", html)

        # Filter out server IP and duplicates
        online_ips = set([ip for ip in ip_matches if ip != portal_ip])

        if not online_ips:
            return False

        # Check for non-local IPs
        other_ips = [ip for ip in online_ips if ip != my_ip]

        if other_ips:
            # We found other IPs online
            log_info(f"Detected other devices online: {list(set(other_ips))}")
            return True
        else:
            return False
    except Exception:
        # Fail-safe: assume not occupied if system is down
        return False


def get_user_info(jquery_version: str, url_head: str) -> dict | None:
    try:
        new_counter = JQueryUtil(jquery_version)
        callback_name = new_counter.get_callback_name()
        query = urlencode({"callback": callback_name, "_": new_counter.get_timestamp()})
        url = urljoin(url_head, f"rad_user_info?{query}")

        with urllib.request.urlopen(url, timeout=10) as resp:
            text = resp.read().decode("utf-8")

        try:
            return json.loads(text[len(callback_name) + 1 : -1])
        except json.JSONDecodeError:
            if text == "not_online_error":
                return None
            else:
                return None
    except Exception:
        return None


def send_login(
    url_head: str,
    jquery_callback: str,
    timestamp: int,
    token: str,
    username: str,
    password: str,
    local_ip: str,
    ac_id: str,
) -> dict:
    hmd5_password = password_encrypt(password, token)
    info = gen_info(token, username, password, local_ip, ac_id)
    login_data = {
        "callback": jquery_callback,
        "action": "login",
        "username": username,
        "password": "{MD5}" + hmd5_password,
        "ac_id": ac_id,
        "ip": local_ip,
        "chksum": gen_chksum(
            token, username, hmd5_password, ac_id, local_ip, "200", "1", info
        ),
        "info": info,
        "n": "200",
        "type": "1",
        "os": "Windows 10",
        "name": "Windows",
        "double_stack": 0,
        "_": timestamp,
    }
    url = urljoin(url_head, f"srun_portal?{urlencode(login_data)}")
    with urllib.request.urlopen(url, timeout=10) as resp:
        text = resp.read().decode("utf-8")
    return json.loads(text[len(jquery_callback) + 1 : -1])


def get_challenge(
    url_head: str, jquery_callback: str, timestamp: int, username: str
) -> dict:
    challenge_data = {
        "callback": jquery_callback,
        "username": username,
        "_": timestamp,
    }
    url = urljoin(url_head, f"get_challenge?{urlencode(challenge_data)}")
    with urllib.request.urlopen(url, timeout=10) as resp:
        text = resp.read().decode("utf-8")
    return json.loads(text[len(jquery_callback) + 1 : -1])


def test_connection():
    """
    Test connectivity using ping (ICMP) to a reliable IP.
    This avoids DNS/TCP redirection issues and allows for fixed routing.
    Target: 223.6.6.6 (AliDNS - Stable and responsive to ping in China)
    """
    target = "223.6.6.6"
    is_windows = platform.system().lower() == "windows"

    # -c 1 (Linux/OpenWrt) / -n 1 (Windows)
    # -W 2 (Linux/OpenWrt timeout in sec) / -w 2000 (Windows timeout in ms)
    if is_windows:
        command = ["ping", "-n", "1", "-w", "2000", target]
    else:
        # Standard OpenWrt/Linux ping
        command = ["ping", "-c", "1", "-W", "2", target]

    try:
        # We use subprocess.call to get return code (0 = success)
        # Redirect output to DEVNULL to keep logs clean
        return (
            subprocess.call(
                command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            == 0
        )
    except Exception:
        return False
