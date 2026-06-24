import base64
import hashlib
import http.cookiejar
import os
import re
import urllib.request
from urllib.parse import urlencode

from utils import log_error, log_info, log_warning


def md5_hash(text: str) -> str:
    return hashlib.md5(text.encode()).hexdigest()


def is_account_in_use():
    """
    Check if the account is already logged in on other devices via self-service portal.
    """
    USERNAME = os.getenv("HAUT_USERNAME")
    PASSWORD = os.getenv("HAUT_PASSWORD")
    PORTAL_IP = "172.16.154.130"
    SSO_URL = f"http://{PORTAL_IP}:8800/site/sso"

    if not USERNAME or not PASSWORD:
        log_error(
            "Please set HAUT_USERNAME and HAUT_PASSWORD environment variables first."
        )
        return None

    log_info("Checking account online status via self-service system...")

    pwd_md5 = md5_hash(PASSWORD)
    auth_str = f"{USERNAME}:{pwd_md5}"
    auth_b64 = base64.b64encode(auth_str.encode()).decode()

    try:
        # Use CookieJar to handle sessions/redirects properly
        cj = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

        url = f"{SSO_URL}?{urlencode({'data': auth_b64})}"
        # Some portals might require a User-Agent
        opener.addheaders = [
            (
                "User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            )
        ]

        with opener.open(url, timeout=10) as response:
            html_content = response.read().decode("utf-8")

        # Decision logic based on markers in the portal HTML
        # "没有找到数据" means "No data found" (no active sessions)
        if "没有找到数据" in html_content:
            log_info("Result: Account [Idle] (No online devices)")
            return False
        # "用户名" (Username) and "IP地址" (IP Address) indicate a table with session data
        elif "用户名" in html_content and "IP地址" in html_content:
            log_warning("Result: Account [Occupied] (Device already online)")

            ip_matches = re.findall(r"\d+\.\d+\.\d+\.\d+", html_content)
            other_ips = [ip for ip in ip_matches if ip != PORTAL_IP]
            if other_ips:
                log_info(f"Detected online IPs: {list(set(other_ips))}")

            return True
        else:
            log_error("Unrecognized page content, please check self_service_debug.html")
            with open("self_service_debug.html", "w", encoding="utf-8") as f:
                f.write(html_content)
            return None

    except Exception as e:
        log_error(f"Failed to connect to self-service system: {e}")
        return None


if __name__ == "__main__":
    in_use = is_account_in_use()
    if in_use is True:
        print("\n>>> Conclusion: Account is occupied, login not recommended.")
    elif in_use is False:
        print("\n>>> Conclusion: Account is idle, safe to login.")
