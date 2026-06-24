import os
from time import sleep, time
from urllib.parse import urljoin

try:
    from colorama import Fore, init

    init(autoreset=True)
except ImportError:

    class Dummy:
        def __getattr__(self, name):
            return ""

    Fore = Dummy()

    def init(*args, **kwargs):
        pass


from request_things import (
    get_challenge,
    get_user_info,
    is_account_in_use,
    send_login,
    test_connection,
)
from utils import (
    JQueryUtil,
    log_custom,
    log_debug,
    log_error,
    log_info,
    log_warning,
    show_data_usage,
    show_time_formatted,
    username_encrypt,
)

# Configuration from environment variables
USERNAME = os.getenv("HAUT_USERNAME")
PASSWORD = os.getenv("HAUT_PASSWORD")
BASE_URL = os.getenv("HAUT_AUTH_IP") or "http://172.16.154.130/"
JQUERY_VERSION = "1.12.4"

if not USERNAME or not PASSWORD:
    log_error("HAUT_USERNAME and HAUT_PASSWORD environment variables are required.")
    exit(1)

# HAUT requires username encryption as per srun3k-new.html
ENCRYPTED_USERNAME = username_encrypt(USERNAME)
URL_HEAD = urljoin(BASE_URL, "cgi-bin/")


def authenticate():
    global ENCRYPTED_USERNAME, PASSWORD, URL_HEAD, JQUERY_VERSION
    ac_id = "1"

    while True:
        jQuery_counter = JQueryUtil(JQUERY_VERSION)
        callback = jQuery_counter.get_callback_name()
        timestamp = jQuery_counter.get_timestamp()

        # Step 1: Get Challenge
        try:
            # Clean up display name (remove \r\n) to prevent multi-line logs
            display_name = ENCRYPTED_USERNAME.replace("\r", "").replace("\n", " ")
            log_debug(f"Fetching challenge for {display_name}...")
            cl_obj = get_challenge(URL_HEAD, callback, timestamp, ENCRYPTED_USERNAME)
            if cl_obj["error"] != "ok":
                log_error(
                    f"Challenge failed: {cl_obj.get('error')}: {cl_obj.get('error_msg')}"
                )
                sleep(10)
                continue
            token = cl_obj["challenge"]
            local_ip = cl_obj["client_ip"]
            log_debug(f"Got token: {token}, IP: {local_ip}")
        except Exception as ex:
            log_error(f"Get challenge exception: {str(ex)}")
            sleep(10)
            continue

        # Step 1.5: Check if account is in use by another device
        try:
            # PASSWORD checked at startup
            if is_account_in_use(USERNAME, str(PASSWORD), local_ip):
                log_warning(
                    f"Account is currently used by another device (not {local_ip}). Skipping login..."
                )
                # Return False to tell main loop that we didn't authenticate but should try again later
                return False
        except Exception as ex:
            log_error(f"Account occupancy check failed: {str(ex)}")
            # If check fails, we proceed anyway to be safe

        # Step 2: Login
        try:
            log_info(f"Attempting login with AC_ID={ac_id}...")
            # PASSWORD has been checked at startup, but we cast to str for type safety
            current_password = str(PASSWORD)
            login_obj = send_login(
                URL_HEAD,
                callback,
                timestamp,
                token,
                ENCRYPTED_USERNAME,
                current_password,
                local_ip,
                ac_id,
            )

            if login_obj["error"] == "ok":
                log_custom(Fore.GREEN, "Login successful!")
                return True
            elif login_obj["error"] == "ip_already_online_error":
                # Special return value to signal 'already online' state to main loop
                return "ALREADY_ONLINE"
            else:
                error_msg = login_obj.get(
                    "error_msg", login_obj.get("error", "Unknown error")
                )
                log_error(f"Login failed: {error_msg}")

                # Retry with AC_ID=2 if AC_ID=1 fails, as seen in srun3k-new.html
                if ac_id == "1":
                    log_warning("Retrying with AC_ID=2...")
                    ac_id = "2"
                    continue

                log_warning("Waiting 10s before retry...")
                sleep(10)
        except Exception as ex:
            log_error(f"Login exception: {str(ex)}")
            sleep(10)


def main():
    last_user_info_time = 0
    while True:
        if not test_connection():
            log_warning("Not connected to internet. Starting authentication...")
            auth_result = authenticate()

            # Show user info if fresh login OR if it's been an hour since last info log
            current_time = time()
            should_show_info = (auth_result is True) or (
                auth_result == "ALREADY_ONLINE"
                and (current_time - last_user_info_time > 3600)
            )

            if should_show_info:
                if auth_result == "ALREADY_ONLINE":
                    log_info("IP is already online. Fetching status...")

                log_info("Waiting 2 seconds to fetch user info...")
                sleep(2)
                user_data = get_user_info(JQUERY_VERSION, URL_HEAD)
                if user_data:
                    log_info(
                        f"User: {user_data['user_name']} | Usage: {show_data_usage(user_data['sum_bytes'])} | Time: {show_time_formatted(user_data['sum_seconds'])}"
                    )
                    last_user_info_time = current_time
                else:
                    log_warning("Could not fetch user info (not online?)")
        else:
            log_debug("Connection alive.")

        sleep(30)


if __name__ == "__main__":
    main()
