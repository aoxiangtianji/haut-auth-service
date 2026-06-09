# haut-auth-service

This project provides an automation script for HAUT (Henan University of Technology) campus network authentication. It handles the login process, monitors the connection state using ICMP pings, and displays data usage information.

## Project Overview

- **Purpose:** Automate the HAUT campus network login process with a minimal footprint suitable for OpenWrt.
- **Technology Stack:** Python 3 (Standard Library only for networking), `colorama` for terminal styling.
- **Key Components:**
    - `main.py`: Entry point for the authentication loop and monitoring.
    - `request_things.py`: Handles specific authentication API calls (login, challenge, user info) and connectivity tests using `urllib` and `ping`.
    - `utils.py`: Contains cryptographic utilities (Custom Base64, xEncode, password encryption, username encryption) and formatting helpers.
    - `check_self_service.py`: A standalone script to check if the account is currently occupied via the self-service portal.

## Architecture & Logic

The project replicates the Srun authentication protocol used by the campus network:
1.  **Connectivity Test:** Periodically pings a reliable IP (e.g., `223.5.5.5`) to check internet access.
2.  **Challenge:** Retrieves a token and local IP from the server.
3.  **Encryption:** 
    - **Username:** Encrypted by shifting each character's ASCII code by +4 and prepending `{SRUN3}\r\n`.
    - **Password:** HMAC-MD5 hashed with the challenge token.
    - **Payload:** Encoded using a custom Base64 alphabet and an `xEncode` algorithm (TEA-based).
4.  **Login:** Sends the encrypted payload and credentials to the portal using `urllib.request`.
5.  **AC_ID Handling:** Attempts authentication with `AC_ID="1"`. If it fails, it automatically retries with `AC_ID="2"`.
6.  **Monitoring:** Displays usage data on fresh login and periodically (every hour) if already online.

## Getting Started

### Prerequisites

- Python 3.x
- Dependencies: `pip install colorama` (Optional but recommended for colored logs)
- OpenWrt: `opkg install python3-light python3-openssl python3-codecs`

### Environment Variables

| Variable | Description | Default |
| :--- | :--- | :--- |
| `HAUT_USERNAME` | Your campus network username | Required |
| `HAUT_PASSWORD` | Your campus network password | Required |
| `HAUT_AUTH_IP` | The authentication server IP | `http://172.16.154.130/` |

### Running the Script

```bash
python main.py
```

## Development Conventions

- **Minimal Dependencies:** Use Python standard libraries (`urllib`, `hashlib`, `subprocess`) instead of external ones like `requests` to keep the footprint small for embedded devices.
- **Logging:** Use the logging helpers in `utils.py` for consistent, cross-platform terminal output. All logs are in English to avoid encoding issues.
- **Testing:** Connectivity is verified via ICMP ping to avoid DNS/HTTP redirection complexities.
