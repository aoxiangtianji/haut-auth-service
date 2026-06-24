# haut-auth

HAUT (Henan University of Technology) campus-network auto-authentication script, written in Python.

A lightweight background service that monitors network connectivity and automatically performs Srun portal login when offline.

## Features

- Pure Python — minimal dependencies (only `colorama` for colored output, optional)
- Replicates the Srun protocol for campus network authentication
- Periodic connectivity checks via TCP
- Optional check for whether the account is already online on another device

## Quick Start

```sh
export HAUT_USERNAME=your_username
export HAUT_PASSWORD=your_password
python main.py
```

## Configuration

All settings are passed via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `HAUT_USERNAME` | *(required)* | Campus-network account username |
| `HAUT_PASSWORD` | *(required)* | Campus-network account password |
| `HAUT_AUTH_IP` | `http://172.16.154.130/` | Srun authentication portal URL |

## How It Works

Every 30 seconds, the daemon checks connectivity.

If offline, it runs the Srun authentication flow:

1. Get challenge token and client IP
2. Optionally check whether the account is online on another device
3. Submit login request
4. Print user traffic/session info after login

## Platform-Specific Packaging

- **OpenWrt**: See `_openwrt_feed/` for the Makefile, UCI config, and procd init script. These will be moved to a separate OpenWrt feed repository.

## License

MIT License
