# haut-auth

HAUT (Henan University of Technology) campus-network auto-authentication daemon, written in Rust.

A lightweight background service that monitors network connectivity and automatically performs Srun portal login when offline.

## Features

- Pure Rust, minimal dependencies — no TLS stack, no Python runtime needed
- Native TCP connectivity probe (no `ping` fork)
- Optional check for whether the account is already online on another device
- Runs on any Linux system; also packaged for OpenWrt (see `_openwrt_feed/`)

## Quick Start

```sh
cargo build --release

export HAUT_USERNAME=your_username
export HAUT_PASSWORD=your_password
./target/release/haut-auth
```

## Configuration

All settings are passed via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `HAUT_USERNAME` | *(required)* | Campus-network account username |
| `HAUT_PASSWORD` | *(required)* | Campus-network account password |
| `HAUT_AUTH_IP` | `http://172.16.154.130/` | Srun authentication portal URL |
| `HAUT_PING_TARGET` | `223.5.5.5` | Host for connectivity checks (TCP port 53) |
| `HAUT_CHECK_OTHER_DEVICE_ONLINE` | `1` | Set to `0` to skip other-device online check |

`HAUT_CHECK_OTHER_DEVICE_ONLINE` accepts `1`/`true`/`yes`/`on` or `0`/`false`/`no`/`off`.

## How It Works

Every 30 seconds, the daemon probes `HAUT_PING_TARGET:53` via TCP.

If offline, it runs the Srun authentication flow:

1. Get challenge token and client IP
2. Optionally check whether the account is online on another device
3. Submit login request
4. Print user traffic/session info after login

## Platform-Specific Packaging

- **OpenWrt**: See `_openwrt_feed/` for the Makefile, UCI config, and procd init script. These will be moved to a separate OpenWrt feed repository.
- **systemd (generic Linux)**: A systemd service unit and environment file will be provided in `contrib/systemd/`.

## Building

```sh
cargo build --release
```

The binary is self-contained — copy it to any Linux machine and run it with the required environment variables.

## License

MIT License
