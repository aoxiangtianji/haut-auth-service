# haut-auth-service

An automation service for HAUT (Henan University of Technology) campus network authentication, packaged for OpenWrt. Originally a Python script, now rewritten in Rust for a small memory footprint.

## Key Features

- **Automated Authentication**: Implements the Srun protocol to handle campus network login automatically.
- **Low Memory Footprint**: Rewritten in Rust with no Python interpreter and no TLS stack (the portal is plaintext HTTP). The audited RustCrypto crates provide the hashing/MAC primitives; only Srun's reversible `xEncode` obfuscation is implemented in-tree.
- **No fork overhead**: Connectivity is checked with a native TCP probe instead of forking the `ping` binary, avoiding the fork-time memory spike.
- **Service Integration**: Fully integrated with OpenWrt's `procd` for automatic startup, crash recovery, and process management.
- **Native Configuration**: Uses OpenWrt's standard UCI configuration (`/etc/config/haut-auth`) for persistent settings.

## Configuration

Settings live in `/etc/config/haut-auth`:

```
config haut-auth 'main'
	option enabled '0'
	option username ''
	option password ''
	option auth_ip 'http://172.16.154.130/'
	option ping_target '223.5.5.5'
```

| Option | Description | Default |
|--------|-------------|---------|
| `enabled` | Set to `1` to enable the service. | `0` |
| `username` | Campus network account username. | (empty) |
| `password` | Campus network account password. | (empty) |
| `auth_ip` | Base URL of the Srun authentication portal. | `http://172.16.154.130/` |
| `ping_target` | Host probed (TCP port 53) to detect connectivity. | `223.5.5.5` |

After editing, restart the service:

```sh
/etc/init.d/haut-auth restart
```

## How it works

Every 30 seconds the daemon opens a short-lived TCP connection to `ping_target:53`. If that fails, it runs the Srun handshake:

1. **get_challenge** — fetch a one-time token and the client IP.
2. **occupancy check** — query the self-service SSO portal to skip login if the account is already in use by another device.
3. **srun_portal login** — submit the encrypted credentials (HMAC-MD5 password, `xEncode`+custom-Base64 `info` blob, SHA-1 checksum).

After a successful login it periodically reports the logged-in user's traffic and session time.

## Building

The package is built from the in-tree Cargo project (`Cargo.toml` + `src/`) using OpenWrt's Rust toolchain. From an OpenWrt SDK with the `rust` feed available:

```sh
make package/haut-auth/compile
```

For local development outside the SDK:

```sh
cd haut-auth
cargo test          # run the unit tests
cargo build --release
```

## License

MIT License
