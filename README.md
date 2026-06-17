# haut-auth-service

HAUT (Henan University of Technology) campus-network auto-authentication service for OpenWrt.

This package runs a small Rust daemon under OpenWrt `procd`. It checks network connectivity periodically and performs Srun login when offline.

## Features

- Rust implementation with low memory usage
- OpenWrt `procd` service integration
- UCI configuration via `/etc/config/haut-auth`
- Native TCP connectivity probe instead of spawning `ping`
- Optional check for whether the account is already online on another device

## Configuration

Settings live in `/etc/config/haut-auth`:

```sh
config haut-auth 'main'
	option enabled '0'
	option username ''
	option password ''
	option auth_ip 'http://172.16.154.130/'
	option ping_target '223.5.5.5'
	option check_other_device_online '1'
```

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `0` | Set to `1` to enable the service. |
| `username` | empty | Campus-network account username. |
| `password` | empty | Campus-network account password. |
| `auth_ip` | `http://172.16.154.130/` | Srun authentication portal URL. |
| `ping_target` | `223.5.5.5` | Host used for connectivity checks on TCP port `53`. |
| `check_other_device_online` | `1` | Set to `0` to skip checking whether the account is already online on another device. |

Example:

```sh
uci set haut-auth.main.enabled='1'
uci set haut-auth.main.username='your_username'
uci set haut-auth.main.password='your_password'
uci set haut-auth.main.check_other_device_online='0'
uci commit haut-auth
/etc/init.d/haut-auth restart
```

## Environment Variables

The init script maps UCI options to environment variables before starting the daemon:

| UCI option | Environment variable |
|------------|----------------------|
| `username` | `HAUT_USERNAME` |
| `password` | `HAUT_PASSWORD` |
| `auth_ip` | `HAUT_AUTH_IP` |
| `ping_target` | `HAUT_PING_TARGET` |
| `check_other_device_online` | `HAUT_CHECK_OTHER_DEVICE_ONLINE` |

`HAUT_CHECK_OTHER_DEVICE_ONLINE` accepts `1/true/yes/on` or `0/false/no/off`. Invalid or missing values default to enabled.

## Service Commands

```sh
/etc/init.d/haut-auth enable
/etc/init.d/haut-auth start
/etc/init.d/haut-auth restart
/etc/init.d/haut-auth stop
```

## How It Works

Every 30 seconds, the daemon probes `ping_target:53`.

If offline, it runs the Srun flow:

1. Get challenge token and client IP
2. Optionally check whether the account is online on another device
3. Submit login request
4. Print user traffic/session info after login

## Building

From an OpenWrt SDK:

```sh
make package/haut-auth/compile
```

For local development:

```sh
cd haut-auth
cargo test
cargo build --release
```

## License

MIT License
