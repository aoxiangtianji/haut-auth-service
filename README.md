# haut-auth-service

An automation script for HAUT (Henan University of Technology) campus network authentication, specifically designed as an OpenWrt package.

## Key Features

- **Automated Authentication**: Replicates the Srun protocol to handle campus network login automatically.
- **Service Integration**: Fully integrated with OpenWrt's `procd` system for automatic startup, crash recovery, and process management.
- **Robustness**: Includes periodic connectivity checks (pinging `223.6.6.6`) to ensure the network remains active.
- **Native Configuration**: Uses OpenWrt's standard UCI configuration system (`/etc/config/haut-auth`) for persistent credential management.

## License

MIT License
