# Backhaul (Linux Usability Fork)

This repository is a Linux‑first fork of the original Backhaul reverse tunneling project. It is maintained by Mehdi Bazyar and focuses on easy installation and management on Linux systems. Windows support and NSSM helpers have been removed.

## Key Improvements

- **Guided installer**: `install.sh` installs missing dependencies, helps you build from source or use a local/remote binary, and sets up systemd automatically.
- **Interactive manager**: `backhaul-manager.sh` offers menus for service control, safe upgrades and a configuration wizard.
- **TLS utilities and monitoring**: helper scripts simplify certificate generation and include cron‑based tunnel watchdogs.

## Quick Start

```bash
bash <(curl -Ls https://raw.githubusercontent.com/MehdiBazyar99/Backhaul/main/scripts/install.sh)
```

The installer detects your architecture, installs the `backhaul` binary, creates `/etc/backhaul/config.toml`, and enables a `backhaul.service` systemd unit. It offers prompts for bind ports, tokens, transport type, and web UI port so the defaults can be customized during setup.

Backhaul automatically applies recommended defaults for the selected mode (server or client). You can further adjust settings at any time.

### Installation options

The installer works even when release binaries are not available. It automatically installs missing dependencies such as `git` and the Go compiler. When run it will prompt you to choose one of the following methods:

1. **Build from source** – clones this repository and compiles `backhaul` with Go.
2. **Use an existing binary** – provide the path to a previously built `backhaul` executable.
3. **Download a tarball** – supply a URL to a `.tar.gz` archive that contains the binary.

All required helper scripts and the manager are downloaded automatically.

## Configuration

Configuration lives in `/etc/backhaul/config.toml`. Both server and client sections are present with sensible defaults. Run `backhaul-manager.sh` and choose **Edit config** or edit the file manually to tweak options.

Example snippet:

```toml
[server]
bind_addr = "0.0.0.0:3080"
transport = "tcp"

[client]
remote_addr = "0.0.0.0:3080"
transport = "tcp"
```

After editing, restart the service with `sudo systemctl restart backhaul.service` or use the manager menu.

## Example: Tunneling Between Two Servers

1. **On the server (A)** run the installer and choose `server` mode. Note the public IP displayed at the end of the installation.
2. **On the client (B)** run the installer and choose `client` mode. When prompted for the server address, enter the IP of server A.
3. Start the service on both machines with `sudo systemctl start backhaul.service` (the installer enables it automatically).
4. Verify connectivity using `backhaul-manager.sh` on either side and check the status.

## Using the Manager

Run `sudo backhaul-manager.sh` to open the interactive menu. Options include:

- Start/stop/restart and view logs
- Regenerate TLS certificates
- Choose common transport presets
- Backup or restore configuration
- Launch a configuration wizard for adjusting ports, tokens and transport
- Perform safe upgrades by providing a new binary path or URL
- Enable a cron watchdog that restarts the service if the tunnel stops
The **Advanced** submenu provides tools to backup/restore configs, apply recommended defaults and start the configuration wizard at any time.

The banner shows your public IP, geolocation and web UI port if configured.

## Troubleshooting

- Logs are available via `journalctl -u backhaul.service`.
- Backup files reside in `/etc/backhaul/backup/`.
- If upgrades fail, the manager automatically rolls back to the previous binary and config.

## About this fork

This repository drops all Windows support from the original project and focuses on automation on Linux. Advanced configuration remains available via the manager menus or by editing `config.toml`.

## License

Backhaul is released under the AGPL‑v3 license.
