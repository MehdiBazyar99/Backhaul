# EasyBackhaul: The User-Friendly Backhaul Installer & Manager

Welcome to `EasyBackhaul`, a user-friendly and powerful management script for the **[Backhaul](https://github.com/Musixal/Backhaul)** reverse tunneling solution. This script simplifies the installation, configuration, and day-to-day management of Backhaul, making it accessible to everyone.

This script, developed by **@N4Xon**, provides a menu-driven interface to manage the core Backhaul reverse tunnel, which was developed by **Musixal**.

-----

## About the Core Backhaul Project

Backhaul is a high-performance reverse tunneling solution optimized for handling massive concurrent connections through NATs and firewalls.

### Core Features

  * **High Performance**: Optimized for handling massive concurrent connections efficiently.
  * **Protocol Flexibility**: Supports TCP, UDP, WebSocket (WS), and Secure WebSocket (WSS) transports.
  * **Multiplexing**: Enables multiple connections over a single transport with SMUX for greater efficiency.
  * **NAT & Firewall Bypass**: Overcomes network restrictions with robust reverse tunneling.
  * **TLS Encryption**: Secures connections via WSS with support for custom TLS certificates.

-----

## EasyBackhaul Script Features

The `EasyBackhaul` script automates the entire lifecycle of your Backhaul tunnels with an easy-to-use wizard.

  * **One-Line Installer**: Get up and running in seconds.
  * **Guided Configuration**: An interactive wizard walks you through creating new server or client tunnels for all supported protocols (TCP, UDP, WS, WSS, and multiplexed variants).
  * **Automatic Dependency Checks**: The script automatically checks for and installs required dependencies like `curl`, `jq`, and `ss`.
  * **Systemd Service Management**: Automatically creates, enables, and manages `systemd` services for each tunnel, ensuring they run reliably in the background.
  * **Port Conflict Detection**: Prevents you from creating a new tunnel on a port that is already in use.
  * **UFW Integration**: Automatically manages UFW firewall rules for your server tunnels.
  * **Full Management Menu**: A comprehensive menu to manage existing tunnels:
      * Start, Stop, and Restart services.
      * View live logs (`journalctl`).
      * View and edit tunnel configuration files with `nano`.
      * Perform connection tests to diagnose issues.
  * **Configuration Backups**: Automatically backs up a configuration file before any edits are made.
  * **Cron Job Management**: Set up custom auto-restart cron jobs for any tunnel to ensure maximum uptime.
  * **Simple Updates & Uninstallation**: Update the Backhaul binary or completely remove all traces of EasyBackhaul from your system with simple menu options.

-----

## Installation

You can install and run EasyBackhaul with a single command. The script requires `root` or `sudo` privileges to run.

```bash
bash <(curl -Ls https://raw.githubusercontent.com/NaxonM/EasyBackhaul/main/easybackhaul.sh)
```

The script will first check for the Backhaul binary. If it's not found, it will automatically download the latest version from the official GitHub repository.

## Usage

After installation, run the script again using the same command to bring up the main menu.

```
      EasyBackhaul Installer & Management Menu (v12.4)
================================================================
  Core by Musixal  |  Installer by @N4Xon
----------------------------------------------------------------
 1. Configure a New Tunnel
 2. Manage Existing Tunnels
 3. Update/Re-install Backhaul Binary
 4. Uninstall EasyBackhaul (Removes binary and ALL configs)
 0. Exit
----------------------------------------------------------------
```

### 1\. Configure a New Tunnel

This option launches the **New Tunnel Configuration Wizard**. It will guide you step-by-step:

1.  **Select Mode**: Choose whether this machine will be a `server` (listens for connections) or a `client` (connects to a server).
2.  **Select Transport**: Pick the protocol for your tunnel (e.g., `tcp`, `wss`, `tcpmux`).
3.  **Enter Configuration**: Provide necessary details like IP addresses, ports, and a secure token. The script validates your input and checks for port availability.
4.  **Advanced Options**: Fine-tune advanced parameters like keep-alive periods, connection pools, and multiplexing settings, or just accept the sensible defaults.
5.  **Confirmation**: Review the generated configuration and confirm. The script then creates the config file, sets up the firewall rule (if on a server), and creates/starts the `systemd` service.

All configuration files are stored in `/etc/backhaul/`.

### 2\. Manage Existing Tunnels

This menu lists all Backhaul services running on your system, showing their current status (Active/Inactive). Selecting a service opens the management menu for that specific tunnel, where you can:

  * **Control the Service**: Start, stop, or restart.
  * **Monitor**: View its real-time logs or check its detailed status.
  * **Configure**: View the current configuration or edit it directly using `nano`. The script will offer to restart the service to apply changes.
  * **Test Connection**: Run a basic connectivity test to help troubleshoot issues.
  * **Set Cron Job**: Create a scheduled task to automatically restart the service at a chosen interval.
  * **Delete**: Permanently remove the service, its configuration file, and its associated firewall rule.

### 3\. Update/Re-install Backhaul Binary

This option fetches the latest version of the `Backhaul` binary from the GitHub releases page and installs it to `/usr/local/bin/backhaul`.

### 4\. Uninstall EasyBackhaul

This is a destructive action that completely removes EasyBackhaul and all related components from your system. It will:

  * Stop and disable all `backhaul-*.service` units.
  * Delete the Backhaul binary (`/usr/local/bin/backhaul`).
  * Remove all configuration and backup files (`/etc/backhaul/`).
  * Delete all Backhaul systemd service files.
  * Remove all related cron jobs.

-----

## License

The core Backhaul project is licensed under the AGPL-3.0 license.
