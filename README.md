# EasyBackhaul: The User-Friendly Backhaul Installer & Manager

Welcome to `EasyBackhaul`, a user-friendly and powerful management script for the **[Backhaul](https://github.com/Musixal/Backhaul)** reverse tunneling solution. This script simplifies the installation, configuration, and day-to-day management of Backhaul, making it accessible to everyone.

This script, developed by **[@N4Xon (NaxonM)](https://www.google.com/search?q=https://github.com/NaxonM)**, provides a menu-driven interface to manage the core Backhaul reverse tunnel, which was developed by **Musixal**.

## Installation

You can install and run EasyBackhaul with a single command. The script requires `root` or `sudo` privileges to run.

```bash
bash <(curl -Ls https://raw.githubusercontent.com/NaxonM/EasyBackhaul/main/EasyBackhaul.sh)
```

The script will first check for the Backhaul binary. If it's not found, it will automatically download the latest version from the official GitHub repository.

-----

## How to Use: A Step-by-Step Guide

This guide will walk you through setting up and managing a tunnel using the EasyBackhaul script.

### Step 1: Run the Script & View the Main Menu

After installation, run the command again to bring up the main menu. The script will greet you with server information and the main options.

```
      EasyBackhaul Installer & Management Menu (v12.5)
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

### Step 2: Configure a New Tunnel (Server Example)

This wizard-driven process makes setup simple. Let's configure a `server` tunnel.

1.  **Select Option 1** from the main menu, "Configure a New Tunnel".
2.  **Choose Mode**: You will be asked if this machine is a `Server` or a `Client`. Select `1` for Server.
3.  **Select Transport**: Choose a transport protocol from the list (e.g., `tcp`, `udp`, `wss`, `tcpmux`).
4.  **Enter Basic Configuration**:
      * **Tunnel Port**: The main port the Backhaul server will listen on. The script will check if this port is already in use.
      * **Forwarded Ports**: The service ports on the client you want to expose on the server (e.g., `80, 443, 2222=22`).
      * **Authentication Token**: A secure password to authenticate the client and server.
5.  **Enter Advanced Configuration**: You can now fine-tune advanced and transport-specific parameters or accept the sensible defaults for things like `log_level`, `keepalive_period`, and multiplexing (MUX) settings if you chose a MUX transport.
6.  **Confirmation**: The script displays a summary of the configuration you've built. If it looks correct, confirm with `y`.
7.  **Service Creation**: The script automatically:
      * Creates a configuration file in `/etc/backhaul/`.
      * Adds a firewall rule using `ufw` if it's active.
      * Creates, enables, and starts a `systemd` service for the new tunnel.

Your new tunnel is now active and ready to accept a client connection.

### Step 3: Manage Existing Tunnels

This menu is the central hub for managing all your tunnels.

1.  **Select Option 2** from the main menu, "Manage Existing Tunnels".
2.  **Service List**: The script will display a list of all configured Backhaul services, showing whether they are `Active` or `Inactive`.
3.  **Select a Service**: Choose the tunnel you wish to manage from the list. This will open the **Tunnel Management Menu**.

#### Tunnel Management Menu Options

Here are the available actions for your selected tunnel:

  * `1. Start`: Starts the systemd service if it is inactive.
  * `2. Stop`: Stops the systemd service.
  * `3. Restart`: Restarts the service.
  * `4. View Status`: Shows the detailed `systemd` status, including uptime and recent logs.
  * `5. View Logs (Live)`: Streams the live service logs using `journalctl -f`.
  * `6. View Configuration`: Displays the contents of the tunnel's configuration file.
  * `7. Edit Configuration (nano)`: Backs up the current config and then opens it in the `nano` text editor for changes. You will be prompted to restart the service to apply the changes.
  * `8. Test Connection`: Performs a basic connectivity test. For servers, it checks if the port is listening locally. For clients, it tries to connect to the remote server.
  * `9. Manage Cron Auto-Restart`: Opens a sub-menu to set or remove a cron job that automatically restarts the service at a chosen interval (e.g., every hour, every day).
  * `10. Delete Service`: A permanent action that stops and disables the service, then deletes its configuration file, systemd service file, firewall rule, and any associated cron jobs.
  * `0. Back to Service List`: Returns to the previous menu.

-----

## Main Menu Options Explained

  * **1. Configure a New Tunnel**: Launches a wizard to create a new client or server tunnel with a specific protocol.
  * **2. Manage Existing Tunnels**: Allows you to view, control, monitor, edit, and delete any tunnel you have previously configured.
  * **3. Update/Re-install Backhaul Binary**: Downloads the latest version of the core `backhaul` binary from GitHub and replaces the current one.
  * **4. Uninstall EasyBackhaul**: This option completely and irreversibly removes the Backhaul binary and all related configurations, services, backups, and cron jobs managed by this script.
  * **0. Exit**: Exits the EasyBackhaul script.

## EasyBackhaul Script Features

  * **One-Line Installer**: Get up and running in seconds.
  * **Guided Configuration**: An interactive wizard for creating server or client tunnels.
  * **Automatic Dependency Checks**: Installs required dependencies like `curl`, `jq`, and `ss`.
  * **Systemd Service Management**: Automatically creates and manages `systemd` services for reliability.
  * **Port Conflict Detection**: Prevents creating a service on an occupied port.
  * **UFW Integration**: Automatically manages UFW firewall rules.
  * **Configuration Backups**: Automatically backs up configs before edits.
  * **Connection Testing**: A built-in function to help diagnose connection issues.
  * **Cron Job Management**: Set up custom auto-restart cron jobs to ensure uptime.

## About the Core Backhaul Project

Backhaul is a high-performance reverse tunneling solution optimized for handling massive concurrent connections through NATs and firewalls.

## Credits

  * **Core Backhaul Project**: **Musixal**
  * **EasyBackhaul Installer Script**: **[@N4Xon (NaxonM)](https://www.google.com/search?q=https://github.com/NaxonM)** (Telegram: @N4Xon)

## License

The core Backhaul project is licensed under the AGPL-3.0 license.
