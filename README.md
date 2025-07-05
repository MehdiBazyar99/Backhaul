# EasyBackhaul: The User-Friendly Backhaul Installer & Manager

![Version](https://img.shields.io/badge/Version-12.5-blue.svg)
![License](https://img.shields.io/badge/License-AGPL--3.0-brightgreen.svg)
![Maintained](https://img.shields.io/badge/Maintained%3F-yes-green.svg)

[**Read this document in Persian (فارسی)**](./README-fa.md)

Welcome to `EasyBackhaul`, a user-friendly and powerful management script for the **[Backhaul](https://github.com/Musixal/Backhaul)** reverse tunneling solution. This script simplifies the installation, configuration, and day-to-day management of Backhaul, making it accessible to everyone.

This script, developed by **[@N4Xon (NaxonM)](https://github.com/NaxonM/EasyBackhaul)**, provides a menu-driven interface to manage the core Backhaul reverse tunnel, which was developed by **Musixal**.

## Installation

You can install and run EasyBackhaul with a single command. The script requires `root` or `sudo` privileges to run.

```bash
bash <(curl -Ls https://raw.githubusercontent.com/NaxonM/EasyBackhaul/stable/easybackhaul.sh)
````

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
5.  **Enter Advanced Configuration**: You can now fine-tune advanced and transport-specific parameters or accept the sensible defaults.
6.  **Confirmation**: The script displays a summary of the configuration you've built. If it looks correct, confirm with `y`.
7.  **Service Creation**: The script automatically creates the config file, adds a firewall rule (if `ufw` is active), and creates/starts a `systemd` service.

### Step 3: Manage Existing Tunnels

This menu is the central hub for managing all your tunnels.

1.  **Select Option 2** from the main menu, "Manage Existing Tunnels".
2.  **Service List**: The script will display a list of all configured Backhaul services, showing whether they are `Active` or `Inactive`.
3.  **Select a Service**: Choose the tunnel you wish to manage from the list to open the **Tunnel Management Menu**.

#### Tunnel Management Menu Options

  * `1. Start`: Starts the systemd service if it is inactive.
  * `2. Stop`: Stops the systemd service.
  * `3. Restart`: Restarts the service.
  * `4. View Status`: Shows the detailed `systemd` status.
  * `5. View Logs (Live)`: Streams the live service logs.
  * `6. View Configuration`: Displays the contents of the tunnel's configuration file.
  * `7. Edit Configuration (nano)`: Backs up the current config and then opens it in `nano`.
  * `8. Test Connection`: Performs a basic connectivity test.
  * `9. Manage Cron Auto-Restart`: Opens a sub-menu to set or remove a cron job for automatic restarts.
  * `10. Delete Service`: Permanently removes the service, its configuration, firewall rule, and cron job.
  * `0. Back to Service List`: Returns to the previous menu.

-----

## Credits

  * **Core Backhaul Project**: **Musixal**
  * **EasyBackhaul Installer Script**: **[@N4Xon (NaxonM)](https://github.com/NaxonM/EasyBackhaul)** ([Telegram](https://t.me/N4Xon))

## License

The core Backhaul project is licensed under the AGPL-3.0 license.
