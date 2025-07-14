# EasyBackhaul: The User-Friendly Backhaul Installer & Manager

![Version](https://img.shields.io/badge/Version-14.0--dev-blue.svg)
![License](https://img.shields.io/badge/License-AGPL--3.0-brightgreen.svg)
![Maintained](https://img.shields.io/badge/Maintained%3F-yes-green.svg)
![Features](https://img.shields.io/badge/Features-Advanced%20Management%20%7C%20Graceful%20Restart%20%7C%20Enhanced%20Validation%20%7C%20System%20Health%20Monitor-orange.svg)

[**Read this document in Persian (فارسی)**](./README-fa.md)

Welcome to **EasyBackhaul**, a user-friendly, modular, and powerful management script for the [Backhaul](https://github.com/Musixal/Backhaul) reverse tunneling solution. This script simplifies installation, configuration, and day-to-day management of Backhaul, making it accessible to everyone.

Developed by [@N4Xon (NaxonM)](https://github.com/NaxonM/EasyBackhaul), EasyBackhaul provides a robust, menu-driven interface to manage the core Backhaul reverse tunnel by **Musixal**.

---

## 🛠️ Installation & Quick Start

**Quick Install (Recommended):**  
Run the script directly from GitHub with a single command:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/NaxonM/EasyBackhaul/dev/easybh.sh)
```

**From Source:**  
Clone the repo and build the script from source for the latest features.

```bash
git clone https://github.com/NaxonM/EasyBackhaul.git
cd EasyBackhaul
./build.sh
sudo bash easybh.sh
```

---

## 🚀 Features

### **Core Management**
- **Modular design**: Easily maintain and extend via the `modules/` directory and `build.sh`
- **Guided configuration wizard**: For both server and client, with context-sensitive help at every step
- **Interactive log viewer**: Scroll, search, and follow logs live—exit cleanly with Ctrl+C
- **Automatic dependency, UFW, and systemd management**
- **TLS certificate management**: Generate and use self-signed certs for secure tunnels

### **Advanced Features**
- **Graceful Restart**: Coordinated restart with health checks, resource monitoring, and error recovery
- **Enhanced Configuration Validation**: Comprehensive validation with detailed error reporting
- **Coordinated Restart Watcher**: Advanced restart coordination between client and server
- **Cron auto-restart**: Set up or remove auto-restart jobs for reliability
- **Performance Monitoring**: Track operation performance and resource usage
- **Health Monitoring**: Real-time tunnel health checks with resource monitoring
- **System Health & Performance Monitor**: Comprehensive system monitoring and optimization
- **Zombie Process Cleanup**: Automatic cleanup of orphaned processes and watchers

### **User Experience**
- **Advanced error handling**: Clear, color-coded messages and safe defaults
- **Progress indicators**: Visual feedback for long operations with spinner animations
- **Input validation**: Robust validation with re-prompting for invalid input
- **Contextual help**: Press `?` for help throughout the interface
- **Multi-language support**: English and Persian documentation
- **Dev channel**: Try the latest features before stable release
- **Installation Wizard**: Multiple installation options with network diagnostics

### **Security & Performance**
- **Secure file operations**: Secure deletion and permission hardening
- **Resource optimization**: Process priority optimization and memory management
- **Rate limiting**: Protection against rapid operations
- **Input sanitization**: Secure handling of user input
- **Log rotation**: Automatic log management and rotation
- **Permission hardening**: Automatic security hardening of config files and directories

### **Logging & Monitoring**
- **Enhanced logging system**: JSON and text formats with configurable levels
- **Log level management**: Dynamic log level changes (debug/info/warn/error)
- **Health logging**: Dedicated health and performance log files
- **Audit logging**: Comprehensive audit trail of all operations
- **Log file viewer**: Interactive log file browsing and searching

---

## 📝 How to Use: Step-by-Step

### 1. Installation Wizard

The script starts with an installation wizard offering multiple options:
- **Automatic GitHub Download** (Recommended): Downloads the latest Backhaul binary from GitHub
- **Local File Installation**: Install from a local backhaul binary file
- **Alternative Download Source**: Use alternative download sources if GitHub is unavailable
- **Network Diagnostics**: Test network connectivity and diagnose issues
- **Skip Installation** (Advanced): Skip binary installation for advanced users

### 2. Main Menu

After installation, you'll see:

```
      EasyBackhaul Management Menu (v14.0-dev)
=================================================================
  Core by Musixal  |  Installer by @N4Xon
-----------------------------------------------------------------
 1. Configure a New Tunnel
 2. Manage Existing Tunnels
 3. Update/Re-install Backhaul Binary
 4. Generate Self-Signed TLS Certificate
 5. System Health & Performance Monitor
 6. Clean Stale Processes & Temp Files
 7. Manage UFW Firewall (if installed)
 8. Uninstall EasyBackhaul
 ?. Help & Documentation
 0. Exit
----------------------------------------------------------------
```

### 3. Configure a New Tunnel

- **Quick Setup (Recommended)**: Uses sensible defaults and asks only essential questions
- **Advanced Setup**: Full control over all settings for power users
- **Smart Transport Selection**: Simplified options with clear descriptions
- **Interactive Port Configuration**: Add port forwarding rules one by one with clear examples.
- **Automatic Validation**: Check port availability, validate IP, and optional ping test
- **Enhanced Input Validation**: Robust validation with helpful error messages

### 4. Manage Existing Tunnels

#### **Tunnel Management Menu**
- **Start/Stop/Restart**: Basic service control
- **Graceful Restart**: Advanced restart with health checks and resource monitoring
- **View Service Status**: Summary and recent logs
- **View Full Logs**: Interactive log viewing with scroll/search/follow options
- **View Configuration**: Display current tunnel configuration
- **Edit Configuration**: Edit with nano and optionally restart
- **Change Log Level**: Modify logging verbosity (debug/info/warn/error)
- **Test Connection**: Real network connectivity testing
- **Hot Reload Config**: Reload configuration without restart
- **Manage Cron Auto-Restart**: Set up automatic restarts
- **Manage Coordinated Restart Watcher**: Advanced restart coordination
- **Health Check & Performance**: Monitor tunnel health and performance
- **Validate Configuration**: Comprehensive configuration validation
- **Delete Service**: Remove tunnel and all related files

---

## 🧑‍💻 Development & Building

### **Modular Architecture**
- All logic is modularized in `modules/`
- Use `./build.sh` to generate the distributable `easybh.sh`
- **Do not edit `easybh.sh` directly**—edit modules and rebuild

---

## 🧪 Dev Channel

This version is distributed via the **dev channel**.  
Please report bugs and feedback via [GitHub Issues](https://github.com/NaxonM/EasyBackhaul/issues).

---

## 🙏 Credits

- **Core Backhaul Project**: [Musixal](https://github.com/Musixal/Backhaul)
- **EasyBackhaul Installer Script**: [@N4Xon (NaxonM)](https://github.com/NaxonM/EasyBackhaul) ([Telegram](https://t.me/N4Xon))

---

## 📄 License

The core Backhaul project is licensed under the AGPL-3.0 license.

---

**For Persian documentation, see [README-fa.md](./README-fa.md).**
