# EasyBackhaul: The User-Friendly Backhaul Installer & Manager

![Version](https://img.shields.io/badge/Version-13.0--beta-blue.svg)
![License](https://img.shields.io/badge/License-AGPL--3.0-brightgreen.svg)
![Maintained](https://img.shields.io/badge/Maintained%3F-yes-green.svg)
![Features](https://img.shields.io/badge/Features-Advanced%20Management%20%7C%20Graceful%20Restart%20%7C%20Enhanced%20Validation%20%7C%20System%20Health%20Monitor-orange.svg)

[**Read this document in Persian (فارسی)**](./README-fa.md)

Welcome to **EasyBackhaul**, a user-friendly, modular, and powerful management script for the [Backhaul](https://github.com/Musixal/Backhaul) reverse tunneling solution. This script simplifies installation, configuration, and day-to-day management of Backhaul, making it accessible to everyone.

Developed by [@N4Xon (NaxonM)](https://github.com/NaxonM/EasyBackhaul), EasyBackhaul provides a robust, menu-driven interface to manage the core Backhaul reverse tunnel by **Musixal**.

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
- **Beta channel**: Try the latest features before stable release
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

## 🛠️ Installation & Quick Start

**Quick Install (Recommended):**  
Run the script directly from GitHub with a single command:

```bash
sudo bash <(curl -Ls https://raw.githubusercontent.com/NaxonM/EasyBackhaul/beta/easybackhaul.sh)
```

**From Source:**  
Clone the repo and build the script from source for the latest features.

```bash
git clone https://github.com/NaxonM/EasyBackhaul.git
cd EasyBackhaul
./build.sh
sudo bash easybackhaul.sh
```

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
      EasyBackhaul Installer & Management Menu (v13.0-beta)
================================================================
  Core by Musixal  |  Installer by @N4Xon
----------------------------------------------------------------
 1. Configure a New Tunnel
 2. Manage Existing Tunnels
 3. Update/Re-install Backhaul Binary
 4. Generate Self-Signed TLS Certificate
 5. Select Backhaul Binary Directory (current: /usr/local/bin/backhaul)
 6. System Health & Performance Monitor
 7. Clean Up Zombie/Orphaned Processes
 8. Uninstall EasyBackhaul (Removes binary and ALL configs)
 ?. Help & Documentation
 0. Exit
----------------------------------------------------------------
```

### 3. Configure a New Tunnel

- **Quick Setup (Recommended)**: Uses sensible defaults and asks only essential questions
- **Advanced Setup**: Full control over all settings for power users
- **Smart Transport Selection**: Simplified options with clear descriptions
- **Simple Port Configuration**: Enter ports as single, multiple, or ranges (e.g., `80,443,8000-8010`)
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

#### **Graceful Restart Feature**
- **Pre-restart health check**: Verify current tunnel status
- **System resource monitoring**: Check memory, CPU, and disk usage
- **Coordinated restart**: Stop service, wait for cooldown, restart with retry
- **Post-restart verification**: Confirm tunnel is healthy after restart
- **Error recovery**: Automatic recovery options if restart fails
- **Progress indicators**: Visual feedback during the restart process

#### **Enhanced Configuration Validation**
- **Comprehensive validation**: Check syntax, required fields, and protocol-specific settings
- **Detailed error reporting**: Clear error messages with specific issues
- **Support for all protocols**: TCP, UDP, WebSocket, WSS, TCP Multiplexing, WSMUX, WSSMUX
- **Port conflict detection**: Identify potential port conflicts
- **Security validation**: Check for security issues and deprecated fields

#### **Interactive Log Viewer**
- Choose between live follow or interactive scroll/search
- **Press Ctrl+C** to exit log view and return to the menu (the script will not close)
- **Search functionality**: Use `/` to search within logs
- **Follow mode**: Use `F` to follow logs in real-time

#### **Coordinated Restart Watcher**
- **Background process**: Runs as a lightweight background process
- **Restart coordination**: Coordinates restarts between client and server
- **Configurable**: Customize patterns, delays, and ports
- **Status monitoring**: View watcher status and logs
- **Testing**: Test watcher communication

### 5. System Health & Performance Monitor

#### **System Overview**
- **Binary status**: Check Backhaul binary installation and version
- **Service status**: Monitor all running Backhaul services
- **Resource usage**: Real-time CPU, memory, and disk usage
- **Log file sizes**: Monitor log file growth and rotation

#### **Actions Available**
- **Refresh health status**: Update all system metrics
- **Clean up zombie processes**: Remove orphaned processes and watchers
- **View detailed logs**: Browse and search through log files
- **Optimize all tunnel processes**: Optimize resource usage for all tunnels

### 6. Advanced Management Features

#### **Log Level Management**
- **Dynamic log level changes**: Modify logging verbosity without restart
- **Supported levels**: debug, info, warn, error
- **Automatic restart**: Option to restart service after log level change
- **Current level display**: Show current log level for each tunnel

#### **Zombie Process Cleanup**
- **Automatic detection**: Find orphaned processes and watchers
- **Safe termination**: Graceful shutdown with fallback to force kill
- **Comprehensive cleanup**: Remove PID files, logs, and temporary files
- **System optimization**: Clean up system resources

#### **Binary Management**
- **Path customization**: Change Backhaul binary location
- **Version checking**: Display binary version and status
- **Reinstallation**: Update or reinstall Backhaul binary
- **Session persistence**: Remember binary path for current session

---

## 🔧 Advanced Features

### **Performance Monitoring**
- **Operation tracking**: Monitor performance of all operations
- **Resource usage**: Track memory, CPU, and disk usage
- **Slow operation detection**: Identify operations taking longer than expected
- **Performance optimization**: Automatic process priority optimization

### **Health Monitoring**
- **Real-time health checks**: Monitor tunnel health status
- **Resource monitoring**: Track memory and CPU usage per tunnel
- **Health logging**: Log health metrics for analysis
- **Automatic recovery**: Attempt recovery for failed tunnels

### **Security Features**
- **Secure file operations**: Secure deletion and permission hardening
- **Input sanitization**: Protect against malicious input
- **Rate limiting**: Prevent abuse of the management interface
- **Audit logging**: Comprehensive audit trail of all operations
- **Permission hardening**: Automatic security hardening of files and directories

### **Error Handling & Recovery**
- **Advanced error recovery**: Automatic recovery for common issues
- **Retry mechanisms**: Exponential backoff for failed operations
- **Graceful degradation**: Continue operation even with partial failures
- **Error logging**: Detailed error logging for troubleshooting

### **Enhanced Logging System**
- **Multiple formats**: JSON and text logging formats
- **Configurable levels**: DEBUG, INFO, WARN, ERROR levels
- **Log rotation**: Automatic log rotation and compression
- **Dedicated log files**: Separate files for health, performance, and general logs
- **Interactive viewing**: Advanced log viewing with search and follow capabilities

---

## 🧑‍💻 Development & Building

### **Modular Architecture**
- All logic is modularized in `modules/`
- Use `./build.sh` to generate the distributable `easybackhaul.sh`
- **Do not edit `easybackhaul.sh` directly**—edit modules and rebuild

### **Module Structure**
```
modules/
├── backhaul_core.sh      # Core Backhaul operations
├── config.sh            # Configuration management
├── cron.sh              # Cron job management
├── globals.sh           # Global variables and settings
├── helpers.sh           # Utility functions and helpers
├── menu.sh              # Main menu and UI
├── prereqs.sh           # Prerequisites and dependencies
├── restart_watcher.sh   # Coordinated restart watcher
├── systemd.sh           # Systemd service management
├── tunnel_mgmt.sh       # Tunnel management
├── ufw.sh               # UFW firewall management
└── validation.sh        # Configuration validation
```

### **Building from Source**
```bash
# Clone the repository
git clone https://github.com/NaxonM/EasyBackhaul.git
cd EasyBackhaul

# Build the script
./build.sh

# The script is now ready to use
sudo bash easybackhaul.sh
```

---

## 🧪 Beta Channel

This version is distributed via the **beta channel**.  
Please report bugs and feedback via [GitHub Issues](https://github.com/NaxonM/EasyBackhaul/issues).

### **Recent Improvements**
- ✅ **Graceful Restart**: Advanced restart with health checks and resource monitoring
- ✅ **Enhanced Validation**: Comprehensive configuration validation with detailed reporting
- ✅ **Improved UX**: Progress indicators, better error messages, and contextual help
- ✅ **Performance Monitoring**: Track operation performance and resource usage
- ✅ **Security Enhancements**: Secure file operations and input sanitization
- ✅ **Error Recovery**: Advanced error handling and recovery mechanisms
- ✅ **Coordinated Restart Watcher**: Advanced restart coordination between client and server
- ✅ **System Health Monitor**: Comprehensive system monitoring and optimization
- ✅ **Zombie Process Cleanup**: Automatic cleanup of orphaned processes
- ✅ **Enhanced Logging**: Advanced logging system with multiple formats and levels
- ✅ **Installation Wizard**: Multiple installation options with network diagnostics
- ✅ **Log Level Management**: Dynamic log level changes for troubleshooting

---

## 🙏 Credits

- **Core Backhaul Project**: [Musixal](https://github.com/Musixal/Backhaul)
- **EasyBackhaul Installer Script**: [@N4Xon (NaxonM)](https://github.com/NaxonM/EasyBackhaul) ([Telegram](https://t.me/N4Xon))

---

## 📄 License

The core Backhaul project is licensed under the AGPL-3.0 license.

---

**For Persian documentation, see [README-fa.md](./README-fa.md).**
