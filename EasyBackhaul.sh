#!/bin/bash

# ==============================================================================
# EasyBackhaul Installer & Management Script
# Version: 12.5 (Line Ending Fix)
#
# Core Backhaul Development: Musixal
# Installer Script by: @N4Xon (https://github.com/MehdiBazyar99/EasyBackhaul)
#
# A user-friendly script to install, configure, and manage the
# Backhaul reverse tunneling solution.
# ==============================================================================
#
# CHANGELOG:
# - FIXED: Converted all line endings to Unix (LF) format to fix execution errors.
# - ADDED: Renamed to EasyBackhaul and added developer credits.
# - FIXED: Switched to `systemctl list-unit-files` for reliable service listing.
# - ADDED: Port conflict detection to prevent service creation on an occupied port.
# - ADDED: Numeric validation for multiplexing (MUX) parameters.
# - FIXED: Enforced universal '0' as the back/exit option in all interactive menus.
# - FIXED: Set 600 permissions on all new config files.
# - FIXED: Added timeouts and retries to network operations (curl/wget).
# - ADDED: Transport-specific configuration for all protocols.
# - ADDED: Option to edit existing tunnel configs with nano.
# - ADDED: Automatic configuration backup before any edits.
# - ADDED: Connection testing function.
# - ADDED: Comprehensive cron job management menu.
# ==============================================================================

# --- Global Variables ---
CONFIG_DIR="/etc/backhaul"
BACKUP_DIR="/etc/backhaul/backup"
BIN_PATH="/usr/local/bin/backhaul"
SERVICE_DIR="/etc/systemd/system"
UFW_METADATA_FILE="/etc/backhaul/ufw_rules.meta"
CRON_COMMENT_TAG="backhaul-installer" # Used to identify cron jobs managed by this script

# --- Helper Functions ---
print_info() { echo -e "\e[34m$1\e[0m"; }
print_success() { echo -e "\e[32m$1\e[0m"; }
print_warning() { echo -e "\e[33m$1\e[0m"; }
print_error() { echo -e "\e[31m$1\e[0m"; }
print_error_and_exit() { echo -e "\e[31m$1\e[0m"; exit 1; }
press_any_key() { read -n 1 -s -r -p "Press any key to continue..."; echo; }

# --- Prerequisite Checks ---
check_root() {
    if [[ $EUID -ne 0 ]]; then
       print_error_and_exit "This script must be run as root or with sudo."
    fi
}

check_dependencies() {
    print_info "--> Checking for required dependencies (curl, wget, tar, jq, nc, ss)..."
    local needs_install=()
    for cmd in curl wget tar jq nc ss; do
        if ! command -v $cmd &> /dev/null; then
            # 'ss' is usually in 'iproute2' or 'iproute' package
            if [[ "$cmd" == "ss" ]]; then
                needs_install+=("iproute2")
            else
                needs_install+=("$cmd")
            fi
        fi
    done

    if [ ${#needs_install[@]} -gt 0 ]; then
        print_warning "The following dependencies are missing: ${needs_install[*]}. Attempting to install..."
        if command -v apt-get &> /dev/null; then
            apt-get update >/dev/null && apt-get install -y --no-install-recommends "${needs_install[@]}" >/dev/null
        elif command -v yum &> /dev/null; then
            yum install -y "${needs_install[@]}" >/dev/null
        else
            print_error_and_exit "Unsupported package manager. Please install '${needs_install[*]}' manually."
        fi
    fi
    print_success "All dependencies are satisfied."
}

# --- Core Logic ---
get_server_info() {
    local response
    response=$(curl -s --connect-timeout 5 http://ip-api.com/json)
    if [ $? -ne 0 ] || [ -z "$response" ]; then
        print_warning "Could not fetch server info from ip-api.com. Continuing without it."
        return
    fi
    local ip
    ip=$(echo "$response" | jq -r '.query // "N/A"')
    local country
    country=$(echo "$response" | jq -r '.country // "N/A"')
    local isp
    isp=$(echo "$response" | jq -r '.isp // "N/A"')
    print_info "================================================================"
    print_info " Server IP: $ip | Location: $country | ISP: $isp"
    print_info "================================================================"
}

download_backhaul() {
    print_info "--> Identifying system architecture..."
    local ARCH
    ARCH=$(uname -m)
    local OS
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    
    print_info "--> Fetching latest version from GitHub..."
    local LATEST_VERSION_JSON
    LATEST_VERSION_JSON=$(curl -s --connect-timeout 10 "https://api.github.com/repos/Musixal/Backhaul/releases/latest")

    if [ $? -ne 0 ] || [ -z "$LATEST_VERSION_JSON" ]; then
        print_error_and_exit "Failed to contact GitHub API. Please check your network connection."
    fi
    
    local LATEST_VERSION
    LATEST_VERSION=$(echo "$LATEST_VERSION_JSON" | jq -r .tag_name)

    if [ -z "$LATEST_VERSION" ] || [ "$LATEST_VERSION" == "null" ]; then
        print_warning "Could not determine latest version from GitHub. Using fallback v0.6.6."
        LATEST_VERSION="v0.6.6"
    fi

    case $ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        *) print_error_and_exit "Unsupported architecture: $ARCH" ;;
    esac

    local download_url="https://github.com/Musixal/Backhaul/releases/download/${LATEST_VERSION}/backhaul_${OS}_${ARCH}.tar.gz"
    print_info "--> Downloading Backhaul version ${LATEST_VERSION}..."
    
    wget -q --show-progress --connect-timeout=15 --tries=3 --retry-connrefused -O /tmp/backhaul.tar.gz "$download_url"
    if [ $? -ne 0 ]; then
        print_error_and_exit "Download failed. Check the URL or your network connection."
    fi

    print_info "--> Extracting binary to $BIN_PATH..."
    tar -xzf /tmp/backhaul.tar.gz -C "$(dirname "$BIN_PATH")" "$(basename "$BIN_PATH")" || print_error_and_exit "Extraction failed."
    rm /tmp/backhaul.tar.gz
    chmod +x "$BIN_PATH"
    print_success "Backhaul binary successfully installed/updated."
}

# --- Configuration & Validation ---
validate_port() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
validate_ip() { [[ "$1" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; }
validate_number() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -gt 0 ]; }

check_port_availability() {
    local port_to_check=$1
    if ss -lntu | awk '{print $5}' | grep -q ":${port_to_check}$"; then
        print_error "Port ${port_to_check} is already in use by another service."
        return 1
    else
        return 0
    fi
}

backup_config() {
    local config_file=$1
    if [ -f "$config_file" ]; then
        mkdir -p "$BACKUP_DIR"
        local backup_path="$BACKUP_DIR/$(basename "$config_file").bak.$(date +%F_%T)"
        print_info "--> Backing up current configuration to $backup_path"
        cp "$config_file" "$backup_path"
    fi
}

configure_new_tunnel() {
    clear
    print_info "=========================================="
    print_info "      New Tunnel Configuration Wizard"
    print_info "=========================================="

    # --- Step 1: Mode ---
    local mode_choice
    while true; do
        echo
        print_info "1. Server (Listens for connections)"
        print_info "2. Client (Connects to a server)"
        print_info "0. Back to Main Menu"
        read -p "Select mode [1-2, 0]: " mode_choice
        case $mode_choice in
            1) INSTALL_MODE="server"; break ;;
            2) INSTALL_MODE="client"; break ;;
            0) return ;;
            *) print_warning "Invalid selection." ;;
        esac
    done

    # --- Step 2: Transport ---
    print_info "\nSelect transport protocol (see README for details):"
    select TRANSPORT in "tcp" "tcpmux" "udp" "ws" "wsmux" "wss" "wssmux"; do
        if [ -n "$TRANSPORT" ]; then break; else echo "Invalid option."; fi
    done

    # --- Step 3: Basic Config ---
    print_info "\n--- Basic Configuration ---"
    local tunnel_port server_ip token forwarded_ports_input
    if [[ "$INSTALL_MODE" == "server" ]]; then
        while true; do
            read -p "Enter the main tunnel port to listen on (e.g., 443): " tunnel_port
            if ! validate_port "$tunnel_port"; then
                print_warning "Invalid port number."
            elif ! check_port_availability "$tunnel_port"; then
                continue
            else
                break
            fi
        done
        read -p "Enter service ports to forward (e.g., 80, 443-600, 8080=80): " forwarded_ports_input
    else # client
        while true; do
            read -p "Enter the public IP address of the Backhaul server: " server_ip
            validate_ip "$server_ip" && break || print_warning "Invalid IP address format."
        done
        while true; do
            read -p "Enter the tunnel port set on the server: " tunnel_port
            validate_port "$tunnel_port" && break || print_warning "Invalid port number."
        done
    fi

    while true; do
        read -p "Enter a secure authentication token: " token
        [ -n "$token" ] && break || print_warning "Token cannot be empty."
    done

    # --- Step 4: Transport-Specific & Advanced Config ---
    local log_level="info" nodelay="true" keepalive_period=75
    local heartbeat=40 connection_pool=8 retry_interval=3 dial_timeout=10
    local tls_cert="" tls_key="" edge_ip=""
    local mux_version=1 mux_framesize=32768 mux_recievebuffer=4194304 mux_streambuffer=65536
    local mux_con=8 accept_udp="false" channel_size=2048 aggressive_pool="false"
    
    print_info "\n--- Advanced & Transport-Specific Configuration ---"
    read -p "Log Level (debug, info, warn, error) [info]: " log_level
    log_level=${log_level:-info}

    if [[ "$TRANSPORT" != "udp" ]]; then
        read -p "Enable TCP_NODELAY for lower latency? (true/false) [true]: " nodelay
        nodelay=${nodelay:-true}
        read -p "Keep-alive period in seconds [75]: " keepalive_period
        keepalive_period=${keepalive_period:-75}
    fi
    
    if [[ "$INSTALL_MODE" == "server" ]]; then
        read -p "Heartbeat interval in seconds [40]: " heartbeat; heartbeat=${heartbeat:-40}
        read -p "Channel size [2048]: " channel_size; channel_size=${channel_size:-2048}
        if [[ "$TRANSPORT" == "tcp" ]]; then
            read -p "Accept UDP traffic over TCP? (true/false) [false]: " accept_udp; accept_udp=${accept_udp:-false}
        fi
    else # client
        read -p "Connection pool size [8]: " connection_pool; connection_pool=${connection_pool:-8}
        read -p "Enable aggressive pool management? (true/false) [false]: " aggressive_pool; aggressive_pool=${aggressive_pool:-false}
        read -p "Connection retry interval in seconds [3]: " retry_interval; retry_interval=${retry_interval:-3}
        read -p "Connection dial timeout in seconds [10]: " dial_timeout; dial_timeout=${dial_timeout:-10}
    fi

    if [[ "$TRANSPORT" == *"mux"* ]]; then
        print_info "\n--- Multiplexing (MUX) Parameters ---"
        while true; do read -p "Multiplexing concurrency [8]: " mux_con; mux_con=${mux_con:-8}; validate_number "$mux_con" && break || print_error "Must be a positive number."; done
        while true; do read -p "SMUX protocol version (1 or 2) [1]: " mux_version; mux_version=${mux_version:-1}; [[ "$mux_version" == "1" || "$mux_version" == "2" ]] && break || print_error "Must be 1 or 2."; done
        while true; do read -p "Mux frame size (bytes) [32768]: " mux_framesize; mux_framesize=${mux_framesize:-32768}; validate_number "$mux_framesize" && break || print_error "Must be a positive number."; done
        while true; do read -p "Mux receive buffer (bytes) [4194304]: " mux_recievebuffer; mux_recievebuffer=${mux_recievebuffer:-4194304}; validate_number "$mux_recievebuffer" && break || print_error "Must be a positive number."; done
        while true; do read -p "Mux stream buffer (bytes) [65536]: " mux_streambuffer; mux_streambuffer=${mux_streambuffer:-65536}; validate_number "$mux_streambuffer" && break || print_error "Must be a positive number."; done
    fi

    if [[ "$TRANSPORT" == "ws"* && "$INSTALL_MODE" == "client" ]]; then
        print_info "\n--- WebSocket Parameters ---"
        read -p "Edge IP for CDN connection (optional, press Enter to skip): " edge_ip
    fi

    if [[ "$TRANSPORT" == "wss"* && "$INSTALL_MODE" == "server" ]]; then
        print_info "\n--- Secure WebSocket (WSS) Parameters ---"
        print_warning "This requires a valid TLS certificate and key."
        while true; do
            read -e -p "Enter the full path to your TLS certificate file (e.g., /path/to/server.crt): " tls_cert
            if [ -f "$tls_cert" ]; then break; else print_error "File not found. Please provide a valid path."; fi
        done
        while true; do
            read -e -p "Enter the full path to your TLS private key file (e.g., /path/to/server.key): " tls_key
            if [ -f "$tls_key" ]; then break; else print_error "File not found. Please provide a valid path."; fi
        done
    fi

    # --- Step 5: Build Config & Service ---
    local config_content service_name_suffix
    if [[ "$INSTALL_MODE" == "server" ]]; then
        service_name_suffix="server-${TRANSPORT}-${tunnel_port}"
        config_content="[server]\n"
        config_content+="bind_addr = \"0.0.0.0:$tunnel_port\"\n"
        config_content+="transport = \"$TRANSPORT\"\n"
        config_content+="token = \"$token\"\n"
        config_content+="log_level = \"$log_level\"\n"
        config_content+="heartbeat = $heartbeat\n"
        config_content+="channel_size = $channel_size\n"
        if [[ "$TRANSPORT" != "udp" ]]; then
            config_content+="nodelay = $nodelay\n"
            config_content+="keepalive_period = $keepalive_period\n"
        fi
        if [[ "$TRANSPORT" == "tcp" ]]; then config_content+="accept_udp = $accept_udp\n"; fi
        if [[ "$TRANSPORT" == "wss"* ]]; then
            config_content+="tls_cert = \"$tls_cert\"\n"
            config_content+="tls_key = \"$tls_key\"\n"
        fi
        
        local ports_toml=""
        IFS=',' read -ra ADDR <<< "$forwarded_ports_input"
        for p in "${ADDR[@]}"; do
            p=$(echo "$p" | tr -d ' ')
            [ -n "$p" ] && ports_toml+="\"$p\", "
        done
        ports_toml=${ports_toml%, }
        [ -n "$ports_toml" ] && config_content+="ports = [$ports_toml]\n"
        
    else # client
        service_name_suffix="client-${TRANSPORT}-$(echo "$server_ip" | tr '.' '-')-${tunnel_port}"
        config_content="[client]\n"
        config_content+="remote_addr = \"$server_ip:$tunnel_port\"\n"
        if [ -n "$edge_ip" ]; then config_content+="edge_ip = \"$edge_ip\"\n"; fi
        config_content+="transport = \"$TRANSPORT\"\n"
        config_content+="token = \"$token\"\n"
        config_content+="log_level = \"$log_level\"\n"
        config_content+="connection_pool = $connection_pool\n"
        config_content+="aggressive_pool = $aggressive_pool\n"
        config_content+="retry_interval = $retry_interval\n"
        config_content+="dial_timeout = $dial_timeout\n"
        if [[ "$TRANSPORT" != "udp" ]]; then
            config_content+="nodelay = $nodelay\n"
            config_content+="keepalive_period = $keepalive_period\n"
        fi
    fi
    
    if [[ "$TRANSPORT" == *"mux"* ]]; then
        config_content+="\n# MUX Parameters\n"
        if [[ "$INSTALL_MODE" == "server" ]]; then config_content+="mux_con = $mux_con\n"; fi
        config_content+="mux_version = $mux_version\n"
        config_content+="mux_framesize = $mux_framesize\n"
        config_content+="mux_recievebuffer = $mux_recievebuffer\n"
        config_content+="mux_streambuffer = $mux_streambuffer\n"
    fi

    # --- Step 6: Confirmation and Creation ---
    clear
    print_info "--- Configuration Summary ---"
    echo -e "$config_content"
    echo "---------------------------"
    read -p "Is this configuration correct? (y/n) [y]: " confirm
    if [[ "${confirm:-y}" != "y" ]]; then print_warning "Configuration cancelled."; return 1; fi

    mkdir -p "$CONFIG_DIR"
    local config_file="$CONFIG_DIR/config-${service_name_suffix}.toml"
    
    backup_config "$config_file"

    echo -e "$config_content" > "$config_file"
    chmod 600 "$config_file"
    print_success "Configuration file created: $config_file"

    if [[ "$INSTALL_MODE" == "server" ]]; then
        manage_ufw_add "$tunnel_port" "$TRANSPORT" "$service_name_suffix"
    fi

    create_systemd_service "$service_name_suffix" "$config_file"
}

manage_ufw_add() {
    local port=$1 transport=$2 suffix=$3
    local proto="tcp" && [[ "$transport" == "udp" ]] && proto="udp"

    if command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
        print_info "--> UFW is active. Adding rule for port $port/$proto..."
        if ufw allow "${port}/${proto}" comment "Backhaul-$suffix" > /dev/null; then
            ufw reload > /dev/null
            touch "$UFW_METADATA_FILE"
            sed -i "/^$suffix:/d" "$UFW_METADATA_FILE"
            echo "$suffix:$port/$proto" >> "$UFW_METADATA_FILE"
            print_success "UFW rule added successfully."
        else
            print_warning "Failed to add UFW rule. Please add it manually."
        fi
    fi
}

manage_ufw_delete() {
    local suffix=$1
    if command -v ufw &> /dev/null && ufw status | grep -q "Status: active" && [ -f "$UFW_METADATA_FILE" ]; then
        local rule
        rule=$(grep "^$suffix:" "$UFW_METADATA_FILE" | cut -d':' -f2)
        if [ -n "$rule" ]; then
            print_info "--> Deleting UFW rule for $rule..."
            if ufw delete allow "$rule" > /dev/null; then
                ufw reload > /dev/null
                sed -i "/^$suffix:/d" "$UFW_METADATA_FILE"
                print_success "UFW rule deleted successfully."
            else
                print_warning "Failed to delete UFW rule for $rule. Please remove it manually."
            fi
        fi
    fi
}

create_systemd_service() {
    local name_suffix=$1 config_path=$2
    local service_file="$SERVICE_DIR/backhaul-${name_suffix}.service"

    print_info "--> Creating systemd service file: $service_file"
    cat > "$service_file" <<EOL
[Unit]
Description=Backhaul Service (${name_suffix})
After=network.target

[Service]
Type=simple
ExecStart=${BIN_PATH} -c ${config_path}
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOL
    systemctl daemon-reload
    print_info "--> Enabling and starting service..."
    if ! systemctl enable "backhaul-${name_suffix}.service" >/dev/null 2>&1; then
        print_error "Failed to enable service. Please check systemd logs."
        return 1
    fi
    if ! systemctl start "backhaul-${name_suffix}.service"; then
        print_error "Failed to start service. Check config and logs with 'journalctl -u backhaul-${name_suffix}.service'."
        return 1
    fi
    print_success "Service backhaul-${name_suffix}.service created and started."

    read -p "Check service status now? (y/n) [y]: " check_status
    if [[ "${check_status:-y}" == "y" ]]; then
        systemctl status "backhaul-${name_suffix}.service" --no-pager
    fi
}

# --- Management Functions ---
manage_tunnels() {
    while true; do
        clear
        print_info "--- Available Backhaul Services ---"
        mapfile -t services < <(systemctl list-unit-files --type=service 'backhaul-*.service' --no-legend | awk '{print $1}')

        if [ ${#services[@]} -eq 0 ]; then
            print_warning "No Backhaul services found. Use 'Configure a New Tunnel' first."
            press_any_key
            return
        fi

        local i=1
        for s in "${services[@]}"; do
            if systemctl is-active --quiet "$s"; then
                echo -e " $i. \e[32m$s (Active)\e[0m"
            else
                echo -e " $i. \e[31m$s (Inactive)\e[0m"
            fi
            ((i++))
        done
        echo " 0. Back to Main Menu"
        
        local choice
        read -p "Select a service to manage [0-$((${#services[@]}))]: " choice

        if [[ "$choice" == "0" ]]; then
            return
        elif [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#services[@]} ]; then
            local service_name=${services[$((choice-1))]}
            manage_single_tunnel "$service_name"
        else
            print_warning "Invalid selection."
            press_any_key
        fi
    done
}

manage_single_tunnel() {
    local service=$1
    local suffix
    suffix=$(echo "$service" | sed 's/backhaul-\(.*\)\.service/\1/')
    local config_file="$CONFIG_DIR/config-${suffix}.toml"

    while true; do
        clear
        local status
        status=$(systemctl is-active "$service")
        local status_text
        if [[ "$status" == "active" ]]; then
             status_text="\e[32mActive\e[0m"
        else
             status_text="\e[31mInactive\e[0m"
        fi
        print_info "--- Managing: $service (Status: $status_text) ---"

        echo " 1. Start"
        echo " 2. Stop"
        echo " 3. Restart"
        echo " 4. View Status"
        echo " 5. View Logs (Live)"
        echo " 6. View Configuration"
        echo " 7. Edit Configuration (nano)"
        echo " 8. Test Connection"
        echo " 9. Manage Cron Auto-Restart"
        echo " 10. Delete Service"
        echo " 0. Back to Service List"

        local choice
        read -p "Enter choice [0-10]: " choice
        
        case $choice in
            1) systemctl start "$service"; print_success "Service started."; press_any_key;;
            2) systemctl stop "$service"; print_success "Service stopped."; press_any_key;;
            3) systemctl restart "$service"; print_success "Service restarted."; press_any_key;;
            4) systemctl status "$service" --no-pager; press_any_key;;
            5) journalctl -u "$service" -f --no-pager; press_any_key;;
            6) less "$config_file";;
            7) 
                if [ ! -f "$config_file" ]; then print_error "Config file not found!"; press_any_key; continue; fi
                backup_config "$config_file"
                nano "$config_file"
                read -p "Restart service to apply changes? (y/n) [y]: " confirm_restart
                if [[ "${confirm_restart:-y}" == "y" ]]; then systemctl restart "$service"; print_success "Service restarted."; fi
                press_any_key;;
            8) test_connection "$config_file"; press_any_key;;
            9) manage_cron_menu "$service";;
            10) 
                read -p "Are you sure you want to PERMANENTLY delete '$service' and its config? (y/n): " confirm_delete
                if [[ "${confirm_delete,,}" == "y" ]]; then
                    print_warning "Stopping and disabling service..."
                    systemctl stop "$service" &>/dev/null
                    systemctl disable "$service" &>/dev/null
                    print_warning "Removing files..."
                    rm -f "$config_file" "$SERVICE_DIR/$service"
                    manage_ufw_delete "$suffix"
                    remove_cron_job "$service"
                    systemctl daemon-reload
                    print_success "Service $service and associated files have been deleted."
                    press_any_key
                    return
                fi
                ;;
            0) return ;;
            *) print_warning "Invalid option."; press_any_key;;
        esac
    done
}

test_connection() {
    local config_file=$1
    if [ ! -f "$config_file" ]; then print_error "Config file not found."; return; fi

    print_info "--- Running Connection Test ---"
    local mode
    mode=$(grep -E '^\s*\[(server|client)\]' "$config_file" | tr -d '[]')
    
    if [[ "$mode" == "server" ]]; then
        local listen_addr
        listen_addr=$(grep -E '^\s*bind_addr\s*=' "$config_file" | cut -d'"' -f2)
        local port
        port=$(echo "$listen_addr" | cut -d':' -f2)
        print_info "Testing server listen port $port..."
        if nc -z localhost "$port"; then
            print_success "Port $port is open and listening locally."
        else
            print_error "Port $port is NOT open. The service might be down or misconfigured."
        fi
    elif [[ "$mode" == "client" ]]; then
        local remote_addr
        remote_addr=$(grep -E '^\s*remote_addr\s*=' "$config_file" | cut -d'"' -f2)
        local ip
        ip=$(echo "$remote_addr" | cut -d':' -f1)
        local port
        port=$(echo "$remote_addr" | cut -d':' -f2)
        print_info "Testing connection to remote server $ip on port $port..."
        if nc -z -w 5 "$ip" "$port"; then
            print_success "Successfully connected to $ip:$port."
        else
            print_error "Could not connect to $ip:$port. Check server status, firewall, and config."
        fi
    else
        print_warning "Could not determine mode from config file."
    fi
}

manage_cron_menu() {
    local service=$1
    while true; do
        clear
        print_info "--- Cron Auto-Restart for $service ---"
        
        local current_job
        current_job=$(crontab -l 2>/dev/null | grep "$service" | grep "$CRON_COMMENT_TAG")
        if [ -n "$current_job" ]; then
            print_success "Current Cron Job: $current_job"
        else
            print_warning "No cron job is currently set for this service."
        fi
        
        print_info "\nSelect an option:"
        echo " 1. Set/Update Job: Every 15 Minutes"
        echo " 2. Set/Update Job: Every Hour"
        echo " 3. Set/Update Job: Every 6 Hours"
        echo " 4. Set/Update Job: Every 24 Hours"
        echo " 5. Set/Update Job: Custom Interval (minutes)"
        echo " 6. Remove Existing Cron Job"
        echo " 0. Back to Tunnel Menu"
        read -p "Enter choice [1-6, 0]: " choice

        case $choice in
            1) set_cron_job "*/15 * * * *" "$service"; break;;
            2) set_cron_job "0 * * * *" "$service"; break;;
            3) set_cron_job "0 */6 * * *" "$service"; break;;
            4) set_cron_job "0 0 * * *" "$service"; break;;
            5) 
                read -p "Enter interval in minutes: " interval
                if validate_number "$interval"; then
                    set_cron_job "*/$interval * * * *" "$service"
                else
                    print_error "Invalid interval. Must be a number."; sleep 2
                fi
                break;;
            6) remove_cron_job "$service"; break;;
            0) return;;
            *) print_warning "Invalid choice.";;
        esac
    done
    press_any_key
}

set_cron_job() {
    local schedule=$1 service=$2
    remove_cron_job "$service"
    local cron_job="$schedule systemctl restart $service # $CRON_COMMENT_TAG"
    (crontab -l 2>/dev/null; echo "$cron_job") | crontab -
    print_success "Cron job set successfully for $service."
}

remove_cron_job() {
    local service=$1
    if crontab -l 2>/dev/null | grep -q "$service"; then
       (crontab -l | grep -v "$service") | crontab -
       print_success "Cron job for $service removed."
    fi
}

# --- Main Menu Logic ---
main_menu() {
    clear
    get_server_info
    print_info "      EasyBackhaul Installer & Management Menu (v12.5)"
    print_info "================================================================"
    print_info "  Core by Musixal  |  Installer by @N4Xon"
    print_info "----------------------------------------------------------------"
    echo " 1. Configure a New Tunnel"
    echo " 2. Manage Existing Tunnels"
    echo " 3. Update/Re-install Backhaul Binary"
    echo " 4. Uninstall EasyBackhaul (Removes binary and ALL configs)"
    echo " 0. Exit"
    print_info "----------------------------------------------------------------"
    read -p "Please select an option [0-4]: " choice

    case $choice in
        1) configure_new_tunnel ;;
        2) manage_tunnels ;;
        3) download_backhaul ;;
        4)
           read -p "This will REMOVE the binary and ALL configs/services. This is irreversible. Are you sure? (y/n): " confirm
           if [[ "${confirm,,}" == "y" ]]; then
                print_warning "Stopping and disabling all backhaul services..."
                systemctl stop backhaul-*.service &>/dev/null
                systemctl disable backhaul-*.service &>/dev/null
                print_warning "Removing all related files..."
                rm -f "$BIN_PATH"
                rm -rf "$CONFIG_DIR"
                rm -f "$SERVICE_DIR"/backhaul-*.service
                (crontab -l 2>/dev/null | grep -v "$CRON_COMMENT_TAG") | crontab -
                systemctl daemon-reload
                print_success "EasyBackhaul has been completely uninstalled."
           fi
           ;;
        0) exit 0 ;;
        *) print_warning "Invalid option." ;;
    esac
    press_any_key
}

# --- Script Execution ---
check_root
check_dependencies
mkdir -p "$CONFIG_DIR" "$BACKUP_DIR"

if [ ! -f "$BIN_PATH" ]; then
    print_warning "Backhaul binary not found. Running initial installation..."
    download_backhaul
    press_any_key
fi

while true; do
    main_menu
done
