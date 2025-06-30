#!/bin/bash
# ==============================================================================
# EasyBackhaul Installer & Management Script
# Version: 15.0 (Standardized Error Handling Framework)
#
# This version introduces a standardized error handling framework featuring:
# - A central `handle_error` function for consistent error reporting.
# - Standard error codes for different failure categories.
# - A `retry_with_backoff` function for transient network failures.
# - An `ERR` trap to catch unexpected errors and provide context.
# - Enhanced logging with severity levels.
# - The existing rollback framework is preserved and integrated.
# ==============================================================================

# --- Strict Mode ---
# -e: Exit immediately if a command exits with a non-zero status.
# -o pipefail: The return value of a pipeline is the status of the last command to fail.
# -u: Treat unset variables as an error.
set -e -o pipefail -u

# --- Global Variables & Constants ---
readonly CONFIG_DIR="/etc/backhaul"
readonly BACKUP_DIR="/etc/backhaul/backup"
readonly MONITOR_DIR="/etc/backhaul/monitors"
readonly LISTENER_DIR="/etc/backhaul/listeners"
readonly BIN_PATH="/usr/local/bin/backhaul"
readonly SERVICE_DIR="/etc/systemd/system"
readonly UFW_METADATA_FILE="/etc/backhaul/ufw_rules.meta"
readonly LOG_FILE="/var/log/easybackhaul.log"
readonly CRON_MONITOR_TAG="easybackhaul-monitor"
readonly CRON_PERIODIC_RESTART_TAG="easybackhaul-periodic-restart"

# --- Color Constants ---
readonly COLOR_BLUE='\e[34m'
readonly COLOR_GREEN='\e[32m'
readonly COLOR_YELLOW='\e[33m'
readonly COLOR_RED='\e[31m'
readonly COLOR_RESET='\e[0m'

# --- Standard Error Codes ---
readonly E_UNKNOWN=1
readonly E_NETWORK_FAILURE=10
readonly E_DOWNLOAD_FAILED=11
readonly E_API_CALL_FAILED=12
readonly E_FILE_NOT_FOUND=20
readonly E_PERMISSION_DENIED=21
readonly E_DISK_SPACE=22
readonly E_FILE_OP_FAILED=23
readonly E_SERVICE_FAILURE=30
readonly E_CONFIG_ERROR=40
readonly E_CMD_FAILURE=50
readonly E_UFW_FAILURE=51
readonly E_CRON_FAILURE=52
readonly E_INVALID_INPUT=60
readonly E_USER_CANCELLED=70
readonly E_DEPENDENCY_MISSING=80
readonly E_UNSUPPORTED_ARCH=90

# --- Resource Tracking for Rollback ---
TRACKED_TEMP_FILES=()
TRACKED_CONFIG_FILES=()
TRACKED_SYSTEMD_SERVICES=()
TRACKED_UFW_RULES=()
TRACKED_CRON_JOBS=()
TRACKED_LISTENER_HANDLERS=()
TRACKED_LISTENER_SOCKETS=()

# ==============================================================================
# --- Error Handling, Logging, and Cleanup Framework ---
# ==============================================================================

# --- Logging ---
log_message() {
    local level="$1"
    local message="$2"
    touch "$LOG_FILE" 2>/dev/null || true
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $message" >> "$LOG_FILE"
}

# --- Centralized Error Handler ---
handle_error() {
    local exit_code="$1"
    local error_message="$2"
    local user_suggestion="${3:-"No specific suggestion available."}"

    set +e
    
    log_message "ERROR" "Code $exit_code: $error_message"
    
    echo -e "\n${COLOR_RED}====================== ERROR ======================${COLOR_RESET}" >&2
    echo -e "${COLOR_RED}Error Code: $exit_code${COLOR_RESET}" >&2
    echo -e "${COLOR_RED}Message: $error_message${COLOR_RESET}" >&2
    echo -e "${COLOR_YELLOW}Suggestion: $user_suggestion${COLOR_RESET}" >&2
    echo -e "${COLOR_RED}==================================================${COLOR_RESET}" >&2
    
    exit "$exit_code"
}

# --- ERR Trap: Catches unexpected command failures ---
err_trap() {
    local exit_code=$?
    local last_command="${BASH_COMMAND:-"Unknown command"}"
    local line_number=${BASH_LINENO[0]}

    handle_error $E_UNKNOWN \
        "A command failed unexpectedly on line $line_number." \
        "The command '$last_command' exited with code $exit_code. Check the log at $LOG_FILE for details."
}

# --- Cleanup Trap: Runs on any script exit to perform rollback ---
cleanup() {
    local exit_code=$?
    tput cnorm 2>/dev/null || true
    tput el 2>/dev/null || true
    
    if [ ${#TRACKED_TEMP_FILES[@]} -gt 0 ] || \
       [ ${#TRACKED_CONFIG_FILES[@]} -gt 0 ] || \
       [ ${#TRACKED_SYSTEMD_SERVICES[@]} -gt 0 ] || \
       [ ${#TRACKED_UFW_RULES[@]} -gt 0 ] || \
       [ ${#TRACKED_CRON_JOBS[@]} -gt 0 ] || \
       [ ${#TRACKED_LISTENER_HANDLERS[@]} -gt 0 ] || \
       [ ${#TRACKED_LISTENER_SOCKETS[@]} -gt 0 ]; then
        
        echo
        if [ $exit_code -ne 0 ]; then
            log_message "WARN" "Script exited with code $exit_code. Starting resource rollback."
            echo -e "${COLOR_YELLOW}\n--- An error occurred. Rolling back created resources... ---${COLOR_RESET}"
        else
            log_message "INFO" "Script finished successfully. Performing final cleanup."
            echo -e "${COLOR_BLUE}\n--- Script finished. Performing final cleanup... ---${COLOR_RESET}"
        fi

        for job_info in "${TRACKED_CRON_JOBS[@]}"; do
            IFS=':' read -r service_name tag <<< "$job_info"
            log_message "CLEANUP" "Rolling back cron job for '$service_name' with tag '$tag'"
            echo -e "${COLOR_BLUE}Rolling back cron job: $tag for $service_name${COLOR_RESET}"
            remove_cron_job "$service_name" "$tag" "force"
        done

        for ufw_suffix in "${TRACKED_UFW_RULES[@]}"; do
            log_message "CLEANUP" "Rolling back UFW rule for: $ufw_suffix"
            echo -e "${COLOR_BLUE}Rolling back UFW rule for: $ufw_suffix${COLOR_RESET}"
            manage_ufw_delete "$ufw_suffix" "force"
        done

        for service in "${TRACKED_SYSTEMD_SERVICES[@]}"; do
            log_message "CLEANUP" "Rolling back systemd service: $service"
            echo -e "${COLOR_BLUE}Rolling back systemd service: $service${COLOR_RESET}"
            systemctl stop "$service" &>/dev/null || true
            systemctl disable "$service" &>/dev/null || true
            rm -f "$SERVICE_DIR/$service"
        done

        for socket in "${TRACKED_LISTENER_SOCKETS[@]}"; do
            log_message "CLEANUP" "Rolling back listener socket: $socket"
            echo -e "${COLOR_BLUE}Rolling back listener socket: $socket${COLOR_RESET}"
            systemctl stop "$socket" &>/dev/null || true
            systemctl disable "$socket" &>/dev/null || true
            rm -f "$SERVICE_DIR/$socket"
        done
        
        for handler in "${TRACKED_LISTENER_HANDLERS[@]}"; do
             log_message "CLEANUP" "Removing listener handler: $handler"
             echo -e "${COLOR_BLUE}Removing listener handler: $handler${COLOR_RESET}"
             rm -f "$handler"
        done

        for config in "${TRACKED_CONFIG_FILES[@]}"; do
            log_message "CLEANUP" "Rolling back config file: $config"
            echo -e "${COLOR_BLUE}Rolling back config file: $config${COLOR_RESET}"
            rm -f "$config"
        done

        for file in "${TRACKED_TEMP_FILES[@]}"; do
            if [ -f "$file" ]; then
                log_message "CLEANUP" "Removing temp file: $file"
                echo -e "${COLOR_BLUE}Removing temp file: $file${COLOR_RESET}"
                rm -f "$file"
            fi
        done

        log_message "INFO" "Reloading systemd daemon after cleanup."
        systemctl daemon-reload
        echo -e "${COLOR_GREEN}Cleanup complete.${COLOR_RESET}"
    fi
    
    exit $exit_code
}

# --- Set Traps ---
trap err_trap ERR
trap cleanup EXIT INT TERM

# --- Helper Functions ---
print_info() { echo -e "${COLOR_BLUE}$1${COLOR_RESET}"; }
print_success() { echo -e "${COLOR_GREEN}$1${COLOR_RESET}"; }
print_warning() { echo -e "${COLOR_YELLOW}$1${COLOR_RESET}"; }
press_any_key() { read -n 1 -s -r -p "Press any key to continue..."; echo; }

track_resource() {
    local type="$1"
    local identifier="$2"
    log_message "TRACK" "Tracking resource Type='$type', ID='$identifier'"
    case "$type" in
        TEMP_FILE) TRACKED_TEMP_FILES+=("$identifier") ;;
        CONFIG) TRACKED_CONFIG_FILES+=("$identifier") ;;
        SERVICE) TRACKED_SYSTEMD_SERVICES+=("$identifier") ;;
        UFW) TRACKED_UFW_RULES+=("$identifier") ;;
        CRON) TRACKED_CRON_JOBS+=("$identifier") ;;
        LISTENER_HANDLER) TRACKED_LISTENER_HANDLERS+=("$identifier") ;;
        LISTENER_SOCKET) TRACKED_LISTENER_SOCKETS+=("$identifier") ;;
        *) print_warning "Unknown resource type to track: $type" ;;
    esac
}

retry_with_backoff() {
    local retries=$1
    local command_to_run="$2"
    local delay=1

    for ((i=1; i<=retries; i++)); do
        set +e
        eval "$command_to_run"
        local exit_code=$?
        set -e

        if [ $exit_code -eq 0 ]; then
            return 0
        fi

        log_message "WARN" "Command failed (attempt $i/$retries). Retrying in ${delay}s..."
        print_warning "Command failed. Retrying in ${delay}s..."
        sleep $delay
        delay=$((delay * 2))
    done

    return 1
}

# ==============================================================================
# --- Prerequisite Checks ---
# ==============================================================================

check_root() {
    if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
       handle_error $E_PERMISSION_DENIED "Script must be run as root." "Please use 'sudo ./script.sh'."
    fi
}

check_dependencies() {
    print_info "--> Checking for required dependencies..."
    local missing_deps=()
    for cmd in curl wget tar jq nc ss realpath; do
        if ! command -v "$cmd" &> /dev/null; then
            case "$cmd" in
                ss) missing_deps+=("iproute2") ;;
                realpath) missing_deps+=("coreutils") ;;
                *) missing_deps+=("$cmd") ;;
            esac
        fi
    done

    if [ ${#missing_deps[@]} -gt 0 ]; then
        print_warning "The following dependencies are missing: ${missing_deps[*]}. Attempting to install..."
        log_message "INFO" "Missing dependencies: ${missing_deps[*]}. Attempting installation."
        set +e
        if command -v apt-get &> /dev/null; then
            apt-get update >/dev/null && apt-get install -y --no-install-recommends "${missing_deps[@]}"
        elif command -v yum &> /dev/null; then
            yum install -y "${missing_deps[@]}"
        else
            set -e
            handle_error $E_DEPENDENCY_MISSING \
                "Unsupported package manager and dependencies are missing: ${missing_deps[*]}." \
                "Please install the required dependencies manually and rerun the script."
        fi
        
        if [ $? -ne 0 ]; then
             set -e
             handle_error $E_DEPENDENCY_MISSING \
                "Failed to automatically install dependencies: ${missing_deps[*]}." \
                "Please install them manually and rerun the script."
        fi
        set -e
    fi
    print_success "All dependencies are satisfied."
}

# ==============================================================================
# --- Core Logic ---
# ==============================================================================

get_server_info() {
    local response
    if ! retry_with_backoff 3 "response=\$(curl -s --connect-timeout 5 http://ip-api.com/json)"; then
        print_warning "Could not fetch server info from ip-api.com after multiple retries. Continuing without it."
        log_message "WARN" "API call to ip-api.com failed permanently."
        return
    fi

    if [ -z "$response" ]; then
        print_warning "ip-api.com returned an empty response. Continuing without server info."
        return
    fi
    
    local ip country isp
    ip=$(echo "$response" | jq -r '.query // "N/A"')
    country=$(echo "$response" | jq -r '.country // "N/A"')
    isp=$(echo "$response" | jq -r '.isp // "N/A"')
    print_info "================================================================"
    print_info " Server IP: $ip | Location: $country | ISP: $isp"
    print_info "================================================================"
}

download_backhaul() {
    print_info "--> Identifying system architecture..."
    local ARCH OS
    ARCH=$(uname -m)
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    
    print_info "--> Fetching latest version from GitHub..."
    local LATEST_VERSION_JSON
    if ! retry_with_backoff 3 "LATEST_VERSION_JSON=\$(curl -s --connect-timeout 10 'https://api.github.com/repos/Musixal/Backhaul/releases/latest')"; then
        handle_error $E_API_CALL_FAILED \
            "Failed to contact GitHub API after multiple retries." \
            "Check your network connection and firewall rules."
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
        *) handle_error $E_UNSUPPORTED_ARCH "Unsupported architecture: $ARCH" "This script only supports x86_64 and aarch64." ;;
    esac

    local download_url="https://github.com/Musixal/Backhaul/releases/download/${LATEST_VERSION}/backhaul_${OS}_${ARCH}.tar.gz"
    local temp_download_file="/tmp/backhaul.tar.gz"
    
    track_resource "TEMP_FILE" "$temp_download_file"

    print_info "--> Downloading Backhaul version ${LATEST_VERSION}..."
    if ! retry_with_backoff 3 "wget -q --show-progress --connect-timeout=15 -O '$temp_download_file' '$download_url'"; then
        handle_error $E_DOWNLOAD_FAILED \
            "Failed to download the Backhaul binary from GitHub after multiple retries." \
            "Check the download URL and your network connection: $download_url"
    fi

    print_info "--> Extracting binary to $BIN_PATH..."
    tar -xzf "$temp_download_file" -C "$(dirname "$BIN_PATH")" "$(basename "$BIN_PATH")"
    
    rm "$temp_download_file"
    TRACKED_TEMP_FILES=()

    chmod +x "$BIN_PATH"
    print_success "Backhaul binary successfully installed/updated."
}

# --- Input Validation ---
validate_number() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -gt 0 ]; }

validate_port_number() {
    local port=$1
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        log_message "VALIDATION_FAILURE" "Port validation failed: Not a number - '$port'"
        echo -e "${COLOR_RED}Error: Port must be a number. Example: 8080${COLOR_RESET}" >&2
        return 1
    fi
    if (( port < 1 || port > 65535 )); then
        log_message "VALIDATION_FAILURE" "Port validation failed: Out of range - '$port'"
        echo -e "${COLOR_RED}Error: Port must be between 1 and 65535. Example: 443${COLOR_RESET}" >&2
        return 1
    fi
    return 0
}

validate_ip_address() {
    local ip=$1
    local ip_regex="^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    if ! [[ "$ip" =~ $ip_regex ]]; then
        log_message "VALIDATION_FAILURE" "IP validation failed: Invalid format - '$ip'"
        echo -e "${COLOR_RED}Error: Invalid IP address format. Example: 192.168.1.1${COLOR_RESET}" >&2
        return 1
    fi
    return 0
}

validate_auth_token() {
    local token=$1
    local min_length=8
    if [[ ${#token} -lt $min_length ]]; then
        log_message "VALIDATION_FAILURE" "Token validation failed: Too short - (hidden)"
        echo -e "${COLOR_RED}Error: Token must be at least $min_length characters long.${COLOR_RESET}" >&2
        return 1
    fi
    if [[ "$token" =~ [^a-zA-Z0-9_!@#$%^&*-] ]]; then
        log_message "VALIDATION_FAILURE" "Token validation failed: Invalid characters - (hidden)"
        echo -e "${COLOR_RED}Error: Token contains invalid characters. Use letters, numbers, and _!@#\$%^&*-${COLOR_RESET}" >&2
        return 1
    fi
    return 0
}

sanitize_service_name() {
    local unsafe_name=$1
    local sanitized_name
    sanitized_name=$(echo "$unsafe_name" | sed 's/[^a-zA-Z0-9._-]//g')
    if [[ -z "$sanitized_name" ]]; then
        log_message "VALIDATION_FAILURE" "Service name sanitization failed: Resulted in empty string - '$unsafe_name'"
        echo -e "${COLOR_RED}Error: Service name resulted in empty string after sanitization.${COLOR_RESET}" >&2
        return 1
    fi
    echo "$sanitized_name"
    return 0
}

validate_and_sanitize_path() {
    local unsafe_path=$1
    local allowed_base_dir=$2
    if [[ "$unsafe_path" == *..* ]]; then
        log_message "VALIDATION_FAILURE" "Path validation failed: Contains '..' - '$unsafe_path'"
        echo -e "${COLOR_RED}Error: Path cannot contain '..'. Example: /etc/backhaul/config.toml${COLOR_RESET}" >&2
        return 1
    fi
    local resolved_path
    resolved_path=$(realpath -m -- "$unsafe_path")
    if [[ $? -ne 0 || "$resolved_path" != "$allowed_base_dir"* ]]; then
        log_message "VALIDATION_FAILURE" "Path validation failed: Outside allowed directory - '$unsafe_path'"
        echo -e "${COLOR_RED}Error: Path is not valid or is outside the allowed directory. Example: /path/to/server.crt${COLOR_RESET}" >&2
        return 1
    fi
    if [ ! -f "$resolved_path" ]; then
        log_message "VALIDATION_FAILURE" "Path validation failed: File not found - '$resolved_path'"
        echo -e "${COLOR_RED}Error: File not found at '$resolved_path'.${COLOR_RESET}" >&2
        return 1
    fi
    echo "$resolved_path"
    return 0
}

check_port_availability() {
    local port_to_check=$1
    local return_status=0
    local messages=""

    if [ "$port_to_check" -le 1023 ]; then
        messages+="Warning: Port $port_to_check is a system-reserved port (1-1023). It may require root privileges to bind.\n"
    fi

    if [ -f /proc/sys/net/ipv4/ip_local_port_range ]; then
        local ephemeral_range
        ephemeral_range=$(cat /proc/sys/net/ipv4/ip_local_port_range)
        local eph_start
        eph_start=$(echo "$ephemeral_range" | awk '{print $1}')
        local eph_end
        eph_end=$(echo "$ephemeral_range" | awk '{print $2}')

        if [ "$port_to_check" -ge "$eph_start" ] && [ "$port_to_check" -le "$eph_end" ]; then
            messages+="Warning: Port $port_to_check is within the ephemeral range ($eph_start-$eph_end), used by the OS for outgoing connections.\n"
        fi
    fi

    local conflict_details
    conflict_details=$(ss -anp | grep -E "(:${port_to_check}(\s|$))")

    if [ -n "$conflict_details" ]; then
        return_status=1
        messages+="Error: Port ${port_to_check} is currently in use or in a conflicting state (e.g., TIME_WAIT).\n"
        messages+="--- Conflict Details ---\n"
        messages+=$(echo "$conflict_details" | awk '{printf "  Proto: %-5s State: %-10s Address: %-22s Process: %s\n", $1, $2, $5, $7}')
        messages+="\n------------------------\n"

        messages+="\nSuggesting alternative ports...\n"
        local suggestions_found=0
        local current_port=$((port_to_check + 1))
        local suggested_ports=""
        
        while [ "$suggestions_found" -lt 3 ] && [ "$current_port" -le 65535 ]; do
            if ! ss -an | awk '{print $5}' | grep -q ":${current_port}$"; then
                suggested_ports+="$current_port "
                ((suggestions_found++))
            fi
            ((current_port++))
        done
        
        if [ -n "$suggested_ports" ]; then
            messages+="Available ports nearby: $suggested_ports\n"
        else
            messages+="Could not find any available ports nearby.\n"
        fi
    fi

    if [ -n "$messages" ]; then
        if [ $return_status -eq 1 ]; then
            echo -e "${COLOR_RED}$(echo -e "$messages")${COLOR_RESET}" >&2
        else
            echo -e "${COLOR_YELLOW}$(echo -e "$messages")${COLOR_RESET}" >&2
        fi
    fi
    
    return $return_status
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

# --- Core Tunnel Configuration ---
configure_new_tunnel() {
    (
      set -e -o pipefail -u
      
      local local_configs=()
      local local_services=()
      local local_ufw_rules=()
      local local_cron_jobs=()
      
      clear
      print_info "=========================================="
      print_info "      New Tunnel Configuration Wizard"
      print_info "=========================================="

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
              0) exit $E_USER_CANCELLED ;;
              *) print_warning "Invalid selection." ;;
          esac
      done

      print_info "\nSelect transport protocol (see README for details):"
      select TRANSPORT in "tcp" "tcpmux" "udp" "ws" "wsmux" "wss" "wssmux"; do
          if [ -n "$TRANSPORT" ]; then break; else echo "Invalid option."; fi
      done

      print_info "\n--- Basic Configuration ---"
      local tunnel_port server_ip token forwarded_ports_input
      if [[ "$INSTALL_MODE" == "server" ]]; then
          while true; do
              read -p "Enter the main tunnel port to listen on (e.g., 443): " tunnel_port
              if ! validate_port_number "$tunnel_port"; then
                  continue
              elif ! check_port_availability "$tunnel_port"; then
                  continue
              else
                  read -p "Port has warnings. Do you want to continue with port $tunnel_port? (y/n) [y]: " confirm_port
                  if [[ "${confirm_port:-y}" == "y" ]]; then
                      break
                  fi
              fi
          done
          read -p "Enter service ports to forward (e.g., 80, 443-600, 8080=80): " forwarded_ports_input
      else
          while true; do
              read -p "Enter the public IP address of the Backhaul server: " server_ip
              validate_ip_address "$server_ip" && break
          done
          while true; do
              read -p "Enter the tunnel port set on the server: " tunnel_port
              validate_port_number "$tunnel_port" && break
          done
      fi

      while true; do
          read -s -p "Enter a secure authentication token: " token
          echo
          validate_auth_token "$token" && break
      done

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
      else
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
          if [[ -n "$edge_ip" ]]; then
              if ! validate_ip_address "$edge_ip"; then edge_ip=""; fi
          fi
      fi

      if [[ "$TRANSPORT" == "wss"* && "$INSTALL_MODE" == "server" ]]; then
          print_info "\n--- Secure WebSocket (WSS) Parameters ---"
          print_warning "This requires a valid TLS certificate and key."
          while true; do
              read -e -p "Enter the full path to your TLS certificate file: " cert_path_input
              tls_cert=$(validate_and_sanitize_path "$cert_path_input" "/etc/")
              if [ $? -eq 0 ]; then break; fi
          done
          while true; do
              read -e -p "Enter the full path to your TLS private key file: " key_path_input
              tls_key=$(validate_and_sanitize_path "$key_path_input" "/etc/")
              if [ $? -eq 0 ]; then break; fi
          done
      fi

      local config_content service_name_suffix
      local sanitized_transport
      sanitized_transport=$(sanitize_service_name "$TRANSPORT")
      local sanitized_port
      sanitized_port=$(sanitize_service_name "$tunnel_port")

      if [[ "$INSTALL_MODE" == "server" ]]; then
          service_name_suffix="server-${sanitized_transport}-${sanitized_port}"
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
          
      else
          local sanitized_ip
          sanitized_ip=$(echo "$server_ip" | tr '.' '-')
          sanitized_ip=$(sanitize_service_name "$sanitized_ip")
          service_name_suffix="client-${sanitized_transport}-${sanitized_ip}-${sanitized_port}"
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

      clear
      print_info "--- Configuration Summary ---"
      echo -e "$config_content"
      echo "---------------------------"
      read -p "Is this configuration correct? (y/n) [y]: " confirm
      if [[ "${confirm:-y}" != "y" ]]; then print_warning "Configuration cancelled."; exit $E_USER_CANCELLED; fi

      mkdir -p "$CONFIG_DIR"
      local config_file="$CONFIG_DIR/config-${service_name_suffix}.toml"
      
      backup_config "$config_file"

      echo -e "$config_content" > "$config_file"
      chmod 600 "$config_file"
      track_resource "CONFIG" "$config_file"
      print_success "Configuration file created: $config_file"

      if [[ "$INSTALL_MODE" == "server" ]]; then
          manage_ufw_add "$tunnel_port" "$TRANSPORT" "$service_name_suffix"
          track_resource "UFW" "$service_name_suffix"
      fi

      local service_name="backhaul-${service_name_suffix}.service"
      create_systemd_service "$service_name" "$config_file"
      track_resource "SERVICE" "$service_name"

      read -p "Enable Self-Healing (Coordinated Restart) for this service? (Recommended) (y/n) [y]: " enable_monitor
      if [[ "${enable_monitor:-y}" == "y" ]]; then
          manage_error_monitor_menu "$service_name"
      fi

      read -p "Set up a simple periodic restart cron job? (Optional) (y/n) [n]: " enable_cron
      if [[ "${enable_cron,,}" == "y" ]]; then
          manage_simple_cron_menu "$service_name"
      fi
    )

    local subshell_exit_code=$?
    if [ $subshell_exit_code -ne 0 ]; then
        if [ $subshell_exit_code -eq $E_USER_CANCELLED ]; then
            print_info "\nTunnel configuration was cancelled by the user."
        else
            print_warning "\nTunnel configuration failed. Rollback is in progress."
        fi
        return 1
    else
        TRACKED_CONFIG_FILES=()
        TRACKED_SYSTEMD_SERVICES=()
        TRACKED_UFW_RULES=()
        TRACKED_CRON_JOBS=()
        TRACKED_LISTENER_HANDLERS=()
        TRACKED_LISTENER_SOCKETS=()
        print_success "\nTunnel configuration completed successfully!"
    fi
}

manage_ufw_add() {
    local port=$1 transport=$2 suffix=$3
    local proto="tcp" && [[ "$transport" == "udp" ]] && proto="udp"

    if command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
        print_info "--> UFW is active. Adding rule for port $port/$proto..."
        if ! ufw allow "${port}/${proto}" comment "Backhaul-$suffix" > /dev/null; then
            handle_error $E_UFW_FAILURE "Failed to add UFW rule for port $port/$proto." "Check UFW status and logs."
        fi
        if ! ufw reload > /dev/null; then
            handle_error $E_UFW_FAILURE "Failed to reload UFW after adding rule." "Check UFW status and logs."
        fi
        touch "$UFW_METADATA_FILE"
        sed -i "/^$suffix:/d" "$UFW_METADATA_FILE"
        echo "$suffix:$port/$proto" >> "$UFW_METADATA_FILE"
        print_success "UFW rule added successfully."
    fi
}

manage_ufw_delete() {
    local suffix=$1
    local force_delete=${2:-"no"}
    local ufw_status

    if ! command -v ufw &> /dev/null; then
        if [[ "$force_delete" != "force" ]]; then
            print_warning "UFW is not installed. Skipping rule deletion."
        fi
        return
    fi

    ufw_status=$(ufw status)
    if ! echo "$ufw_status" | grep -q "Status: active"; then
        if [[ "$force_delete" != "force" ]]; then
            print_warning "UFW is not active. Skipping rule deletion."
        fi
        log_message "UFW_DELETE_SKIP" "UFW not active for suffix $suffix."
        return
    fi
    
    if [ ! -f "$UFW_METADATA_FILE" ]; then
        if [[ "$force_delete" != "force" ]]; then
            print_warning "UFW metadata file not found. Cannot determine which rule to delete."
        fi
        log_message "UFW_DELETE_FAIL" "Metadata file not found for suffix $suffix."
        return
    fi

    local metadata_entry
    metadata_entry=$(grep -wF "$suffix:" "$UFW_METADATA_FILE")
    
    if [ -z "$metadata_entry" ]; then
        if [[ "$force_delete" != "force" ]]; then
            print_info "No UFW rule metadata found for '$suffix'. Nothing to delete."
        fi
        return
    fi
    
    local rule
    rule=$(echo "$metadata_entry" | cut -d':' -f2)

    if ! [[ "$rule" =~ ^[0-9]+(:[0-9]+)?/(tcp|udp)$ ]]; then
        print_error "Invalid rule format '$rule' found in metadata for suffix '$suffix'. Aborting."
        log_message "UFW_DELETE_FAIL" "Invalid rule format '$rule' for suffix '$suffix'."
        return
    fi

    if ! ufw status numbered | grep -q "ALLOW IN .* $rule"; then
        if [[ "$force_delete" != "force" ]]; then
            print_warning "UFW rule '$rule' for '$suffix' does not exist in active rules. Cleaning up metadata."
        fi
        log_message "UFW_DELETE_CLEANUP" "Rule '$rule' for '$suffix' not found. Removing stale metadata."
        sed -i "/^$suffix:/d" "$UFW_METADATA_FILE"
        return
    fi

    if [[ "$force_delete" != "force" ]]; then
        print_warning "You are about to delete the UFW rule: allow $rule"
        read -p "Are you sure you want to proceed? (y/n) [n]: " confirm
        if [[ "${confirm,,}" != "y" ]]; then
            print_info "Rule deletion cancelled by user."
            log_message "UFW_DELETE_CANCEL" "User cancelled deletion of rule '$rule' for suffix '$suffix'."
            return
        fi
    fi

    print_info "--> Deleting UFW rule: allow $rule"
    log_message "UFW_DELETE_ATTEMPT" "Attempting to delete rule '$rule' for suffix '$suffix'."

    if ! ufw delete allow "$rule" > /dev/null; then
        handle_error $E_UFW_FAILURE "Failed to delete UFW rule '$rule'." "Check UFW status and logs."
    fi
    sed -i "/^$suffix:/d" "$UFW_METADATA_FILE"
    if ! ufw reload > /dev/null; then
        handle_error $E_UFW_FAILURE "Failed to reload UFW after deleting rule." "Check UFW status and logs."
    fi
    print_success "UFW rule '$rule' deleted successfully."
    log_message "UFW_DELETE_SUCCESS" "Rule '$rule' for suffix '$suffix' deleted."
}

create_systemd_service() {
    local service_name=$1 config_path=$2
    local service_file="$SERVICE_DIR/$service_name"
    local temp_service_file
    temp_service_file=$(mktemp)
    track_resource "TEMP_FILE" "$temp_service_file"

    print_info "--> Creating systemd service file: $service_file"
    cat > "$temp_service_file" <<EOL
[Unit]
Description=Backhaul Service ($(basename "$service_name" .service))
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
    
    mv "$temp_service_file" "$service_file"
    TRACKED_TEMP_FILES=()

    systemctl daemon-reload
    print_info "--> Enabling and starting service..."
    
    if ! systemctl enable "$service_name" >/dev/null 2>&1; then
        handle_error $E_SERVICE_FAILURE "Failed to enable service '$service_name'." "Run 'journalctl -xe' for details."
    fi
    if ! systemctl start "$service_name"; then
        handle_error $E_SERVICE_FAILURE "Failed to start service '$service_name'." "Check its status with 'systemctl status $service_name' and logs with 'journalctl -u $service_name'."
    fi

    print_success "Service $service_name created and started."

    read -p "Check service status now? (y/n) [y]: " check_status
    if [[ "${check_status:-y}" == "y" ]]; then
        systemctl status "$service_name" --no-pager
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
                echo -e " $i. ${COLOR_GREEN}$s (Active)${COLOR_RESET}"
            else
                echo -e " $i. ${COLOR_RED}$s (Inactive)${COLOR_RESET}"
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
        local status_text
        if systemctl is-active --quiet "$service"; then
             status_text="${COLOR_GREEN}Active${COLOR_RESET}"
        else
             status_text="${COLOR_RED}Inactive${COLOR_RESET}"
        fi
        print_info "--- Managing: $service (Status: $status_text) ---"

        echo " 1. Start"
        echo " 2. Stop"
        echo " 3. Restart"
        echo " 4. View Status"
        echo " 5. View Logs (Live)"
        echo " 6. View Configuration"
        echo " 7. Edit Configuration (nano)"
        echo " 8. Manage Auto-Restart Rules"
        echo " 9. Test Connection"
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
            8) manage_restart_rules_menu "$service";;
            9) test_connection "$config_file"; press_any_key;;
            10) delete_service "$service" "$suffix" && return;;
            0) return ;;
            *) print_warning "Invalid option."; press_any_key;;
        esac
    done
}

delete_service() {
    local service=$1
    local suffix=$2
    
    read -p "Are you sure you want to PERMANENTLY delete '$service' and its config? (y/n): " confirm_delete
    if [[ "${confirm_delete,,}" != "y" ]]; then
        print_info "Deletion cancelled."
        press_any_key
        return 1
    fi

    print_warning "Stopping and disabling service..."
    systemctl stop "$service" &>/dev/null
    systemctl disable "$service" &>/dev/null
    
    disable_error_monitor "$service"
    remove_cron_job "$service" "$CRON_PERIODIC_RESTART_TAG"
    
    print_warning "Removing files..."
    rm -f "$CONFIG_DIR/config-${suffix}.toml" "$SERVICE_DIR/$service"
    
    manage_ufw_delete "$suffix" "force"
    
    systemctl daemon-reload
    print_success "Service $service and associated files have been deleted."
    press_any_key
    return 0
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

# --- Auto-Restart Rules ---
manage_restart_rules_menu() {
    local service=$1
    while true; do
        clear
        print_info "--- Auto-Restart Rules for $service ---"
        echo "Select the type of auto-restart to manage."
        echo
        echo "1. Self-Healing (on Error)"
        echo "2. Simple Periodic Restart"
        echo "0. Back to Tunnel Menu"
        read -p "Enter choice [0-2]: " choice

        case $choice in
            1) manage_error_monitor_menu "$service";;
            2) manage_simple_cron_menu "$service";;
            0) return;;
            *) print_warning "Invalid choice.";;
        esac
    done
}

manage_simple_cron_menu() {
    local service=$1
    while true; do
        clear
        print_info "--- Simple Periodic Restart for $service ---"
        
        local current_job
        current_job=$(remove_cron_job "$service" "$CRON_PERIODIC_RESTART_TAG" "true")
        if [ -n "$current_job" ]; then
            print_success "Current Cron Job: $current_job"
        else
            print_warning "No periodic restart cron job is currently set."
        fi
        
        print_info "\nSelect an option:"
        echo " 1. Set/Update Job: Every 6 Hours"
        echo " 2. Set/Update Job: Every 12 Hours"
        echo " 3. Set/Update Job: Every 24 Hours"
        echo " 4. Remove Existing Cron Job"
        echo " 0. Back to Auto-Restart Menu"
        read -p "Enter choice [0-4]: " choice

        case $choice in
            1) set_simple_cron_job "0 */6 * * *" "$service"; break;;
            2) set_simple_cron_job "0 */12 * * *" "$service"; break;;
            3) set_simple_cron_job "0 0 * * *" "$service"; break;;
            4) remove_cron_job "$service" "$CRON_PERIODIC_RESTART_TAG"; break;;
            0) return;;
            *) print_warning "Invalid choice.";;
        esac
    done
    press_any_key
}

set_simple_cron_job() {
    local schedule=$1 service=$2
    remove_cron_job "$service" "$CRON_PERIODIC_RESTART_TAG"
    local cron_comment="# $CRON_PERIODIC_RESTART_TAG for $service"
    local cron_job="$schedule systemctl restart $service $cron_comment"
    (crontab -l 2>/dev/null; echo "$cron_job") | crontab -
    
    track_resource "CRON" "$service:$CRON_PERIODIC_RESTART_TAG"
    
    print_success "Periodic restart cron job set successfully for $service."
    log_event "CRON_SET" "Set periodic restart for $service"
}

manage_error_monitor_menu() {
    local service=$1
    while true; do
        clear
        print_info "--- Self-Healing (on Error) for $service ---"
        local sanitized_service_name
        sanitized_service_name=$(sanitize_service_name "$service")
        local monitor_script_path="$MONITOR_DIR/monitor_${sanitized_service_name}.sh"
        local listener_base_name="bh-listener-for-$(echo "$sanitized_service_name" | sed 's/\.service//')"
        local socket_unit_file="$SERVICE_DIR/${listener_base_name}.socket"

        if [ -f "$monitor_script_path" ]; then
            print_success "Monitor Status: ENABLED"
            if [ -f "$socket_unit_file" ]; then
                print_info "  -> Coordinated Restart Listener: ENABLED"
            fi
        else
            print_warning "Monitor Status: DISABLED"
        fi

        echo
        echo " 1. Configure / Re-Configure Monitor"
        echo " 2. Test Self-Healing Signal"
        echo " 3. Disable Monitor"
        echo " 4. View Monitor Log"
        echo " 0. Back to Auto-Restart Menu"
        read -p "Enter choice [0-4]: " choice

        case $choice in
            1) enable_error_monitor "$service";;
            2) test_coordinated_restart "$service"; press_any_key;;
            3) disable_error_monitor "$service";;
            4) 
                if [ -f "$LOG_FILE" ]; then
                    less "$LOG_FILE"
                else
                    print_warning "Monitor log file does not exist yet."
                    press_any_key
                fi
                ;;
            0) return;;
            *) print_warning "Invalid choice.";;
        esac
    done
}

enable_error_monitor() {
    local service=$1
    local sanitized_service_name
    sanitized_service_name=$(sanitize_service_name "$service")
    if [ -z "$sanitized_service_name" ]; then
        print_error "Cannot enable monitor for invalid service name."
        return
    fi
    local monitor_script_path="$MONITOR_DIR/monitor_${sanitized_service_name}.sh"
    
    print_info "--> Configuring Self-Healing Monitor for $service..."
    
    local coordinated_restart_vars=""
    read -p "Enable Bidirectional Coordinated Restart? (y/n) [y]: " enable_coord
    if [[ "${enable_coord:-y}" == "y" ]]; then
        print_warning "This requires setup on BOTH the client and server."
        
        print_info "\n--- [Step 1/2] Configuring LOCAL Listener ---"
        local shared_key
        while true; do
            read -s -p "Enter a SHARED secret key for the restart signal: " shared_key
            echo
            validate_auth_token "$shared_key" && break
        done
        setup_restart_listener "$service" "$shared_key"
        
        print_info "\n--- [Step 2/2] Configuring REMOTE Trigger ---"
        local remote_ip remote_port
        while true; do
            read -p "Enter the REMOTE peer's public IP address: " remote_ip
            validate_ip_address "$remote_ip" && break
        done
        while true; do
            read -p "Enter the REMOTE peer's listener port: " remote_port
            validate_port_number "$remote_port" && break
        done
        coordinated_restart_vars="REMOTE_IP=\"$remote_ip\"\nREMOTE_LISTENER_PORT=\"$remote_port\"\nCOORDINATED_RESTART_KEY=\"$shared_key\""
    fi

    local interval
    while true; do
        read -p "Enter log check interval in minutes (e.g., 3): " interval
        validate_number "$interval" && break || print_error "Must be a positive number."
    done

    cat > "$monitor_script_path" << EOF
#!/bin/bash
SERVICE_NAME="$service"
LOG_FILE="$LOG_FILE"
# Coordinated restart variables are injected below
$coordinated_restart_vars

# Check for error keywords in the last 5 log lines for the specific service
if journalctl -u "\$SERVICE_NAME" -n 5 --no-pager | grep -E -i 'ERROR|failed|invalid token|connection reset'; then
    echo "\$(date): [\$SERVICE_NAME] Detected error. Restarting service..." >> "\$LOG_FILE"
    systemctl restart "\$SERVICE_NAME"
    
    # If coordinated restart is configured, send signal to the remote peer
    if [ -n "\${COORDINATED_RESTART_KEY-}" ]; then
        echo "\$(date): [\$SERVICE_NAME] Sending restart signal to remote peer \$REMOTE_IP:\$REMOTE_LISTENER_PORT" >> "\$LOG_FILE"
        # Use a timeout of 5 seconds for the connection
        echo "\$COORDINATED_RESTART_KEY" | nc -w 5 "\$REMOTE_IP" "\$REMOTE_LISTENER_PORT"
    fi
fi
EOF

    chmod +x "$monitor_script_path"
    
    remove_cron_job "$service" "$CRON_MONITOR_TAG"
    local cron_comment="# $CRON_MONITOR_TAG for $service"
    local cron_job="*/$interval * * * * $monitor_script_path $cron_comment"
    (crontab -l 2>/dev/null; echo "$cron_job") | crontab -
    
    track_resource "CRON" "$service:$CRON_MONITOR_TAG"

    print_success "Monitor enabled. It will check for errors every $interval minutes."
    log_event "MONITOR_ENABLED" "Monitor enabled for $service with $interval min interval."
    press_any_key
}

disable_error_monitor() {
    local service=$1
    local sanitized_service_name
    sanitized_service_name=$(sanitize_service_name "$service")
    local monitor_script_path="$MONITOR_DIR/monitor_${sanitized_service_name}.sh"

    print_info "--> Disabling error monitor for $service..."
    remove_cron_job "$service" "$CRON_MONITOR_TAG"
    
    if [ -f "$monitor_script_path" ]; then
        rm -f "$monitor_script_path"
    fi

    disable_restart_listener "$service"
    
    print_success "Monitor disabled successfully."
    log_event "MONITOR_DISABLED" "Monitor disabled for $service."
    press_any_key
}

setup_restart_listener() {
    local target_service=$1
    local shared_key=$2
    local listener_port

    local sanitized_target_service
    sanitized_target_service=$(sanitize_service_name "$(echo "$target_service" | sed 's/\.service//')")
    
    local listener_base_name="bh-listener-for-${sanitized_target_service}"
    
    local handler_script_path="$LISTENER_DIR/${listener_base_name}-handler.sh"
    local socket_unit_path="$SERVICE_DIR/${listener_base_name}.socket"
    local service_unit_path="$SERVICE_DIR/${listener_base_name}@.service"

    while true; do
        read -p "Enter a high, unused port for THIS machine's listener (e.g., 48123): " listener_port
        if ! validate_port_number "$listener_port"; then
            continue
        elif ! check_port_availability "$listener_port"; then
            continue
        else
            read -p "Port has warnings. Do you want to continue with port $listener_port? (y/n) [y]: " confirm_port
            if [[ "${confirm_port:-y}" == "y" ]]; then
                break
            fi
        fi
    done
    
    print_info "--> Creating listener handler script: $handler_script_path"
    cat > "$handler_script_path" << 'EOF'
#!/bin/bash
set -euo pipefail
readonly TARGET_SERVICE="$1"
readonly RESTART_KEY="$2"
readonly LOG_FILE="$3"
readonly TEST_KEY="TEST_SIGNAL"
readonly PEER_IP="${SYSTEMD_REMOTE_HOST:-"unknown"}"

log_msg() {
    echo "$(date): [LISTENER] [Peer: $PEER_IP] $1" >> "$LOG_FILE"
}
log_msg "Connection received."

if ! read -t 5 command; then
    log_msg "Error: Timed out after 5s waiting for command. Closing connection."
    echo "ERROR: Timeout." >&2
    exit 1
fi

command=$(echo "$command" | xargs)
case "$command" in
    "$RESTART_KEY")
        log_msg "Received valid restart signal for $TARGET_SERVICE. Restarting..."
        if systemd-run --unit="backhaul-restart-job" --description="Restarting $TARGET_SERVICE" systemctl restart "$TARGET_SERVICE"; then
            echo "OK: Restart command accepted for $TARGET_SERVICE."
        else
            echo "ERROR: Failed to schedule restart for $TARGET_SERVICE."
        fi
        ;;
    "$TEST_KEY")
        log_msg "Received valid TEST signal for $TARGET_SERVICE. Connection is OK."
        echo "OK: Test signal received."
        ;;
    *)
        log_msg "Error: Received invalid signal. Command: '$command'"
        echo "ERROR: Invalid command."
        exit 1
        ;;
esac
log_msg "Successfully processed command. Closing connection."
exit 0
EOF
    chmod +x "$handler_script_path"
    track_resource "LISTENER_HANDLER" "$handler_script_path"

    print_info "--> Creating systemd socket unit: $socket_unit_path"
    cat > "$socket_unit_path" << EOL
[Unit]
Description=Socket Listener for Backhaul service ${target_service}
[Socket]
ListenStream=${listener_port}
Accept=yes
MaxConnections=10
[Install]
WantedBy=sockets.target
EOL
    track_resource "LISTENER_SOCKET" "$(basename "$socket_unit_path")"

    print_info "--> Creating systemd service unit: ${service_unit_path}"
    cat > "$service_unit_path" << EOL
[Unit]
Description=Backhaul Restart Handler for ${target_service}
[Service]
Type=oneshot
ExecStart=${handler_script_path} "${target_service}" "${shared_key}" "${LOG_FILE}"
StandardInput=socket
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=yes
Environment="SYSTEMD_REMOTE_HOST=%H"
EOL

    systemctl daemon-reload
    print_info "--> Enabling and starting listener socket..."
    systemctl enable --now "$socket_unit_path"
    
    local ufw_suffix="$(basename "$listener_base_name")"
    manage_ufw_add "$listener_port" "tcp" "$ufw_suffix"
    track_resource "UFW" "$ufw_suffix"

    print_success "Listener service '$listener_base_name' is now active on port $listener_port."
    print_warning "IMPORTANT: You must configure the REMOTE peer to send its signal to this port."
}

disable_restart_listener() {
    local target_service=$1
    local sanitized_target_service
    sanitized_target_service=$(sanitize_service_name "$(echo "$target_service" | sed 's/\.service//')")
    
    local listener_base_name="bh-listener-for-${sanitized_target_service}"
    local socket_unit_path="$SERVICE_DIR/${listener_base_name}.socket"
    local service_unit_path="$SERVICE_DIR/${listener_base_name}@.service"
    local handler_script_path="$LISTENER_DIR/${listener_base_name}-handler.sh"

    if [ -f "$socket_unit_path" ]; then
        print_info "--> Disabling and removing listener for $target_service..."
        
        systemctl disable --now "$socket_unit_path" &>/dev/null
        
        local listener_port
        listener_port=$(grep 'ListenStream=' "$socket_unit_path" | cut -d'=' -f2)
        if [ -n "$listener_port" ]; then
             manage_ufw_delete "$(basename "$listener_base_name")" "force"
        fi

        rm -f "$socket_unit_path" "$service_unit_path" "$handler_script_path"
        
        systemctl daemon-reload
        print_success "Listener service for $target_service disabled and cleaned up."
    fi
}

test_coordinated_restart() {
    local service=$1
    local sanitized_service_name
    sanitized_service_name=$(sanitize_service_name "$service")
    local monitor_script_path="$MONITOR_DIR/monitor_${sanitized_service_name}.sh"
    print_info "--- Testing Coordinated Restart Signal ---"

    if [ ! -f "$monitor_script_path" ] || ! grep -q "COORDINATED_RESTART_KEY" "$monitor_script_path"; then
        print_error "Coordinated Restart is not configured for this service."
        return
    fi

    local REMOTE_IP
    REMOTE_IP=$(awk -F'"' '/REMOTE_IP=/ {print $2}' "$monitor_script_path")
    local REMOTE_LISTENER_PORT
    REMOTE_LISTENER_PORT=$(awk -F'"' '/REMOTE_LISTENER_PORT=/ {print $2}' "$monitor_script_path")

    if [ -z "$REMOTE_IP" ] || [ -z "$REMOTE_LISTENER_PORT" ]; then
        print_error "Could not parse remote peer details from monitor script."
        return
    fi
    
    print_info "Sending TEST signal to $REMOTE_IP on port $REMOTE_LISTENER_PORT..."
    if echo "TEST_SIGNAL" | nc -w 5 "$REMOTE_IP" "$REMOTE_LISTENER_PORT"; then
        print_success "Test signal sent successfully."
        print_warning "Check the monitor log on the remote machine for a confirmation message."
    else
        print_error "Failed to send test signal. Check firewall rules and listener status on the remote machine."
    fi
}

remove_cron_job() {
    local service_name=$1
    local tag=$2
    local dry_run=${3:-"false"}

    local sanitized_service
    sanitized_service=$(sanitize_service_name "$service_name")
    if [[ -z "$sanitized_service" || "$sanitized_service" != "$service_name" ]]; then
        log_message "CRON_REMOVE_FAIL" "Invalid service name provided for cron removal: $service_name"
        print_error "Cannot remove cron job for invalid service name."
        return 1
    fi

    local cron_comment="# $tag for $service_name"

    if ! crontab -l 2>/dev/null | grep -Fq "$cron_comment"; then
        return 0
    fi

    if [[ "$dry_run" == "true" ]]; then
        crontab -l 2>/dev/null | grep -F "$cron_comment"
        return
    fi

    (crontab -l 2>/dev/null | grep -Fv "$cron_comment") | crontab -
    
    if [ $? -eq 0 ]; then
        if [[ "$dry_run" != "true" ]]; then
            print_success "Cron job for '${service_name}' with tag '${tag}' removed."
        fi
        log_message "CRON_REMOVED" "Removed cron job with comment: $cron_comment"
    else
        print_error "Failed to remove cron job for '${service_name}'."
        log_message "CRON_REMOVE_FAIL" "crontab command failed for comment: $cron_comment"
    fi
}

# --- Main Menu Logic ---
main_menu() {
    while true; do
        clear
        get_server_info
        print_info "    EasyBackhaul Installer & Management Menu (v15.0 Robust)"
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
                    systemctl stop 'backhaul-*.service' 'bh-listener-for-*.socket' &>/dev/null || true
                    systemctl disable 'backhaul-*.service' 'bh-listener-for-*.socket' &>/dev/null || true
                    print_warning "Removing all related files..."
                    rm -f "$BIN_PATH"
                    rm -rf "$CONFIG_DIR" "$LISTENER_DIR" "$MONITOR_DIR"
                    rm -f "$SERVICE_DIR"/backhaul-*.service "$SERVICE_DIR"/bh-listener-for-*.socket "$SERVICE_DIR"/bh-listener-for-*@.service
                    (crontab -l 2>/dev/null | grep -v "$CRON_MONITOR_TAG" | grep -v "$CRON_PERIODIC_RESTART_TAG") | crontab -
                    systemctl daemon-reload
                    print_success "EasyBackhaul has been completely uninstalled."
               fi
               ;;
            0) exit 0 ;;
            *) print_warning "Invalid option." ;;
        esac
        press_any_key
    done
}

# ==============================================================================
# --- Script Entry Point ---
# ==============================================================================

tput civis 2>/dev/null || true

check_root
check_dependencies
mkdir -p "$CONFIG_DIR" "$BACKUP_DIR" "$MONITOR_DIR" "$LISTENER_DIR"
touch "$LOG_FILE"
chmod 666 "$LOG_FILE"

if [ ! -f "$BIN_PATH" ]; then
    print_warning "Backhaul binary not found. Running initial installation..."
    download_backhaul
    press_any_key
fi

log_message "INFO" "Script started."
main_menu
