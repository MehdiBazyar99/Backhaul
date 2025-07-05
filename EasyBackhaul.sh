#!/bin/bash
# ======================================================================
# THIS FILE IS AUTO-GENERATED. DO NOT EDIT DIRECTLY.
# Edit the files in ./modules/ and run ./build.sh to regenerate.
# ======================================================================
# --- MODULE: modules/globals.sh ---
# globals.sh
# Contains global variables, constants, and paths for EasyBackhaul

# --- Global Variables ---
# All global variables use UPPER_SNAKE_CASE for consistency
CONFIG_DIR="/etc/backhaul"
BACKUP_DIR="/etc/backhaul/backup"
BIN_PATH="/usr/local/bin/backhaul"
SERVICE_DIR="/etc/systemd/system"
UFW_METADATA_FILE="/etc/backhaul/ufw_rules.meta"
CRON_COMMENT_TAG="backhaul-installer" # Used to identify cron jobs managed by this script
RESTART_WATCHER_PORT=45679
RESTART_WATCHER_SECRET="easybackhaul-restart-secret"
RESTART_WATCHER_DIR="/etc/backhaul/restart_watchers"

# --- Enhanced Logging System ---
LOG_DIR="/var/log/backhaul"
LOG_LEVEL="INFO"  # DEBUG, INFO, WARN, ERROR
LOG_MAX_SIZE="10M"
LOG_MAX_FILES=5
LOG_FORMAT="json"  # json, text

# --- Health Monitoring ---
HEALTH_CHECK_INTERVAL=30  # seconds
HEALTH_CHECK_TIMEOUT=10   # seconds
HEALTH_LOG_FILE="$LOG_DIR/health.log"
PERFORMANCE_LOG_FILE="$LOG_DIR/performance.log"

# --- Performance Settings ---
MAX_CONCURRENT_OPERATIONS=3
OPERATION_TIMEOUT=300  # seconds
RESOURCE_CHECK_INTERVAL=60  # seconds

# --- Advanced Error Recovery ---
MAX_RESTART_ATTEMPTS=3
RESTART_COOLDOWN=10  # seconds
ERROR_RECOVERY_ENABLED=true

# --- Resource Management ---
MAX_MEMORY_USAGE="512M"
MAX_CPU_USAGE=80  # percentage
PROCESS_PRIORITY=0  # nice value (-20 to 19)

# --- Configuration Validation ---
CONFIG_VALIDATION_STRICT=true
CONFIG_BACKUP_ON_CHANGE=true
CONFIG_VERSION="1.0"

# --- Security Enhancements ---
SECURE_MODE_ENABLED=true
FILE_PERMISSIONS_STRICT=true
TEMP_FILE_SECURE_DELETE=true


# --- MODULE: modules/helpers.sh ---
# helpers.sh
# Utility and print functions (color output, error handling, etc.) 

# --- Helper Functions ---
# Standardized print functions with consistent color coding
print_info() { echo -e "\e[34m$1\e[0m"; }
print_success() { echo -e "\e[32m$1\e[0m"; }
print_warning() { echo -e "\e[33m$1\e[0m"; }
print_error() { echo -e "\e[31m$1\e[0m"; }
print_error_and_exit() { echo -e "\e[31m$1\e[0m"; exit 1; }
press_any_key() { read -n 1 -s -r -p "Press any key to continue..."; echo; }

# --- Enhanced Logging System ---
# Initialize logging system
init_logging() {
    mkdir -p "$LOG_DIR"
    chmod 755 "$LOG_DIR"
    
    # Create log files if they don't exist
    touch "$HEALTH_LOG_FILE" "$PERFORMANCE_LOG_FILE"
    chmod 644 "$HEALTH_LOG_FILE" "$PERFORMANCE_LOG_FILE"
    
    # Set up log rotation if logrotate is available
    if command -v logrotate &>/dev/null; then
        setup_log_rotation
    fi
}

# Setup log rotation
setup_log_rotation() {
    local logrotate_conf="/etc/logrotate.d/backhaul"
    cat > "$logrotate_conf" << EOF
$LOG_DIR/*.log {
    daily
    missingok
    rotate $LOG_MAX_FILES
    compress
    delaycompress
    notifempty
    create 644 root root
    postrotate
        systemctl reload backhaul-* 2>/dev/null || true
    endscript
}
EOF
    chmod 644 "$logrotate_conf"
}

# Enhanced logging function with levels
log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local log_file="$LOG_DIR/easybackhaul.log"
    
    # Check log level
    case "$LOG_LEVEL" in
        "DEBUG") ;;
        "INFO") [[ "$level" == "DEBUG" ]] && return ;;
        "WARN") [[ "$level" == "DEBUG" || "$level" == "INFO" ]] && return ;;
        "ERROR") [[ "$level" != "ERROR" ]] && return ;;
    esac
    
    # Format message based on LOG_FORMAT
    if [[ "$LOG_FORMAT" == "json" ]]; then
        echo "{\"timestamp\":\"$timestamp\",\"level\":\"$level\",\"message\":\"$message\"}" >> "$log_file"
    else
        echo "[$timestamp] [$level] $message" >> "$log_file"
    fi
}

# Logging convenience functions
log_debug() { log_message "DEBUG" "$1"; }
log_info() { log_message "INFO" "$1"; }
log_warn() { log_message "WARN" "$1"; }
log_error() { log_message "ERROR" "$1"; }
log_success() { log_message "SUCCESS" "$1"; }

# --- Configuration Validation ---
# Legacy validate_config function - now handled by validation.sh module
# This function is kept for backward compatibility
validate_config() {
    validate_config_detailed "$1"
}

# --- Health Monitoring ---
# Check tunnel health
check_tunnel_health() {
    local tunnel_name="$1"
    local service_name="backhaul-$tunnel_name"
    local health_status="unknown"
    
    # Check if systemd service is running
    if systemctl is-active --quiet "$service_name" 2>/dev/null; then
        health_status="running"
    elif systemctl is-failed --quiet "$service_name" 2>/dev/null; then
        health_status="failed"
    elif systemctl is-enabled --quiet "$service_name" 2>/dev/null; then
        health_status="stopped"
    else
        health_status="not_started"
    fi
    
    # Check resource usage if running
    if [[ "$health_status" == "running" ]]; then
        # Get the main process PID from systemd
        local pid
        pid=$(systemctl show -p MainPID --value "$service_name" 2>/dev/null)
        
        if [[ -n "$pid" && "$pid" != "0" ]]; then
            local memory_usage
            memory_usage=$(ps -o rss= -p "$pid" 2>/dev/null | awk '{print $1}')
            local cpu_usage
            cpu_usage=$(ps -o %cpu= -p "$pid" 2>/dev/null | awk '{print $1}')
            
            # Log health metrics
            log_info "Tunnel $tunnel_name health: $health_status, Memory: ${memory_usage}KB, CPU: ${cpu_usage}%"
            
            # Check for resource issues
            if [[ -n "$memory_usage" && $memory_usage -gt 512000 ]]; then
                log_warn "High memory usage for tunnel $tunnel_name: ${memory_usage}KB"
            fi
            
            if [[ -n "$cpu_usage" && $(echo "$cpu_usage > 80" | bc -l 2>/dev/null) -eq 1 ]]; then
                log_warn "High CPU usage for tunnel $tunnel_name: ${cpu_usage}%"
            fi
        fi
    fi
    
    # Log health status
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "{\"timestamp\":\"$timestamp\",\"tunnel\":\"$tunnel_name\",\"status\":\"$health_status\"}" >> "$HEALTH_LOG_FILE"
    
    echo "$health_status"
}

# Monitor all tunnels health
monitor_all_tunnels() {
    local tunnels
    tunnels=$(find "$CONFIG_DIR" -name "*.conf" -exec basename {} .conf \; 2>/dev/null)
    
    for tunnel in $tunnels; do
        check_tunnel_health "$tunnel" &
    done
    
    wait
}

# --- Performance Tracking ---
# Track operation performance
track_performance() {
    local operation="$1"
    local start_time="$2"
    local end_time="$3"
    local success="$4"
    
    local duration=$((end_time - start_time))
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "{\"timestamp\":\"$timestamp\",\"operation\":\"$operation\",\"duration\":$duration,\"success\":$success}" >> "$PERFORMANCE_LOG_FILE"
    
    # Log slow operations
    if [[ $duration -gt 30 ]]; then
        log_warn "Slow operation detected: $operation took ${duration}s"
    fi
}

# Performance monitoring wrapper
with_performance_tracking() {
    local operation="$1"
    shift
    
    local start_time=$(date +%s)
    local success=false
    
    if "$@"; then
        success=true
    fi
    
    local end_time=$(date +%s)
    track_performance "$operation" "$start_time" "$end_time" "$success"
    
    return $([[ "$success" == "true" ]] && echo 0 || echo 1)
}

# --- Advanced Error Recovery ---
# Retry mechanism with exponential backoff
retry_operation() {
    local max_attempts="$1"
    local operation="$2"
    shift 2
    
    local attempt=1
    local delay=1
    
    while [[ $attempt -le $max_attempts ]]; do
        log_info "Attempting $operation (attempt $attempt/$max_attempts)"
        
        if "$@"; then
            log_success "$operation completed successfully"
            return 0
        fi
        
        if [[ $attempt -lt $max_attempts ]]; then
            log_warn "$operation failed, retrying in ${delay}s..."
            sleep "$delay"
            delay=$((delay * 2))  # Exponential backoff
        fi
        
        ((attempt++))
    done
    
    log_error "$operation failed after $max_attempts attempts"
    return 1
}

# Low-level graceful service restart with health check (called by UI wrapper)
graceful_restart() {
    local tunnel_name="$1"
    local max_attempts="${MAX_RESTART_ATTEMPTS:-3}"
    
    log_info "Starting graceful restart for tunnel $tunnel_name"
    
    # Stop service
    if systemctl stop "backhaul-$tunnel_name" 2>/dev/null; then
        log_info "Service stopped successfully"
    else
        log_warn "Service stop failed, attempting force stop"
        systemctl kill "backhaul-$tunnel_name" 2>/dev/null
        sleep 2
    fi
    
    # Wait for cooldown with progress indicator
    local cooldown="${RESTART_COOLDOWN:-10}"
    echo "Waiting ${cooldown}s for service to fully stop..."
    for i in $(seq 1 $cooldown); do
        echo -ne "\rCooldown: $i/$cooldown seconds [$(printf '%*s' $((i * 20 / cooldown)) | tr ' ' '#')$(printf '%*s' $((20 - i * 20 / cooldown)) | tr ' ' '-')]"
        sleep 1
    done
    echo -e "\nCooldown complete. Starting service..."
    
    # Start service with retry
    retry_operation "$max_attempts" "start tunnel $tunnel_name" systemctl start "backhaul-$tunnel_name"
    
    # Verify health
    echo "Waiting 5s for service to stabilize..."
    sleep 5
    local health_status
    health_status=$(check_tunnel_health "$tunnel_name")
    
    if [[ "$health_status" == "running" ]]; then
        log_success "Graceful restart completed successfully"
        return 0
    else
        log_error "Graceful restart failed - tunnel not healthy"
        return 1
    fi
}

# --- Resource Management ---
# Check system resources
check_system_resources() {
    local memory_usage
    memory_usage=$(free | awk '/^Mem:/ {printf "%.1f", $3/$2 * 100.0}')
    local cpu_usage
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    local disk_usage
    disk_usage=$(df / | awk 'NR==2 {print $5}' | cut -d'%' -f1)
    
    log_info "System resources - Memory: ${memory_usage}%, CPU: ${cpu_usage}%, Disk: ${disk_usage}%"
    
    # Check for resource issues
    if [[ $(echo "$memory_usage > 80" | bc -l 2>/dev/null) -eq 1 ]]; then
        log_warn "High memory usage detected: ${memory_usage}%"
    fi
    
    if [[ $(echo "$cpu_usage > 80" | bc -l 2>/dev/null) -eq 1 ]]; then
        log_warn "High CPU usage detected: ${cpu_usage}%"
    fi
    
    if [[ $disk_usage -gt 80 ]]; then
        log_warn "High disk usage detected: ${disk_usage}%"
    fi
}

# Optimize process priority
optimize_process_priority() {
    local tunnel_name="$1"
    local pid_file="/tmp/backhaul-$tunnel_name.pid"
    
    if [[ -f "$pid_file" ]]; then
        local pid
        pid=$(cat "$pid_file" 2>/dev/null)
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            renice "$PROCESS_PRIORITY" "$pid" 2>/dev/null
            log_info "Process priority optimized for tunnel $tunnel_name"
        fi
    fi
}

# --- Security Enhancements ---
# Secure file operations
secure_delete() {
    local file="$1"
    if [[ -f "$file" && "$TEMP_FILE_SECURE_DELETE" == "true" ]]; then
        # Overwrite with random data before deletion
        dd if=/dev/urandom of="$file" bs=1M count=1 2>/dev/null
        shred -u "$file" 2>/dev/null || rm -f "$file"
        log_debug "Securely deleted file: $file"
    else
        rm -f "$file"
    fi
}

# Set secure file permissions
set_secure_permissions() {
    local file="$1"
    if [[ "$FILE_PERMISSIONS_STRICT" == "true" ]]; then
        chmod 600 "$file" 2>/dev/null
        log_debug "Set secure permissions for: $file"
    fi
}

# --- Unified Error Handling ---
# Enhanced error handling with logging and recovery
handle_error() {
    local error_msg="$1"
    local return_code="${2:-1}"
    local operation="${3:-unknown}"
    
    log_error "Error in $operation: $error_msg"
    print_error "$error_msg"
    
    # Attempt recovery if enabled
    if [[ "$ERROR_RECOVERY_ENABLED" == "true" ]]; then
        attempt_error_recovery "$operation" "$error_msg"
    fi
    
    return "$return_code"
}

# Error recovery attempts
attempt_error_recovery() {
    local operation="$1"
    local error_msg="$2"
    
    case "$operation" in
        "tunnel_start")
            log_info "Attempting tunnel recovery..."
            cleanup_zombie_processes
            ;;
        "config_validation")
            log_info "Attempting config recovery..."
            restore_config_backup
            ;;
        *)
            log_info "No specific recovery for operation: $operation"
            ;;
    esac
}

# Restore configuration backup
restore_config_backup() {
    local tunnel_name="$1"
    local backup_file="$BACKUP_DIR/$tunnel_name.conf.backup"
    
    if [[ -f "$backup_file" ]]; then
        cp "$backup_file" "$CONFIG_DIR/$tunnel_name.conf"
        log_info "Configuration restored from backup"
        return 0
    else
        log_warn "No backup found for configuration"
        return 1
    fi
}

# --- Unified Success Handling ---
handle_success() {
    local success_msg="$1"
    local operation="${2:-unknown}"
    
    log_info "Success in $operation: $success_msg"
    print_success "$success_msg"
    return 0
}

# --- Unified Default Value Handling ---
get_default_value() {
    local user_input="$1"
    local default_value="$2"
    if [[ -z "$user_input" ]]; then
        echo "$default_value"
    else
        echo "$user_input"
    fi
}

# --- Unified Yes/No Prompt Handling ---
confirm_action() {
    local prompt="$1"
    local default="${2:-y}"
    local user_input
    read -p "$prompt (y/n) [$default]: " user_input
    user_input=$(get_default_value "$user_input" "$default")
    [[ "${user_input,,}" == "y" ]]
}

# --- Unified Configuration File Update Function ---
update_config_value() {
    local config_file="$1"
    local key="$2"
    local value="$3"
    
    # Create backup if enabled
    if [[ "$CONFIG_BACKUP_ON_CHANGE" == "true" ]]; then
        local backup_file="${config_file}.backup.$(date +%Y%m%d-%H%M%S)"
        cp "$config_file" "$backup_file" 2>/dev/null
        log_debug "Configuration backup created: $backup_file"
    fi
    
    # Remove existing line if it exists
    sed -i "/^${key}[[:space:]]*=/d" "$config_file"
    # Add new line
    echo "${key} = \"${value}\"" >> "$config_file"
    
    # Set secure permissions
    set_secure_permissions "$config_file"
}

# --- Unified Configuration File Update Function for Numeric Values ---
update_config_numeric() {
    local config_file="$1"
    local key="$2"
    local value="$3"
    
    # Create backup if enabled
    if [[ "$CONFIG_BACKUP_ON_CHANGE" == "true" ]]; then
        local backup_file="${config_file}.backup.$(date +%Y%m%d-%H%M%S)"
        cp "$config_file" "$backup_file" 2>/dev/null
        log_debug "Configuration backup created: $backup_file"
    fi
    
    # Remove existing line if it exists
    sed -i "/^${key}[[:space:]]*=/d" "$config_file"
    # Add new line
    echo "${key} = ${value}" >> "$config_file"
    
    # Set secure permissions
    set_secure_permissions "$config_file"
}

# --- Unified Menu Header Function ---
print_menu_header() {
    local title="$1"
    local subtitle="$2"
    clear
    print_server_info_banner
    print_info "      $title"
    print_info "================================================================"
    if [[ -n "$subtitle" ]]; then
        print_info "  $subtitle"
        print_info "----------------------------------------------------------------"
    fi
}

# --- Unified Menu Footer Function ---
print_menu_footer() {
    print_info "----------------------------------------------------------------"
}

# --- Generate a Random Secret for Restart Watcher ---
generate_restart_secret() {
    tr -dc A-Za-z0-9 </dev/urandom | head -c 32 ; echo
}

# --- Check for Common Alternative Download Sources ---
check_alternative_sources() {
    local os="$1"
    local arch="$2"
    
    print_info "--- Alternative Download Sources ---"
    echo
    print_info "If GitHub is not accessible, you can try these alternative sources:"
    echo
    echo "1. Direct Binary Download:"
    echo "   - Download from: https://github.com/Musixal/Backhaul/releases"
    echo "   - Look for: backhaul_${os}_${arch}.tar.gz"
    echo "   - Upload to your server or use a file sharing service"
    echo
    echo "2. Mirror Sites (if available):"
    echo "   - Check if your VPS provider has GitHub mirrors"
    echo "   - Some providers offer internal mirrors for common tools"
    echo
    echo "3. Package Managers (if available):"
    echo "   - Check if Backhaul is available in your system's package manager"
    echo "   - Some distributions may have it in community repositories"
    echo
    echo "4. Manual Compilation:"
    echo "   - Clone from: https://github.com/Musixal/Backhaul"
    echo "   - Build using: cargo build --release"
    echo
    print_info "For local installation, you can:"
    echo "- Download the binary on another machine with GitHub access"
    echo "- Transfer it to this VPS using SCP, SFTP, or file sharing"
    echo "- Use the 'Local file installation' option in this script"
    echo
    press_any_key
}

# --- Ensure Netcat is Installed ---
ensure_netcat() {
    if ! command -v nc &>/dev/null; then
        print_warning "Netcat (nc) is not installed. Attempting to install..."
        if command -v apt-get &>/dev/null; then
            apt-get update && apt-get install -y netcat-openbsd || print_error_and_exit "Failed to install netcat."
        elif command -v yum &>/dev/null; then
            yum install -y nmap-ncat || print_error_and_exit "Failed to install netcat."
        else
            print_error_and_exit "Unsupported package manager. Please install netcat manually."
        fi
    fi
}

# --- Clean Up Zombie and Orphaned Processes ---
cleanup_zombie_processes() {
    local cleaned_count=0
    
    # Check for zombie processes
    local zombies
    zombies=$(ps aux | grep -E 'Z.*<defunct>' | grep -v grep | wc -l)
    if [[ $zombies -gt 0 ]]; then
        print_warning "Found $zombies zombie processes. Attempting cleanup..."
        
        # Try to reap zombies by sending SIGCHLD to init
        kill -CHLD 1 2>/dev/null
        sleep 1
        
        # Check if zombies remain
        local remaining_zombies
        remaining_zombies=$(ps aux | grep -E 'Z.*<defunct>' | grep -v grep | wc -l)
        if [[ $remaining_zombies -gt 0 ]]; then
            print_warning "Some zombie processes may remain. This is usually harmless."
        else
            print_success "Zombie processes cleaned up successfully."
        fi
        ((cleaned_count++))
    fi
    
    # Check for orphaned watcher processes
    local orphaned_watchers
    orphaned_watchers=$(pgrep -f "backhaul-watcher" 2>/dev/null | wc -l)
    if [[ $orphaned_watchers -gt 0 ]]; then
        print_warning "Found $orphaned_watchers orphaned watcher processes. Cleaning up..."
        
        # Kill orphaned watcher processes
        pkill -f "backhaul-watcher" 2>/dev/null
        
        # Wait for processes to terminate
        sleep 2
        
        # Force kill any remaining processes
        pkill -9 -f "backhaul-watcher" 2>/dev/null
        
        # Verify cleanup
        local remaining_orphaned
        remaining_orphaned=$(pgrep -f "backhaul-watcher" 2>/dev/null | wc -l)
        if [[ $remaining_orphaned -eq 0 ]]; then
            print_success "Orphaned watcher processes cleaned up successfully."
        else
            print_error "Failed to clean up all orphaned watcher processes."
        fi
        ((cleaned_count++))
    fi
    
    # Clean up orphaned PID files
    local orphaned_pid_files
    orphaned_pid_files=$(find /tmp -name "backhaul-watcher-*.pid" 2>/dev/null | wc -l)
    if [[ $orphaned_pid_files -gt 0 ]]; then
        print_info "Cleaning up orphaned PID files..."
        find /tmp -name "backhaul-watcher-*.pid" -exec rm -f {} \; 2>/dev/null
        print_success "Orphaned PID files cleaned up."
        ((cleaned_count++))
    fi
    
    # Clean up orphaned temporary files
    local orphaned_temp_files
    orphaned_temp_files=$(find /tmp -name "restart_ack_*" 2>/dev/null | wc -l)
    if [[ $orphaned_temp_files -gt 0 ]]; then
        print_info "Cleaning up orphaned temporary files..."
        find /tmp -name "restart_ack_*" -exec rm -f {} \; 2>/dev/null
        print_success "Orphaned temporary files cleaned up."
        ((cleaned_count++))
    fi
    
    if [[ $cleaned_count -eq 0 ]]; then
        print_success "No zombie or orphaned processes found."
    fi
    
    return 0
}

# --- Generate Self-Signed Certificate ---
generate_self_signed_cert() {
    clear
    print_info "--- TLS Certificate Management ---"
    local CERT_DIR="/etc/backhaul/certs"
    mkdir -p "$CERT_DIR"
    chmod 700 "$CERT_DIR"

    # Check for openssl
    if ! command -v openssl &>/dev/null; then
        print_warning "OpenSSL is not installed. Attempting to install..."
        if command -v apt-get &>/dev/null; then
            apt-get update && apt-get install -y openssl || { print_error "Failed to install OpenSSL."; press_any_key; return 1; }
        elif command -v yum &>/dev/null; then
            yum install -y openssl || { print_error "Failed to install OpenSSL."; press_any_key; return 1; }
        else
            print_error "Unsupported package manager. Please install OpenSSL manually."; press_any_key; return 1;
        fi
    fi

    # List existing certs
    local existing_certs
    existing_certs=$(find "$CERT_DIR" -maxdepth 1 -name '*.crt' 2>/dev/null)
    if [ -n "$existing_certs" ]; then
        print_info "Existing certificates found in $CERT_DIR:"
        local i=1
        for cert in $existing_certs; do
            echo "  $i. $cert"
            ((i++))
        done
        echo "  0. Create a new certificate"
        read -p "Select a certificate to use [0-$((i-1))]: " cert_choice
        if [[ "$cert_choice" =~ ^[1-9][0-9]*$ ]] && [ "$cert_choice" -le $((i-1)) ]; then
            local chosen_cert
            chosen_cert=$(echo "$existing_certs" | sed -n "${cert_choice}p")
            local chosen_key="${chosen_cert%.crt}.key"
            print_success "Selected certificate: $chosen_cert"
            print_success "Associated key: $chosen_key"
            print_info "You can use these paths in the tunnel wizard for WSS/WSSMUX."
            press_any_key
            return 0
        fi
    fi

    # Generate new cert
    local timestamp
    timestamp=$(date +%Y%m%d-%H%M%S)
    local cert_path="$CERT_DIR/backhaul-$timestamp.crt"
    local key_path="$CERT_DIR/backhaul-$timestamp.key"
    read -p "Country (2 letter code) [US]: " country
    country=${country:-US}
    read -p "State or Province [State]: " state
    state=${state:-State}
    read -p "Locality (City) [City]: " city
    city=${city:-City}
    read -p "Organization [Org]: " org
    org=${org:-Org}
    read -p "Common Name (domain or IP) [${SERVER_IP}]: " cn
    cn=${cn:-$SERVER_IP}

    print_info "Generating private key..."
    openssl genpkey -algorithm RSA -out "$key_path" -pkeyopt rsa_keygen_bits:2048 || { print_error "OpenSSL key generation failed."; press_any_key; return 1; }
    chmod 600 "$key_path"
    print_info "Generating certificate signing request (CSR)..."
    openssl req -new -key "$key_path" -out /tmp/server.csr -subj "/C=$country/ST=$state/L=$city/O=$org/CN=$cn" || { print_error "OpenSSL CSR generation failed."; press_any_key; return 1; }
    print_info "Generating self-signed certificate..."
    openssl x509 -req -in /tmp/server.csr -signkey "$key_path" -out "$cert_path" -days 365 || { print_error "OpenSSL certificate generation failed."; press_any_key; return 1; }
    chmod 644 "$cert_path"
    rm -f /tmp/server.csr
    print_success "Certificate and key generated!"
    print_info "Certificate: $cert_path"
    print_info "Private Key: $key_path"
    print_info "You can now use these paths in the tunnel wizard for WSS/WSSMUX."
    press_any_key
}

# --- Show Help ---
show_help() {
    clear
    print_info "================= EasyBackhaul Help ================="
    print_info "General Usage:"
    echo "- This script helps you install, configure, and manage Backhaul tunnels."
    echo
    print_info "Main Menu Options:"
    echo "  1. Configure a New Tunnel: Launches a guided wizard to set up a new Backhaul tunnel (server or client)."
    echo "  2. Manage Existing Tunnels: Start, stop, restart, view logs, edit config, test, hot reload, or delete tunnels."
    echo "  3. Update/Re-install Backhaul Binary: Downloads and installs the latest Backhaul binary."
    echo "  4. Generate Self-Signed TLS Certificate: Creates a certificate for secure WebSocket (wss/wssmux) tunnels."
    echo "  5. Select Backhaul Binary Directory: Change the path to the Backhaul binary for this session."
    echo "  6. Uninstall EasyBackhaul: Removes all configs, binaries, services, and optionally certificates."
                    echo "  ?. Help: Shows this help screen."
    echo "  0. Exit: Quits the script."
    echo
    print_info "Tunnel Modes:"
    echo "- Server: Listens for connections (use on Iran VPS)."
    echo "- Client: Connects to a server (use on foreign VPS)."
    echo
    print_info "Transport Protocols:"
    echo "- tcp: Standard TCP tunnel."
    echo "- tcpmux: Multiplexed TCP (multiple connections over one port)."
    echo "- udp: UDP tunnel."
    echo "- ws: WebSocket (useful for CDN/Cloudflare)."
    echo "- wss: Secure WebSocket (TLS/SSL)."
    echo "- wsmux: Multiplexed WebSocket."
    echo "- wssmux: Multiplexed Secure WebSocket."
    echo
    print_info "Port Forwarding:"
    echo "- Simple format: 80,443,8000-8010 (single ports and ranges)"
    echo "- Advanced format: Use the Advanced Setup option in the wizard"
    echo
    print_info "Advanced Options:"
    echo "- sniffer: Enable traffic logging (true/false)"
    echo "- sniffer_log: Path to log file for sniffer"
    echo "- web_port: Port for web interface (0 to disable)"
    echo "- mux_con, mux_version, mux_framesize, mux_recievebuffer, mux_streambuffer: Multiplexing options for *mux transports"
    echo "- tls_cert, tls_key: Paths to TLS certificate and key for wss/wssmux"
    echo
    print_info "Hot Reload:"
    echo "- Use 'Hot Reload Config' in tunnel management to reload config without restart (if supported by Backhaul binary)."
    echo
    print_info "TLS Certificate Generation:"
    echo "- Use the main menu option to generate a self-signed certificate for wss/wssmux."
    echo
    print_info "Troubleshooting Tips:"
    echo "- If a tunnel does not start, check the logs (Manage Tunnels > View Logs)."
    echo "- Make sure required ports are open in your firewall (UFW)."
    echo "- Use the test connection option to verify connectivity."
    echo "- For advanced configuration, edit the config file directly and restart the service."
    echo
    print_info "Further Resources:"
    echo "- Project README: https://github.com/Musixal/Backhaul"
    echo "- Installer Issues: https://github.com/N4Xon/EasyBackhaul"
    echo
    print_info "For more details, see the README or project GitHub page."
}

# --- Spinner/Progress Indicator for Long-Running Operations ---
show_spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while kill -0 $pid 2>/dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        spinstr=$temp${spinstr%$temp}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# --- Usage: with_spinner "Description..." command args... ---
with_spinner() {
    local msg="$1"; shift
    echo -n "$msg... "
    "$@" &
    local pid=$!
    show_spinner $pid
    wait $pid
    local rc=$?
    if [ $rc -eq 0 ]; then
        print_success "Done."
    else
        print_error "Failed."
    fi
    return $rc
}

# =============================================================================
# SECURITY & PERFORMANCE OPTIMIZATIONS
# =============================================================================

# Input sanitization and validation
sanitize_input() {
    local input="$1"
    local max_length="${2:-100}"
    
    # Remove dangerous characters and limit length
    echo "$input" | sed 's/[<>"'\''&|;`$(){}[\]\\]/_/g' | head -c "$max_length"
}

validate_port() {
    local port="$1"
    if [[ ! "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        return 1
    fi
    return 0
}

validate_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -ra ADDR <<< "$ip"
        for i in "${ADDR[@]}"; do
            if [ "$i" -lt 0 ] || [ "$i" -gt 255 ]; then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

# Secure file operations
secure_write() {
    local file="$1"
    local content="$2"
    local temp_file
    
    temp_file=$(mktemp)
    echo "$content" > "$temp_file"
    
    # Set secure permissions before moving
    chmod 600 "$temp_file"
    mv "$temp_file" "$file"
    chmod 600 "$file"
}

secure_delete() {
    local file="$1"
    if [ -f "$file" ]; then
        # Overwrite with random data before deletion
        dd if=/dev/urandom of="$file" bs=1M count=1 2>/dev/null
        shred -u "$file" 2>/dev/null || rm -f "$file"
    fi
}

# Permission hardening
harden_permissions() {
    local dir="$1"
    
    # Set restrictive permissions on config and log directories
    if [ -d "$dir" ]; then
        chmod 700 "$dir"
        find "$dir" -type f -exec chmod 600 {} \;
        find "$dir" -type d -exec chmod 700 {} \;
    fi
}

secure_config_file() {
    local config_file="$1"
    
    if [ -f "$config_file" ]; then
        chmod 600 "$config_file"
        chown root:root "$config_file" 2>/dev/null || true
    fi
}

# Performance monitoring
get_system_resources() {
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    local mem_usage=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
    local disk_usage=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
    
    echo "CPU: ${cpu_usage}% | Memory: ${mem_usage}% | Disk: ${disk_usage}%"
}

monitor_performance() {
    local operation="$1"
    local start_time=$(date +%s.%N)
    
    # Execute the operation
    "$@"
    local exit_code=$?
    
    local end_time=$(date +%s.%N)
    local duration=$(echo "$end_time - $start_time" | bc -l 2>/dev/null || echo "0")
    
    log_message "PERFORMANCE" "$operation completed in ${duration}s"
    
    return $exit_code
}

# Resource optimization
optimize_memory_usage() {
    # Clear unnecessary caches
    sync
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
    
    # Log memory optimization
    log_message "PERFORMANCE" "Memory optimization completed"
}

cleanup_temp_files() {
    local temp_dir="/tmp"
    local pattern="easybackhaul_*"
    
    # Remove temporary files older than 1 hour
    find "$temp_dir" -name "$pattern" -mmin +60 -delete 2>/dev/null
    
    log_message "PERFORMANCE" "Temporary files cleanup completed"
}

# Security audit functions
audit_security() {
    local issues=()
    
    # Check file permissions
    if [ -f "$CONFIG_FILE" ] && [ "$(stat -c %a "$CONFIG_FILE" 2>/dev/null)" != "600" ]; then
        issues+=("Config file has insecure permissions")
    fi
    
    # Check for world-writable directories
    if find "$LOG_DIR" -type d -perm -002 2>/dev/null | grep -q .; then
        issues+=("Log directory has world-writable permissions")
    fi
    
    # Check for running processes as non-root
    if [ "$(id -u)" -eq 0 ] && pgrep -f "easybackhaul" | xargs ps -o user= 2>/dev/null | grep -v root | grep -q .; then
        issues+=("Some processes running as non-root user")
    fi
    
    if [ ${#issues[@]} -eq 0 ]; then
        echo "✓ Security audit passed"
        return 0
    else
        echo "⚠ Security issues found:"
        printf '%s\n' "${issues[@]}"
        return 1
    fi
}

# Rate limiting for operations
rate_limit_check() {
    local operation="$1"
    local max_per_minute="${2:-10}"
    local lock_file="/tmp/easybackhaul_rate_limit_${operation}.lock"
    
    # Check if rate limit exceeded
    if [ -f "$lock_file" ]; then
        local last_time=$(cat "$lock_file" 2>/dev/null || echo "0")
        local current_time=$(date +%s)
        local time_diff=$((current_time - last_time))
        
        if [ $time_diff -lt $((60 / max_per_minute)) ]; then
            return 1
        fi
    fi
    
    # Update rate limit timestamp
    echo "$(date +%s)" > "$lock_file"
    return 0
}

# Enhanced logging with security context
secure_log_message() {
    local level="$1"
    local message="$2"
    local user=$(whoami 2>/dev/null || echo "unknown")
    local ip=$(who am i | awk '{print $NF}' | sed 's/[()]//g' 2>/dev/null || echo "unknown")
    
    log_message "$level" "[$user@$ip] $message"
} 
# --- MODULE: modules/prereqs.sh ---
# prereqs.sh
# Root check and dependency installation logic

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
            with_spinner "Installing dependencies" apt-get update >/dev/null && apt-get install -y --no-install-recommends "${needs_install[@]}" >/dev/null
        elif command -v yum &> /dev/null; then
            with_spinner "Installing dependencies" yum install -y "${needs_install[@]}" >/dev/null
        else
            print_error_and_exit "Unsupported package manager. Please install '${needs_install[*]}' manually."
        fi
    fi
    print_success "All dependencies are satisfied."
}


# --- MODULE: modules/backhaul_core.sh ---
# backhaul_core.sh
# Download, install, and update Backhaul binary; get server info 

# --- Core Logic ---
SERVER_IP=""
SERVER_COUNTRY=""
SERVER_ISP=""

get_server_info() {
    local response
    response=$(curl -s --connect-timeout 5 http://ip-api.com/json)
    if [ $? -ne 0 ] || [ -z "$response" ]; then
        print_warning "Could not fetch server info from ip-api.com. Continuing without it."
        SERVER_IP="N/A"
        SERVER_COUNTRY="N/A"
        SERVER_ISP="N/A"
        return
    fi
    SERVER_IP=$(echo "$response" | jq -r '.query // "N/A"')
    SERVER_COUNTRY=$(echo "$response" | jq -r '.country // "N/A"')
    SERVER_ISP=$(echo "$response" | jq -r '.isp // "N/A"')
}

print_server_info_banner() {
    print_info "================================================================"
    print_info " Server IP: $SERVER_IP | Location: $SERVER_COUNTRY | ISP: $SERVER_ISP"
    print_info "================================================================"
}

# Verify binary installation
verify_binary_installation() {
    if [[ ! -f "$BIN_PATH" ]]; then
        print_error "Binary not found at expected location: $BIN_PATH"
        return 1
    fi
    
    if [[ ! -x "$BIN_PATH" ]]; then
        print_error "Binary is not executable. Attempting to fix permissions..."
        chmod +x "$BIN_PATH"
        if [[ ! -x "$BIN_PATH" ]]; then
            print_error "Failed to make binary executable."
            return 1
        fi
    fi
    
    # Test if binary works - try both -v and --version flags
    local version_output=""
    if "$BIN_PATH" -v >/dev/null 2>&1; then
        version_output=$("$BIN_PATH" -v 2>/dev/null | head -n1)
    elif "$BIN_PATH" --version >/dev/null 2>&1; then
        version_output=$("$BIN_PATH" --version 2>/dev/null | head -n1)
    else
        print_warning "Binary exists but version check failed."
        print_info "This might indicate an incompatible or corrupted binary."
        print_info "You can still try to use it, but some features might not work."
        return 1
    fi
    print_success "Binary verification successful: $version_output"
    return 0
}

# Test network connectivity to various sources
test_network_connectivity() {
    print_info "--- Network Connectivity Test ---"
    echo
    print_info "Testing connectivity to various sources..."
    echo
    
    local test_urls=(
        "https://api.github.com"
        "https://github.com"
        "https://google.com"
        "https://cloudflare.com"
    )
    
    local test_names=(
        "GitHub API"
        "GitHub Main"
        "Google (general internet)"
        "Cloudflare (CDN)"
    )
    
    for i in "${!test_urls[@]}"; do
        local url="${test_urls[$i]}"
        local name="${test_names[$i]}"
        
        print_info "Testing $name ($url)..."
        if curl -s --connect-timeout 5 --max-time 10 "$url" >/dev/null 2>&1; then
            print_success "✓ $name is accessible"
        else
            print_error "✗ $name is not accessible"
        fi
    done
    
    echo
    print_info "If GitHub is not accessible but other sites are, this might indicate:"
    echo "- GitHub is blocked in your region"
    echo "- Your VPS provider has restrictions"
    echo "- DNS resolution issues for GitHub"
    echo "- Firewall rules blocking GitHub"
    echo
    print_info "If all sites are inaccessible, check your VPS network configuration."
    echo
    press_any_key
}

download_backhaul() {
    print_info "--> Identifying system architecture..."
    local ARCH
    ARCH=$(uname -m)
    local OS
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')

    case $ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        *) print_error_and_exit "Unsupported architecture: $ARCH" ;;
    esac

    # Try to fetch latest version from GitHub
    print_info "--> Fetching latest version from GitHub..."
    local LATEST_VERSION_JSON
    local curl_exit_code
    LATEST_VERSION_JSON=$(curl -s --connect-timeout 10 "https://api.github.com/repos/Musixal/Backhaul/releases/latest")
    curl_exit_code=$?

    local LATEST_VERSION=""
    if [ $curl_exit_code -eq 0 ] && [ -n "$LATEST_VERSION_JSON" ]; then
        # Check if the response is valid JSON and contains tag_name
        if echo "$LATEST_VERSION_JSON" | jq -e . >/dev/null 2>&1; then
            LATEST_VERSION=$(echo "$LATEST_VERSION_JSON" | jq -r .tag_name)
            if [ -z "$LATEST_VERSION" ] || [ "$LATEST_VERSION" == "null" ]; then
                print_warning "Could not determine latest version from GitHub. Using fallback v0.6.6."
                LATEST_VERSION="v0.6.6"
            fi
        else
            print_warning "Invalid JSON response from GitHub API. Using fallback v0.6.6."
            LATEST_VERSION="v0.6.6"
        fi
    else
        print_warning "Failed to contact GitHub API. This might be due to network restrictions."
        echo
        print_info "GitHub access issues detected. Please choose an alternative method:"
        echo
        echo "1. Use local binary file (if you have downloaded it manually)"
        echo "2. Use alternative download source"
        echo "3. Use fallback version (v0.6.6) and try GitHub again"
        echo "4. Show alternative download sources and tips"
        echo "5. Test network connectivity"
        echo "6. Cancel installation"
        echo
        read -p "Select option [1-6]: " download_choice
        
        case $download_choice in
            1) download_from_local_file "$OS" "$ARCH" ;;
            2) download_from_alternative_source "$OS" "$ARCH" ;;
            3) 
                LATEST_VERSION="v0.6.6"
                download_from_github "$LATEST_VERSION" "$OS" "$ARCH"
                ;;
            4) 
                check_alternative_sources "$OS" "$ARCH"
                # After showing tips, ask again
                download_backhaul
                return 0
                ;;
            5) 
                test_network_connectivity
                # After testing, ask again
                download_backhaul
                return 0
                ;;
            6) 
                print_info "Installation cancelled."
                return 1
                ;;
            *) 
                print_error "Invalid option. Installation cancelled."
                return 1
                ;;
        esac
        return 0
    fi

    # If we got here, GitHub is accessible
    download_from_github "$LATEST_VERSION" "$OS" "$ARCH"
}

download_from_github() {
    local version="$1"
    local os="$2"
    local arch="$3"
    
    local download_url="https://github.com/Musixal/Backhaul/releases/download/${version}/backhaul_${os}_${arch}.tar.gz"
    print_info "--> Downloading Backhaul version ${version} from GitHub..."
    
    with_spinner "Downloading from GitHub" wget -q --show-progress --connect-timeout=15 --tries=3 --retry-connrefused -O /tmp/backhaul.tar.gz "$download_url"
    if [ $? -ne 0 ]; then
        print_error "GitHub download failed. Trying alternative methods..."
        echo
        print_info "GitHub download failed. Please choose an alternative method:"
        echo
        echo "1. Use local binary file (if you have downloaded it manually)"
        echo "2. Use alternative download source"
        echo "3. Cancel installation"
        echo
        read -p "Select option [1-3]: " fallback_choice
        
        case $fallback_choice in
            1) download_from_local_file "$os" "$arch" ;;
            2) download_from_alternative_source "$os" "$arch" ;;
            3) 
                print_info "Installation cancelled."
                return 1
                ;;
            *) 
                print_error "Invalid option. Installation cancelled."
                return 1
                ;;
        esac
        return 0
    fi

    install_downloaded_binary
}

download_from_local_file() {
    local os="$1"
    local arch="$2"
    
    print_info "--> Local file installation mode"
    echo
    print_info "Please provide the path to your local Backhaul binary file."
    print_info "Supported formats: .tar.gz, .zip, or direct binary file"
    echo
    print_info "Expected filename pattern: backhaul_${os}_${arch}.tar.gz"
    echo
    read -e -p "Enter path to local file: " local_file_path
    
    if [[ -z "$local_file_path" ]]; then
        print_error "No file path provided. Installation cancelled."
        return 1
    fi
    
    if [[ ! -f "$local_file_path" ]]; then
        print_error "File not found: $local_file_path"
        return 1
    fi
    
    # Determine file type and handle accordingly
    local file_extension
    file_extension=$(echo "$local_file_path" | sed 's/.*\.//' | tr '[:upper:]' '[:lower:]')
    
    case $file_extension in
        tar.gz|tgz)
            print_info "--> Detected .tar.gz file, copying to temporary location..."
            cp "$local_file_path" /tmp/backhaul.tar.gz
            ;;
        zip)
            print_info "--> Detected .zip file, extracting to temporary location..."
            if ! unzip -q "$local_file_path" -d /tmp/ 2>/dev/null; then
                print_error "Failed to extract .zip file. Please check if the file is valid."
                return 1
            fi
            # Look for the binary in the extracted contents
            if [[ -f "/tmp/backhaul" ]]; then
                # Create a tar.gz structure for consistency
                tar -czf /tmp/backhaul.tar.gz -C /tmp backhaul
                rm -f /tmp/backhaul
            else
                print_error "Could not find 'backhaul' binary in the extracted .zip file."
                rm -rf /tmp/backhaul*
                return 1
            fi
            ;;
        *)
            # Assume it's a direct binary file
            print_info "--> Detected direct binary file, creating archive structure..."
            if [[ -x "$local_file_path" ]] || [[ -f "$local_file_path" ]]; then
                # Create a tar.gz with the binary
                tar -czf /tmp/backhaul.tar.gz -C "$(dirname "$local_file_path")" "$(basename "$local_file_path")"
            else
                print_error "File is not executable or readable. Please check permissions."
                return 1
            fi
            ;;
    esac
    
    if [[ $? -ne 0 ]]; then
        print_error "Failed to prepare local file for installation."
        return 1
    fi
    
    install_downloaded_binary
}

download_from_alternative_source() {
    local os="$1"
    local arch="$2"
    
    print_info "--> Alternative download source mode"
    echo
    print_info "Please provide an alternative download URL for the Backhaul binary."
    print_info "The URL should point to a .tar.gz file containing the binary."
    echo
    print_info "Expected filename pattern: backhaul_${os}_${arch}.tar.gz"
    echo
    print_info "Example sources:"
    echo "- Your own server: https://your-server.com/backhaul_${os}_${arch}.tar.gz"
    echo "- Alternative CDN: https://cdn.example.com/backhaul_${os}_${arch}.tar.gz"
    echo "- Direct file server: http://files.example.com/backhaul_${os}_${arch}.tar.gz"
    echo
    read -p "Enter alternative download URL: " alt_url
    
    if [[ -z "$alt_url" ]]; then
        print_error "No URL provided. Installation cancelled."
        return 1
    fi
    
    print_info "--> Downloading from alternative source..."
    wget -q --show-progress --connect-timeout=15 --tries=3 --retry-connrefused -O /tmp/backhaul.tar.gz "$alt_url"
    
    if [[ $? -ne 0 ]]; then
        print_error "Alternative download failed. Please check the URL and try again."
        return 1
    fi
    
    install_downloaded_binary
}

install_downloaded_binary() {
    print_info "--> Extracting binary to $BIN_PATH..."
    
    # Check if the downloaded file is actually a tar.gz
    if ! tar -tzf /tmp/backhaul.tar.gz >/dev/null 2>&1; then
        print_error "The downloaded file is not a valid tar.gz archive."
        print_info "Please check your download source and try again."
        rm -f /tmp/backhaul.tar.gz
        return 1
    fi
    
    # Extract the binary
    tar -xzf /tmp/backhaul.tar.gz -C "$(dirname "$BIN_PATH")" "$(basename "$BIN_PATH")" 
    if [[ $? -ne 0 ]]; then
        print_error "Extraction failed. The archive might be corrupted or contain unexpected files."
        rm -f /tmp/backhaul.tar.gz
        return 1
    fi
    
    # Clean up and set permissions
    rm -f /tmp/backhaul.tar.gz
    chmod +x "$BIN_PATH"
    
    # Verify the binary works
    if verify_binary_installation; then
        print_success "Backhaul binary installation completed successfully!"
    else
        print_warning "Binary installation completed but verification failed."
        print_info "The binary might be incompatible or corrupted."
        print_info "You can still try to use it, but some features might not work correctly."
    fi
} 
# --- MODULE: modules/config.sh ---
# config.sh
# Validation functions, backup config, and tunnel configuration wizard

# --- Configuration & Validation ---
validate_port() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
validate_ip() { [[ "$1" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; }
validate_number() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -gt 0 ]; }

# Get process information for a port
get_port_process_info() {
    local port_to_check=$1
    local process_info=""
    
    # Try to get process info using ss
    if command -v ss >/dev/null 2>&1; then
        process_info=$(ss -lntup 2>/dev/null | grep ":${port_to_check}[[:space:]]" | head -1)
        if [[ -n "$process_info" ]]; then
            # Extract PID and process name
            local pid=$(echo "$process_info" | awk '{print $6}' | sed 's/.*pid=\([0-9]*\).*/\1/')
            if [[ -n "$pid" && "$pid" != "pid=" ]]; then
                local process_name=$(ps -p "$pid" -o comm= 2>/dev/null | head -1)
                local cmd_line=$(ps -p "$pid" -o cmd= 2>/dev/null | head -1 | cut -c1-60)
                echo "Process ID: $pid"
                echo "Process Name: $process_name"
                echo "Command: $cmd_line..."
                return
            fi
        fi
    fi
    
    # Fallback to netstat if ss doesn't work
    if command -v netstat >/dev/null 2>&1; then
        process_info=$(netstat -tlnp 2>/dev/null | grep ":${port_to_check}[[:space:]]" | head -1)
        if [[ -n "$process_info" ]]; then
            local pid=$(echo "$process_info" | awk '{print $7}' | cut -d'/' -f1)
            if [[ -n "$pid" && "$pid" != "-" ]]; then
                local process_name=$(ps -p "$pid" -o comm= 2>/dev/null | head -1)
                local cmd_line=$(ps -p "$pid" -o cmd= 2>/dev/null | head -1 | cut -c1-60)
                echo "Process ID: $pid"
                echo "Process Name: $process_name"
                echo "Command: $cmd_line..."
                return
            fi
        fi
    fi
    
    # If we can't get detailed info, show basic port usage
    echo "Port is in use but process details unavailable"
}

# Unified port checking function - uses 'ss' as it's more modern and available on most systems
check_port_availability() {
    local port_to_check=$1
    if ss -lntu 2>/dev/null | awk '{print $5}' | grep -q ":${port_to_check}$"; then
        print_error "Port ${port_to_check} is already in use by another service."
        print_info "Process information:"
        get_port_process_info "$port_to_check"
        return 1
    else
        return 0
    fi
}

backup_config() {
    local config_file="$1"
    if [ -f "$config_file" ]; then
        mkdir -p "$BACKUP_DIR"
        local backup_path="$BACKUP_DIR/$(basename "$config_file").bak.$(date +%F_%T)"
        print_info "--> Backing up current configuration to $backup_path"
        if ! cp "$config_file" "$backup_path"; then
            print_warning "Failed to backup $config_file to $backup_path. Please check permissions."
        fi
    fi
}

configure_new_tunnel() {
    clear
    print_server_info_banner
    print_info "=========================================="
    print_info "      VPN Tunnel Configuration Wizard"
    print_info "=========================================="
    print_info "This wizard helps you set up a VPN tunnel between:"
    print_info "  • Iran Server: Relay/exit point (users connect here)"
    print_info "  • Foreign Server: VPN panel hosting (tunnel destination)"
    print_info "Users connect to Iran server → Traffic forwarded to foreign server VPN panel"

    # --- Step 1: Setup Type ---
    print_info "\nChoose your setup preference:"
    print_info "1. Quick Setup (recommended) - Uses sensible defaults for most settings"
    print_info "2. Advanced Setup - Configure all settings manually"
    print_info "0. Back to Main Menu"
    
    local setup_type
    while true; do
        read -p "Select setup type [1-2, 0] (default: 1): " setup_type
        setup_type=${setup_type:-1}
        case $setup_type in
            1|2) break ;;
            0) return ;;
            *) print_warning "Invalid selection." ;;
        esac
    done

    # --- Step 2: Mode ---
    local mode_choice
    local default_mode
    if [[ "$SERVER_COUNTRY" == "Iran" ]]; then
        default_mode="1"
        print_info "\nDetected server location: Iran (defaulting to Server mode)"
    else
        default_mode="2"
        print_info "\nDetected server location: $SERVER_COUNTRY (defaulting to Client mode)"
    fi
    while true; do
        echo
        print_info "1. Server (Listens for connections)"
        print_info "2. Client (Connects to a server)"
        print_info "0. Back to Main Menu"
        read -p "Select mode [1-2, 0] (default: $default_mode): " mode_choice
        mode_choice=${mode_choice:-$default_mode}
        case $mode_choice in
            1) INSTALL_MODE="server"; break ;;
            2) INSTALL_MODE="client"; break ;;
            0) return ;;
            *) print_warning "Invalid selection." ;;
        esac
    done

    # --- Step 3: Transport Protocol (Simplified) ---
    print_info "\nSelect transport protocol:"
    if [[ $setup_type -eq 1 ]]; then
        # Quick setup - simplified options
        print_info "1. TCP (recommended) - Standard, reliable, works everywhere"
        print_info "2. WebSocket (WS) - Good for bypassing firewalls"
        print_info "3. Secure WebSocket (WSS) - Encrypted, most secure"
        print_info "4. Show all options"
        
        local transport_choice
        while true; do
            read -p "Select transport [1-4] (default: 1): " transport_choice
            transport_choice=${transport_choice:-1}
            case $transport_choice in
                1) TRANSPORT="tcp"; break ;;
                2) TRANSPORT="ws"; break ;;
                3) TRANSPORT="wss"; break ;;
                4) 
                    # Show all options
                    print_info "\nAll transport options:"
                    print_info "1. tcp - Standard TCP (recommended)"
                    print_info "2. tcpmux - Multiplexed TCP"
                    print_info "3. udp - UDP"
                    print_info "4. ws - WebSocket"
                    print_info "5. wsmux - Multiplexed WebSocket"
                    print_info "6. wss - Secure WebSocket"
                    print_info "7. wssmux - Multiplexed Secure WebSocket"
                    read -p "Select transport [1-7] (default: 1): " transport_choice
                    transport_choice=${transport_choice:-1}
                    local transport_options=("tcp" "tcpmux" "udp" "ws" "wsmux" "wss" "wssmux")
                    if [[ "$transport_choice" =~ ^[1-7]$ ]]; then
                        TRANSPORT="${transport_options[$((transport_choice-1))]}"
                        break
                    else
                        print_warning "Invalid selection."
                    fi
                    ;;
                *) print_warning "Invalid selection." ;;
            esac
        done
    else
        # Advanced setup - show all options
        print_info "Available transports:"
        local transport_options=("tcp" "tcpmux" "udp" "ws" "wsmux" "wss" "wssmux")
        local transport_descriptions=(
            "Standard TCP - Fast and reliable"
            "Multiplexed TCP - Multiple connections over single TCP"
            "UDP - For UDP-specific applications"
            "WebSocket - Good for bypassing firewalls"
            "Multiplexed WebSocket - Multiple connections over WS"
            "Secure WebSocket - Encrypted with TLS"
            "Multiplexed Secure WebSocket - Multiple connections over WSS"
        )
        
        local i=1
        for t in "${transport_options[@]}"; do
            echo "  $i) $t - ${transport_descriptions[$((i-1))]}"
            ((i++))
        done
        
        while true; do
            read -p "Select transport protocol [1-${#transport_options[@]}]: " transport_choice
            if [[ "$transport_choice" =~ ^[1-7]$ ]]; then
                TRANSPORT="${transport_options[$((transport_choice-1))]}"
                break
            else
                print_warning "Invalid selection. Enter a number 1-${#transport_options[@]}."
            fi
        done
    fi

    # --- Step 4: Basic Configuration ---
    print_info "\n--- Basic Configuration ---"
    local tunnel_port server_ip token forwarded_ports_input
    if [[ "$INSTALL_MODE" == "server" ]]; then
        local default_tunnel_port=443
        while true; do
            read -p "Enter the main tunnel port to listen on [${default_tunnel_port}]: " tunnel_port
            tunnel_port=${tunnel_port:-$default_tunnel_port}
            if ! validate_port "$tunnel_port"; then
                print_warning "Invalid port number."
            elif ! check_port_availability "$tunnel_port"; then
                read -p "Port $tunnel_port is in use. Auto-select a free port? (y/n): " autoport
                if [[ "${autoport,,}" == "y" ]]; then
                    for p in $(seq 20000 1 65000); do
                        if check_port_availability "$p"; then
                            tunnel_port="$p"
                            print_success "Selected free port: $tunnel_port"
                            break
                        fi
                    done
                    break
                else
                    continue
                fi
            else
                break
            fi
        done
        
        # VPN-focused port forwarding configuration
        print_info "\n--- VPN Panel Port Forwarding Configuration ---"
        print_info "This forwards ports from Iran server to your VPN panel on the foreign server."
        print_info "Users will connect to these ports on the Iran server to access your VPN panel."
        print_info "Common VPN panel ports:"
        print_info "  • 80,443 - Web panel (HTTP/HTTPS)"
        print_info "  • 8080,8443 - Alternative web panel ports"
        print_info "  • 1194,500,4500 - VPN protocols (OpenVPN, IPSec)"
        print_info "  • 1080,1081 - SOCKS proxy"
        
        while true; do
            read -p "How do you want to configure port forwarding? 1) Simple (recommended) 2) Advanced [1/2]: " pf_mode
            pf_mode=${pf_mode:-1}
            if [[ "$pf_mode" == "1" ]]; then
                # Simple mode - just ask for VPN panel ports to expose
                while true; do
                    read -p "Enter VPN panel ports to expose (e.g., 80,443,8080): " local_ports
                    if [[ -n "$local_ports" ]]; then
                        break
                    else
                        print_warning "Please enter at least one port."
                    fi
                done
                break
            elif [[ "$pf_mode" == "2" ]]; then
                # Advanced mode - for complex VPN setups
                print_info "\n--- Advanced VPN Port Forwarding (Guided) ---"
                print_info "This mode allows custom port mapping for complex VPN setups."
                print_info "Most users should use Simple mode. Only use Advanced if you need:"
                print_info "  • Different ports on Iran vs foreign server"
                print_info "  • Multiple VPN panels on different IPs"
                print_info "  • Custom routing scenarios"
                print_info "Example: 443=8443 (Iran port 443 → foreign port 8443)"
                
                local pf_rules=()
                while true; do
                    print_info "\n--- Add Advanced VPN Port Forwarding Rule ---"
                    
                    # Local port (Iran server port)
                    while true; do
                        read -p "Iran server port to listen on [443]: " local_port
                        if [[ "$local_port" == "?" || "$local_port" == "h" ]]; then
                            print_info "This is the port on Iran server that users will connect to"
                            print_info "Common ports: 80 (HTTP), 443 (HTTPS), 8080, 8443"
                            continue
                        fi
                        local_port=${local_port:-443}
                        if ! validate_port "$local_port"; then
                            print_warning "Invalid port number."
                            continue
                        fi
                        break
                    done
                    
                    # Remote port (Foreign server VPN panel port)
                    while true; do
                        read -p "Foreign server VPN panel port [443]: " remote_port
                        if [[ "$remote_port" == "?" || "$remote_port" == "h" ]]; then
                            print_info "This is the port on your foreign server where VPN panel is running"
                            print_info "Common ports: 80 (HTTP), 443 (HTTPS), 8080, 8443"
                            continue
                        fi
                        remote_port=${remote_port:-443}
                        if ! validate_port "$remote_port"; then
                            print_warning "Invalid port number."
                            continue
                        fi
                        break
                    done
                    
                    # Remote IP (optional - for multiple VPN panels)
                    print_info "Remote IP (optional):"
                    print_info "  • Leave blank = forward to foreign server (recommended)"
                    print_info "  • Specific IP = forward to different server (multiple VPN panels)"
                    read -p "Forward to specific remote IP? (leave blank for foreign server): " remote_ip
                    if [[ "$remote_ip" == "?" || "$remote_ip" == "h" ]]; then
                        print_info "Leave blank to forward to the foreign server - recommended for most users"
                        print_info "Or enter a specific IP if you have multiple VPN panels on different servers"
                        continue
                    fi
                    if [[ -n "$remote_ip" ]] && ! validate_ip "$remote_ip"; then
                        print_warning "Invalid IP address format."
                        continue
                    fi
                    
                    # Build the rule
                    local rule="$local_port"
                    if [[ -n "$remote_ip" && -n "$remote_port" ]]; then
                        rule+="=$remote_ip:$remote_port"
                    elif [[ -n "$remote_port" ]]; then
                        rule+="=$remote_port"
                    fi
                    
                    pf_rules+=("$rule")
                    print_success "Added rule: $rule (Iran:$local_port → Foreign:$remote_port)"
                    
                    read -p "Add another rule? (y/n) [n]: " another
                    another=${another:-n}
                    if [[ "${another,,}" != "y" ]]; then break; fi
                done
                
                # Combine all rules
                if [[ ${#pf_rules[@]} -gt 0 ]]; then
                    forwarded_ports_input=$(IFS=, ; echo "${pf_rules[*]}")
                    print_info "\nFinal VPN port forwarding configuration:"
                    local idx=1
                    for r in "${pf_rules[@]}"; do
                        echo "  $idx. $r"
                        ((idx++))
                    done
                else
                    # Default to common VPN web panel ports if no rules added
                    forwarded_ports_input="80,443"
                    print_info "\nNo rules added. Using default VPN web panel ports: 80,443"
                fi
                break
            else
                print_warning "Invalid selection."
            fi
        done
    else # client
        print_info "\n--- Foreign Server Configuration ---"
        print_info "This foreign server will connect to Iran server to provide VPN panel access."
        print_info "Users will connect to Iran server, which forwards traffic to this foreign server."
        
        while true; do
            read -p "Enter the public IP address of the Iran server: " server_ip
            validate_ip "$server_ip" && break || print_warning "Invalid IP address format."
        done
        
        # Optional: Offer to ping the server IP
        read -p "Do you want to ping the Iran server IP to check connectivity? (y/n) [y]: " do_ping
        do_ping=${do_ping:-y}
        if [[ "${do_ping,,}" == "y" ]]; then
            print_info "Pinging $server_ip..."
            if ping -c 2 -W 2 "$server_ip" >/dev/null 2>&1; then
                print_success "Ping successful! Iran server is reachable."
            else
                print_warning "Ping failed. The Iran server may be offline or unreachable."
            fi
        fi
        
        while true; do
            local default_tunnel_port=443
            read -p "Enter the tunnel port set on the Iran server [${default_tunnel_port}]: " tunnel_port
            tunnel_port=${tunnel_port:-$default_tunnel_port}
            if ! validate_port "$tunnel_port"; then
                print_warning "Invalid port number."
            elif ! check_port_availability "$tunnel_port"; then
                read -p "Port $tunnel_port is in use. Auto-select a free port? (y/n): " autoport
                if [[ "${autoport,,}" == "y" ]]; then
                    for p in $(seq 20000 1 65000); do
                        if check_port_availability "$p"; then
                            tunnel_port="$p"
                            print_success "Selected free port: $tunnel_port"
                            break
                        fi
                    done
                    break
                else
                    continue
                fi
            else
                break
            fi
        done
    fi

    # Token prompt (same for both server and client)
    local default_token="vpn-tunnel-naxon"
    while true; do
        read -p "Enter a secure authentication token [default: $default_token, must match on both sides]: " token
        # Use default token if input is empty
        token=${token:-$default_token}
        if [[ -n "$token" ]]; then
            break
        else
            print_warning "Token cannot be empty."
        fi
    done

    # --- Step 5: Advanced Configuration (Conditional) ---
    local log_level="info" nodelay="true" keepalive_period=75
    local heartbeat=40 connection_pool=8 retry_interval=3 dial_timeout=10
    local tls_cert="" tls_key="" edge_ip=""
    local mux_version=1 mux_framesize=32768 mux_recievebuffer=4194304 mux_streambuffer=65536
    local mux_con=8 accept_udp="false" channel_size=2048 aggressive_pool="false"
    local sniffer="false" sniffer_log="/root/backhaul.json" web_port=0
    
    if [[ $setup_type -eq 2 ]]; then
        # Advanced setup - ask for all settings
        print_info "\n--- Advanced & Transport-Specific Configuration ---"
        while true; do
            read -p "Log Level (debug, info, warn, error) [info]: " log_level
            log_level=${log_level:-info}
            break
        done
        while true; do
            read -p "Enable sniffer (traffic logging)? [false]: " sniffer
            sniffer=${sniffer:-false}
            break
        done
        if [[ "$sniffer" == "true" ]]; then
            while true; do
                read -p "Sniffer log file path [/root/backhaul.json]: " sniffer_log
                sniffer_log=${sniffer_log:-/root/backhaul.json}
                break
            done
        fi
        while true; do
            read -p "Web interface port (0 to disable) [0]: " web_port
            web_port=${web_port:-0}
            break
        done

        if [[ "$TRANSPORT" != "udp" ]]; then
            while true; do
                read -p "Enable TCP_NODELAY for lower latency? [true]: " nodelay
                nodelay=${nodelay:-true}
                break
            done
            while true; do
                read -p "Keep-alive period in seconds [75]: " keepalive_period
                keepalive_period=${keepalive_period:-75}
                break
            done
        fi
        
        if [[ "$INSTALL_MODE" == "server" ]]; then
            while true; do
                read -p "Heartbeat interval in seconds [40]: " heartbeat
                heartbeat=${heartbeat:-40}
                break
            done
            while true; do
                read -p "Channel size [2048]: " channel_size
                channel_size=${channel_size:-2048}
                break
            done
            if [[ "$TRANSPORT" == "tcp" ]]; then
                while true; do
                    read -p "Accept UDP traffic over TCP? [false]: " accept_udp
                    accept_udp=${accept_udp:-false}
                    break
                done
            fi
        else # client
            while true; do
                read -p "Connection pool size [8]: " connection_pool
                connection_pool=${connection_pool:-8}
                break
            done
            while true; do
                read -p "Enable aggressive pool management? [false]: " aggressive_pool
                aggressive_pool=${aggressive_pool:-false}
                break
            done
            while true; do
                read -p "Connection retry interval in seconds [3]: " retry_interval
                retry_interval=${retry_interval:-3}
                break
            done
            while true; do
                read -p "Connection dial timeout in seconds [10]: " dial_timeout
                dial_timeout=${dial_timeout:-10}
                break
            done
        fi

        if [[ "$TRANSPORT" == *"mux"* ]]; then
            print_info "\n--- Multiplexing (MUX) Parameters ---"
            while true; do 
                read -p "Multiplexing concurrency [8]: " mux_con
                mux_con=${mux_con:-8}
                if [[ "$mux_con" =~ ^[0-9]+$ ]]; then
                    break
                else
                    print_error "Must be a positive number."
                fi
            done
            while true; do 
                read -p "SMUX protocol version (1 or 2) [1]: " mux_version
                mux_version=${mux_version:-1}
                if [[ "$mux_version" =~ ^[12]$ ]]; then
                    break
                else
                    print_error "Must be 1 or 2."
                fi
            done
            while true; do 
                read -p "Mux frame size (bytes) [32768]: " mux_framesize
                mux_framesize=${mux_framesize:-32768}
                if [[ "$mux_framesize" =~ ^[0-9]+$ ]]; then
                    break
                else
                    print_error "Must be a positive number."
                fi
            done
            while true; do 
                read -p "Mux receive buffer (bytes) [4194304]: " mux_recievebuffer
                mux_recievebuffer=${mux_recievebuffer:-4194304}
                if [[ "$mux_recievebuffer" =~ ^[0-9]+$ ]]; then
                    break
                else
                    print_error "Must be a positive number."
                fi
            done
            while true; do 
                read -p "Mux stream buffer (bytes) [65536]: " mux_streambuffer
                mux_streambuffer=${mux_streambuffer:-65536}
                if [[ "$mux_streambuffer" =~ ^[0-9]+$ ]]; then
                    break
                else
                    print_error "Must be a positive number."
                fi
            done

            if [[ "$TRANSPORT" == "ws"* && "$INSTALL_MODE" == "client" ]]; then
                print_info "\n--- WebSocket Parameters ---"
                while true; do
                    read -p "Edge IP for CDN connection (optional, press Enter to skip): " edge_ip
                    if [[ -z "$edge_ip" ]]; then
                        break
                    fi
                    break
                done
            fi
        fi
    fi

    if [[ "$TRANSPORT" == "wss"* && "$INSTALL_MODE" == "server" ]]; then
        print_info "\n--- Secure WebSocket (WSS) Certificate Setup ---"
        print_warning "This requires a valid TLS certificate and key."
        local CERT_DIR="/etc/backhaul/certs"
        mkdir -p "$CERT_DIR"
        local newest_cert newest_key
        newest_cert=$(ls -1t "$CERT_DIR"/*.crt 2>/dev/null | head -n1)
        if [[ -n "$newest_cert" ]]; then
            newest_key="${newest_cert%.crt}.key"
            if [ -f "$newest_cert" ] && [ -f "$newest_key" ]; then
                print_info "Found existing certificate: $newest_cert"
                print_info "Associated key: $newest_key"
                read -p "Use this certificate? (Y/n/generate new/manual): " cert_choice
                case "${cert_choice,,}" in
                    ""|y|yes)
                        tls_cert="$newest_cert"
                        tls_key="$newest_key"
                        ;;
                    g|generate)
                        generate_self_signed_cert
                        newest_cert=$(ls -1t "$CERT_DIR"/*.crt 2>/dev/null | head -n1)
                        newest_key="${newest_cert%.crt}.key"
                        tls_cert="$newest_cert"
                        tls_key="$newest_key"
                        ;;
                    m|manual)
                        while true; do
                            read -e -p "Enter the full path to your TLS certificate file: " tls_cert
                            if [ -f "$tls_cert" ]; then break; else print_error "File not found. Please provide a valid path."; fi
                        done
                        while true; do
                            read -e -p "Enter the full path to your TLS private key file: " tls_key
                            if [ -f "$tls_key" ]; then break; else print_error "File not found. Please provide a valid path."; fi
                        done
                        ;;
                    *)
                        tls_cert="$newest_cert"
                        tls_key="$newest_key"
                        ;;
                esac
            else
                print_info "No valid certificate/key pair found. Generating a new one."
                generate_self_signed_cert
                newest_cert=$(ls -1t "$CERT_DIR"/*.crt 2>/dev/null | head -n1)
                newest_key="${newest_cert%.crt}.key"
                tls_cert="$newest_cert"
                tls_key="$newest_key"
            fi
        else
            print_info "No existing certificates found. Generating a new one."
            generate_self_signed_cert
            newest_cert=$(ls -1t "$CERT_DIR"/*.crt 2>/dev/null | head -n1)
            newest_key="${newest_cert%.crt}.key"
            tls_cert="$newest_cert"
            tls_key="$newest_key"
        fi
    fi

    # --- Step 6: Coordinated Restart on Error (Optional) ---
    if [[ $setup_type -eq 2 ]]; then
        print_info "\n--- Optional: Coordinated Restart on Error ---"
        read -p "Enable coordinated restart-on-error watcher for this tunnel? [n]: " enable_restart
        enable_restart=${enable_restart:-n}
        local restart_pattern restart_delay_local restart_delay_remote restart_secret restart_listen_port restart_remote_port
        if [[ "${enable_restart,,}" == "y" ]]; then
            read -p "Error pattern to trigger restart [ERROR|FATAL]: " restart_pattern
            restart_pattern=${restart_pattern:-ERROR|FATAL}
            read -p "Restart delay (seconds, local side) [10]: " restart_delay_local
            restart_delay_local=${restart_delay_local:-10}
            read -p "Restart delay (seconds, remote side) [10]: " restart_delay_remote
            restart_delay_remote=${restart_delay_remote:-10}
            read -p "Shared secret for restart coordination (leave blank to auto-generate): " restart_secret
            if [[ -z "$restart_secret" ]]; then
                restart_secret=$(generate_restart_secret)
                print_info "Generated secret: $restart_secret"
            fi
            # Prompt for watcher ports
            echo
            print_info "Configure watcher ports:"
            echo "  • Listen port: Where this side receives restart requests from remote"
            echo "  • Remote port: Where this side sends restart requests to remote"
            echo
            print_warning "IMPORTANT: The remote side must use the opposite ports!"
            echo "  If this side listens on 45679, remote must send to 45679"
            echo "  If this side sends to 45680, remote must listen on 45680"
            echo
            read -p "Watcher listen port (receive restart requests) [45679]: " restart_listen_port
            restart_listen_port=${restart_listen_port:-45679}
            read -p "Watcher remote port (send restart requests) [45680]: " restart_remote_port
            restart_remote_port=${restart_remote_port:-45680}
        fi
    else
        # Quick setup - skip restart watcher
        enable_restart="n"
    fi

    # --- Step 7: Build Config & Service ---
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
        config_content+="sniffer = $sniffer\n"
        config_content+="sniffer_log = \"$sniffer_log\"\n"
        config_content+="web_port = $web_port\n"
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
        
        # Add restart watcher config as TOML comments/keys
        config_content+="\n# Coordinated Restart Watcher\n"
        config_content+="restart_watcher_enabled = \"${enable_restart,,}\"\n"
        if [[ "${enable_restart,,}" == "y" ]]; then
            config_content+="restart_watcher_pattern = \"$restart_pattern\"\n"
            config_content+="restart_watcher_delay_local = $restart_delay_local\n"
            config_content+="restart_watcher_delay_remote = $restart_delay_remote\n"
            config_content+="restart_watcher_secret = \"$restart_secret\"\n"
            config_content+="restart_watcher_listen_port = $restart_listen_port\n"
            config_content+="restart_watcher_remote_port = $restart_remote_port\n"
        fi
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
        config_content+="sniffer = $sniffer\n"
        config_content+="sniffer_log = \"$sniffer_log\"\n"
        config_content+="web_port = $web_port\n"
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

    # Add restart watcher config for client mode
    if [[ "$INSTALL_MODE" == "client" ]]; then
        config_content+="\n# Coordinated Restart Watcher\n"
        config_content+="restart_watcher_enabled = \"${enable_restart,,}\"\n"
        if [[ "${enable_restart,,}" == "y" ]]; then
            config_content+="restart_watcher_pattern = \"$restart_pattern\"\n"
            config_content+="restart_watcher_delay_local = $restart_delay_local\n"
            config_content+="restart_watcher_delay_remote = $restart_delay_remote\n"
            config_content+="restart_watcher_secret = \"$restart_secret\"\n"
            config_content+="restart_watcher_listen_port = $restart_listen_port\n"
            config_content+="restart_watcher_remote_port = $restart_remote_port\n"
        fi
    fi

    # --- Step 8: Confirmation and Creation ---
    clear
    print_server_info_banner
    print_info "--- Configuration Summary ---"
    echo -e "$config_content"
    echo "---------------------------"
    read -p "Is this configuration correct? [y]: " confirm
    confirm=${confirm:-y}
    if [[ "${confirm,,}" != "y" ]]; then
        print_warning "Configuration cancelled. You can go back and edit your entries."
        press_any_key
        return 1
    fi

    mkdir -p "$CONFIG_DIR"
    local config_file="$CONFIG_DIR/config-${service_name_suffix}.toml"
    
    if [ -f "$config_file" ]; then
        print_warning "A configuration file for this tunnel already exists: $config_file"
        if confirm_action "Do you want to create a backup before overwriting?" "y"; then
            backup_config "$config_file"
            print_success "Backup created."
        fi
    fi

    echo -e "$config_content" > "$config_file"
    chmod 600 "$config_file"
    print_success "Configuration file created: $config_file"

    if [[ "$INSTALL_MODE" == "server" ]]; then
        manage_ufw_add "$tunnel_port" "$TRANSPORT" "$service_name_suffix"
        # Add UFW rule for watcher listen port if enabled
        if [[ "${enable_restart,,}" == "y" ]]; then
            manage_ufw_add "$restart_listen_port" "tcp" "${service_name_suffix}-watcher"
        fi
    fi

    create_systemd_service "$service_name_suffix" "$config_file"
}

update_config_file() {
    local tunnel_name="$1"
    local server_ip="$2"
    local server_port="$3"
    local local_port="$4"
    local protocol="$5"
    
    # Input validation
    if ! validate_ip "$server_ip" || ! validate_port "$server_port" || ! validate_port "$local_port"; then
        log_message "ERROR" "Invalid configuration parameters for tunnel $tunnel_name"
        return 1
    fi
    
    # Sanitize inputs
    tunnel_name=$(sanitize_input "$tunnel_name" 50)
    server_ip=$(sanitize_input "$server_ip" 15)
    server_port=$(sanitize_input "$server_port" 5)
    local_port=$(sanitize_input "$local_port" 5)
    protocol=$(sanitize_input "$protocol" 3)
    
    # Create config directory if it doesn't exist
    mkdir -p "$CONFIG_DIR"
    harden_permissions "$CONFIG_DIR"
    
    # Read existing config or create new one
    local temp_config=$(mktemp)
    if [ -f "$CONFIG_FILE" ]; then
        # Remove existing entry for this tunnel if it exists
        grep -v "^$tunnel_name=" "$CONFIG_FILE" > "$temp_config" 2>/dev/null || true
    fi
    
    # Add new tunnel entry
    echo "$tunnel_name=$server_ip:$server_port:$local_port:$protocol" >> "$temp_config"
    
    # Securely write the updated config
    secure_write "$CONFIG_FILE" "$(cat "$temp_config")"
    secure_config_file "$CONFIG_FILE"
    
    # Clean up temp file
    rm -f "$temp_config"
    
    secure_log_message "INFO" "Updated config for tunnel $tunnel_name"
}

remove_from_config() {
    local tunnel_name="$1"
    
    # Input sanitization
    tunnel_name=$(sanitize_input "$tunnel_name" 50)
    
    if [ ! -f "$CONFIG_FILE" ]; then
        return 0
    fi
    
    # Create temporary file with tunnel removed
    local temp_config=$(mktemp)
    grep -v "^$tunnel_name=" "$CONFIG_FILE" > "$temp_config" 2>/dev/null || true
    
    # Securely write the updated config
    secure_write "$CONFIG_FILE" "$(cat "$temp_config")"
    secure_config_file "$CONFIG_FILE"
    
    # Clean up temp file
    rm -f "$temp_config"
    
    secure_log_message "INFO" "Removed tunnel $tunnel_name from config"
}

backup_configuration() {
    echo ""
    echo "=== Backup Configuration ==="
    
    local backup_dir="$CONFIG_DIR/backups"
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    local backup_file="$backup_dir/easybackhaul_backup_$timestamp.tar.gz"
    
    # Create backup directory with secure permissions
    mkdir -p "$backup_dir"
    harden_permissions "$backup_dir"
    
    # Create backup
    tar -czf "$backup_file" -C "$CONFIG_DIR" . 2>/dev/null
    
    if [ $? -eq 0 ]; then
        # Set secure permissions on backup file
        chmod 600 "$backup_file"
        
        echo "✅ Configuration backed up to: $backup_file"
        echo "📊 Backup size: $(du -h "$backup_file" | cut -f1)"
        
        # List recent backups
        echo ""
        echo "Recent backups:"
        ls -la "$backup_dir"/*.tar.gz 2>/dev/null | tail -5 || echo "No previous backups found"
        
        secure_log_message "INFO" "Configuration backed up to $backup_file"
    else
        echo "❌ Backup failed"
        log_message "ERROR" "Configuration backup failed"
    fi
}

restore_configuration() {
    echo ""
    echo "=== Restore Configuration ==="
    
    local backup_dir="$CONFIG_DIR/backups"
    
    if [ ! -d "$backup_dir" ]; then
        echo "❌ No backup directory found"
        return 1
    fi
    
    # List available backups
    local backups=($(ls "$backup_dir"/*.tar.gz 2>/dev/null))
    
    if [ ${#backups[@]} -eq 0 ]; then
        echo "❌ No backup files found"
        return 1
    fi
    
    echo "Available backups:"
    for i in "${!backups[@]}"; do
        local backup_file="${backups[$i]}"
        local backup_name=$(basename "$backup_file")
        local backup_size=$(du -h "$backup_file" | cut -f1)
        local backup_date=$(stat -c %y "$backup_file" 2>/dev/null | cut -d' ' -f1)
        echo "$((i+1))) $backup_name ($backup_size, $backup_date)"
    done
    
    echo ""
    read -p "Select backup to restore (1-${#backups[@]}): " choice
    
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt ${#backups[@]} ]; then
        echo "❌ Invalid selection"
        return 1
    fi
    
    local selected_backup="${backups[$((choice-1))]}"
    
    echo ""
    echo "⚠ WARNING: This will overwrite current configuration."
    echo "   Backup file: $selected_backup"
    read -p "Proceed with restore? (y/n): " confirm
    
    if [ "$confirm" != "y" ]; then
        echo "❌ Restore cancelled"
        return 1
    fi
    
    # Create temporary restore directory
    local temp_restore=$(mktemp -d)
    
    # Extract backup
    if tar -xzf "$selected_backup" -C "$temp_restore" 2>/dev/null; then
        # Validate extracted files
        if [ -f "$temp_restore/config" ]; then
            # Backup current config
            if [ -f "$CONFIG_FILE" ]; then
                cp "$CONFIG_FILE" "$CONFIG_FILE.bak.$(date '+%Y%m%d_%H%M%S')"
            fi
            
            # Restore files
            cp -r "$temp_restore"/* "$CONFIG_DIR/"
            
            # Set secure permissions
            harden_permissions "$CONFIG_DIR"
            secure_config_file "$CONFIG_FILE"
            
            echo "✅ Configuration restored successfully"
            secure_log_message "INFO" "Configuration restored from $selected_backup"
        else
            echo "❌ Invalid backup file (missing config)"
            log_message "ERROR" "Invalid backup file structure"
        fi
    else
        echo "❌ Failed to extract backup file"
        log_message "ERROR" "Backup extraction failed"
    fi
    
    # Clean up
    rm -rf "$temp_restore"
}

validate_configuration() {
    local config_file="$1"
    
    if [ ! -f "$config_file" ]; then
        return 1
    fi
    
    # Check file permissions
    local perms=$(stat -c %a "$config_file" 2>/dev/null)
    if [ "$perms" != "600" ]; then
        echo "⚠ Config file has insecure permissions: $perms"
        return 1
    fi
    
    # Validate syntax
    while IFS='=' read -r tunnel_name tunnel_config; do
        if [ -n "$tunnel_name" ] && [ -n "$tunnel_config" ]; then
            IFS=':' read -r server_ip server_port local_port protocol <<< "$tunnel_config"
            
            if ! validate_ip "$server_ip" || ! validate_port "$server_port" || ! validate_port "$local_port"; then
                echo "❌ Invalid configuration for tunnel $tunnel_name"
                return 1
            fi
        fi
    done < "$config_file"
    
    return 0
}


# --- MODULE: modules/validation.sh ---
# validation.sh
# Comprehensive configuration validation for all Backhaul protocols

# --- Configuration Validation ---
# Validate configuration file with protocol-specific checks
validate_config() {
    local config_file="$1"
    local errors=0
    local warnings=0
    
    if [[ ! -f "$config_file" ]]; then
        log_error "Configuration file not found: $config_file"
        return 1
    fi
    
    print_info "=== Configuration Validation ==="
    echo
    
    # Check for required sections
    local required_sections=("server" "client")
    local found_sections=()
    
    for section in "${required_sections[@]}"; do
        if grep -q "^\[$section\]" "$config_file"; then
            found_sections+=("$section")
        fi
    done
    
    if [[ ${#found_sections[@]} -eq 0 ]]; then
        log_error "Missing required section [server] or [client] in config file"
        ((errors++))
    else
        print_success "Found section(s): ${found_sections[*]}"
    fi
    
    # Check for basic syntax errors
    if ! grep -q "^\[.*\]\|^[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*=" "$config_file"; then
        log_error "Invalid configuration syntax in $config_file"
        ((errors++))
    fi
    
    # Validate port numbers
    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*port[[:space:]]*=[[:space:]]*([0-9]+) ]]; then
            local port="${BASH_REMATCH[1]}"
            if [[ $port -lt 1 || $port -gt 65535 ]]; then
                log_error "Invalid port number: $port (must be 1-65535)"
                ((errors++))
            fi
        fi
    done < "$config_file"
    
    # Protocol-specific validation
    validate_protocol_config "$config_file"
    local protocol_errors=$?
    errors=$((errors + protocol_errors))
    
    # Advanced validation checks
    validate_advanced_config "$config_file"
    local advanced_errors=$?
    local advanced_warnings=$?
    errors=$((errors + advanced_errors))
    warnings=$((warnings + advanced_warnings))
    
    if [[ $errors -gt 0 ]]; then
        log_error "Configuration validation failed with $errors error(s) and $warnings warning(s)"
        return 1
    fi
    
    if [[ $warnings -gt 0 ]]; then
        log_warn "Configuration validation passed with $warnings warning(s)"
    else
        log_info "Configuration validation passed"
    fi
    
    return 0
}

# Protocol-specific validation
validate_protocol_config() {
    local config_file="$1"
    local errors=0
    local transport=""
    
    # Detect transport protocol
    transport=$(grep '^transport[[:space:]]*=' "$config_file" | cut -d'"' -f2)
    
    if [[ -z "$transport" ]]; then
        print_error "Missing required 'transport' field"
        return 1
    fi
    
    print_info "--- Protocol Validation ($transport) ---"
    
    case "$transport" in
        "tcp")
            validate_tcp_config "$config_file"
            errors=$?
            ;;
        "tcpmux")
            validate_tcpmux_config "$config_file"
            errors=$?
            ;;
        "udp")
            validate_udp_config "$config_file"
            errors=$?
            ;;
        "ws")
            validate_ws_config "$config_file"
            errors=$?
            ;;
        "wss")
            validate_wss_config "$config_file"
            errors=$?
            ;;
        "wsmux")
            validate_wsmux_config "$config_file"
            errors=$?
            ;;
        "wssmux")
            validate_wssmux_config "$config_file"
            errors=$?
            ;;
        *)
            print_error "Unsupported transport protocol: $transport"
            return 1
            ;;
    esac
    
    return $errors
}

# TCP protocol validation
validate_tcp_config() {
    local config_file="$1"
    local errors=0
    
    # Check required fields
    if ! grep -q '^bind_addr\|^remote_addr' "$config_file"; then
        print_error "Missing required address field (bind_addr for server, remote_addr for client)"
        ((errors++))
    fi
    
    # Check optional but recommended fields
    if ! grep -q '^token' "$config_file"; then
        print_warning "No authentication token specified (recommended for security)"
    fi
    
    # Validate numeric fields
    validate_numeric_field "$config_file" "heartbeat" 1 3600
    validate_numeric_field "$config_file" "channel_size" 1 65536
    validate_numeric_field "$config_file" "keepalive_period" 1 3600
    validate_numeric_field "$config_file" "web_port" 0 65535
    
    # Validate boolean fields
    validate_boolean_field "$config_file" "accept_udp"
    validate_boolean_field "$config_file" "nodelay"
    validate_boolean_field "$config_file" "sniffer"
    
    return $errors
}

# TCP Multiplexing protocol validation
validate_tcpmux_config() {
    local config_file="$1"
    local errors=0
    
    # Include TCP validation
    validate_tcp_config "$config_file"
    errors=$?
    
    # Check multiplexing-specific fields
    validate_numeric_field "$config_file" "mux_con" 1 64
    validate_numeric_field "$config_file" "mux_version" 1 2
    validate_numeric_field "$config_file" "mux_framesize" 1024 1048576
    validate_numeric_field "$config_file" "mux_recievebuffer" 1024 16777216
    validate_numeric_field "$config_file" "mux_streambuffer" 1024 1048576
    
    return $errors
}

# UDP protocol validation
validate_udp_config() {
    local config_file="$1"
    local errors=0
    
    # Check required fields
    if ! grep -q '^bind_addr\|^remote_addr' "$config_file"; then
        print_error "Missing required address field (bind_addr for server, remote_addr for client)"
        ((errors++))
    fi
    
    # Check optional but recommended fields
    if ! grep -q '^token' "$config_file"; then
        print_warning "No authentication token specified (recommended for security)"
    fi
    
    # Validate numeric fields
    validate_numeric_field "$config_file" "heartbeat" 1 3600
    validate_numeric_field "$config_file" "channel_size" 1 65536
    validate_numeric_field "$config_file" "web_port" 0 65535
    
    # Validate boolean fields
    validate_boolean_field "$config_file" "sniffer"
    
    return $errors
}

# WebSocket protocol validation
validate_ws_config() {
    local config_file="$1"
    local errors=0
    
    # Check required fields
    if ! grep -q '^bind_addr\|^remote_addr' "$config_file"; then
        print_error "Missing required address field (bind_addr for server, remote_addr for client)"
        ((errors++))
    fi
    
    # Check optional but recommended fields
    if ! grep -q '^token' "$config_file"; then
        print_warning "No authentication token specified (recommended for security)"
    fi
    
    # Validate numeric fields and count errors
    if ! validate_numeric_field "$config_file" "heartbeat" 1 3600; then
        ((errors++))
    fi
    if ! validate_numeric_field "$config_file" "channel_size" 1 65536; then
        ((errors++))
    fi
    if ! validate_numeric_field "$config_file" "keepalive_period" 1 3600; then
        ((errors++))
    fi
    if ! validate_numeric_field "$config_file" "web_port" 0 65535; then
        ((errors++))
    fi
    
    # Validate boolean fields and count errors
    if ! validate_boolean_field "$config_file" "nodelay"; then
        ((errors++))
    fi
    if ! validate_boolean_field "$config_file" "sniffer"; then
        ((errors++))
    fi
    
    return $errors
}

# Secure WebSocket protocol validation
validate_wss_config() {
    local config_file="$1"
    local errors=0
    
    # Include WS validation
    validate_ws_config "$config_file"
    errors=$?
    
    # Check TLS certificate files
    local tls_cert tls_key
    tls_cert=$(grep '^tls_cert' "$config_file" | cut -d'"' -f2)
    tls_key=$(grep '^tls_key' "$config_file" | cut -d'"' -f2)
    
    if [[ -z "$tls_cert" ]]; then
        print_error "Missing required tls_cert field for WSS transport"
        ((errors++))
    elif [[ ! -f "$tls_cert" ]]; then
        print_error "TLS certificate file not found: $tls_cert"
        ((errors++))
    fi
    
    if [[ -z "$tls_key" ]]; then
        print_error "Missing required tls_key field for WSS transport"
        ((errors++))
    elif [[ ! -f "$tls_key" ]]; then
        print_error "TLS key file not found: $tls_key"
        ((errors++))
    fi
    
    return $errors
}

# WebSocket Multiplexing protocol validation
validate_wsmux_config() {
    local config_file="$1"
    local errors=0
    
    # Include WS validation
    validate_ws_config "$config_file"
    errors=$?
    
    # Check multiplexing-specific fields
    validate_numeric_field "$config_file" "mux_con" 1 64
    validate_numeric_field "$config_file" "mux_version" 1 2
    validate_numeric_field "$config_file" "mux_framesize" 1024 1048576
    validate_numeric_field "$config_file" "mux_recievebuffer" 1024 16777216
    validate_numeric_field "$config_file" "mux_streambuffer" 1024 1048576
    
    return $errors
}

# Secure WebSocket Multiplexing protocol validation
validate_wssmux_config() {
    local config_file="$1"
    local errors=0
    
    # Include WSS validation
    validate_wss_config "$config_file"
    errors=$?
    
    # Check multiplexing-specific fields
    validate_numeric_field "$config_file" "mux_con" 1 64
    validate_numeric_field "$config_file" "mux_version" 1 2
    validate_numeric_field "$config_file" "mux_framesize" 1024 1048576
    validate_numeric_field "$config_file" "mux_recievebuffer" 1024 16777216
    validate_numeric_field "$config_file" "mux_streambuffer" 1024 1048576
    
    return $errors
}

# Advanced configuration validation
validate_advanced_config() {
    local config_file="$1"
    local errors=0
    local warnings=0
    
    # Check for syntax errors with improved regex
    local syntax_errors
    syntax_errors=$(grep -v "^[[:space:]]*#" "$config_file" | grep -v "^[[:space:]]*$" | grep -v "^\[.*\]" | grep -v "^[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*=[[:space:]]*[^[:space:]]*" | wc -l)
    if [[ $syntax_errors -gt 0 ]]; then
        print_warning "Found $syntax_errors potential syntax issues"
        ((warnings++))
    fi
    
    # Check for deprecated or invalid fields
    local deprecated_fields=("mux_session" "edge_ip")
    for field in "${deprecated_fields[@]}"; do
        if grep -q "^$field[[:space:]]*=" "$config_file"; then
            print_warning "Deprecated field found: $field"
            ((warnings++))
        fi
    done
    
    # Check for security issues
    if grep -q '^token[[:space:]]*=[[:space:]]*""' "$config_file"; then
        print_warning "Empty authentication token (security risk)"
        ((warnings++))
    fi
    
    # Check for performance issues
    local channel_size
    channel_size=$(grep '^channel_size' "$config_file" | cut -d'"' -f2)
    if [[ -n "$channel_size" && $channel_size -gt 8192 ]]; then
        print_warning "High channel_size ($channel_size) may impact performance"
        ((warnings++))
    fi
    
    # Check for file permissions (if files exist)
    local sniffer_log
    sniffer_log=$(grep '^sniffer_log' "$config_file" | cut -d'"' -f2)
    if [[ -n "$sniffer_log" && -f "$sniffer_log" ]]; then
        if [[ ! -r "$sniffer_log" ]]; then
            print_error "Sniffer log file not readable: $sniffer_log"
            ((errors++))
        fi
    fi
    
    # Check for port conflicts
    validate_port_conflicts "$config_file"
    local port_conflicts=$?
    warnings=$((warnings + port_conflicts))
    
    return $errors
}

# Validate numeric field with range
validate_numeric_field() {
    local config_file="$1"
    local field="$2"
    local min="$3"
    local max="$4"
    
    local value
    # Handle both quoted and unquoted values
    value=$(grep "^$field[[:space:]]*=" "$config_file" | sed 's/^[^=]*=[[:space:]]*//' | sed 's/^"\(.*\)"$/\1/' | sed 's/^'\''\(.*\)'\''$/\1/')
    
    if [[ -n "$value" ]]; then
        if [[ ! "$value" =~ ^[0-9]+$ ]]; then
            print_error "Invalid $field value: $value (must be numeric)"
            return 1
        elif [[ $value -lt $min || $value -gt $max ]]; then
            print_error "Invalid $field value: $value (must be $min-$max)"
            return 1
        fi
    fi
    
    return 0
}

# Validate boolean field
validate_boolean_field() {
    local config_file="$1"
    local field="$2"
    
    local value
    # Handle both quoted and unquoted values
    value=$(grep "^$field[[:space:]]*=" "$config_file" | sed 's/^[^=]*=[[:space:]]*//' | sed 's/^"\(.*\)"$/\1/' | sed 's/^'\''\(.*\)'\''$/\1/')
    
    if [[ -n "$value" ]]; then
        if [[ ! "$value" =~ ^(true|false)$ ]]; then
            print_error "Invalid $field value: $value (must be true or false)"
            return 1
        fi
    fi
    
    return 0
}

# Validate port conflicts
validate_port_conflicts() {
    local config_file="$1"
    local warnings=0
    
    # Extract ports from config
    local ports=()
    while IFS= read -r line; do
        if [[ "$line" =~ bind_addr.*:([0-9]+) ]]; then
            ports+=("${BASH_REMATCH[1]}")
        elif [[ "$line" =~ remote_addr.*:([0-9]+) ]]; then
            ports+=("${BASH_REMATCH[1]}")
        elif [[ "$line" =~ web_port[[:space:]]*=[[:space:]]*([0-9]+) ]]; then
            ports+=("${BASH_REMATCH[1]}")
        fi
    done < "$config_file"
    
    # Check for duplicate ports
    local unique_ports=($(printf '%s\n' "${ports[@]}" | sort -u))
    if [[ ${#ports[@]} -ne ${#unique_ports[@]} ]]; then
        print_warning "Duplicate ports detected in configuration"
        ((warnings++))
    fi
    
    # Check for common port conflicts
    for port in "${ports[@]}"; do
        case $port in
            22|80|443|3306|5432|6379|8080|8443)
                print_warning "Port $port is commonly used by other services"
                ((warnings++))
                ;;
        esac
    done
    
    return $warnings
}

# Enhanced configuration validation with detailed reporting
validate_config_detailed() {
    local config_file="$1"
    
    clear
    print_info "=== Configuration Validation ==="
    echo
    
    if [[ ! -f "$config_file" ]]; then
        print_error "Configuration file not found: $config_file"
        press_any_key
        return 1
    fi
    
    # Initialize logging if not already done
    init_logging
    
    # Run comprehensive validation
    local validation_result=0
    local issues_found=0
    local warnings_found=0
    
    print_info "--- Basic Validation ---"
    
    # Check for required sections
    local required_sections=("server" "client")
    local found_sections=()
    
    for section in "${required_sections[@]}"; do
        if grep -q "^\[$section\]" "$config_file"; then
            found_sections+=("$section")
        fi
    done
    
    if [[ ${#found_sections[@]} -eq 0 ]]; then
        print_error "Missing required section [server] or [client]"
        ((issues_found++))
        validation_result=1
    else
        print_success "Found section(s): ${found_sections[*]}"
    fi
    
    # Check for basic syntax errors
    if ! grep -q "^\[.*\]\|^[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*=" "$config_file"; then
        print_error "Invalid configuration syntax"
        ((issues_found++))
        validation_result=1
    fi
    
    # Validate port numbers
    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*port[[:space:]]*=[[:space:]]*([0-9]+) ]]; then
            local port="${BASH_REMATCH[1]}"
            if [[ $port -lt 1 || $port -gt 65535 ]]; then
                print_error "Invalid port number: $port (must be 1-65535)"
                ((issues_found++))
                validation_result=1
            fi
        fi
    done < "$config_file"
    
    # Protocol-specific validation
    echo
    validate_protocol_config "$config_file"
    local protocol_errors=$?
    issues_found=$((issues_found + protocol_errors))
    if [[ $protocol_errors -gt 0 ]]; then
        validation_result=1
    fi
    
    # Advanced validation
    echo
    validate_advanced_config "$config_file"
    local advanced_errors=$?
    local advanced_warnings=$?
    issues_found=$((issues_found + advanced_errors))
    if [[ $advanced_errors -gt 0 ]]; then
        validation_result=1
    fi
    warnings_found=$((warnings_found + advanced_warnings))
    
    # Summary
    echo
    print_info "--- Validation Summary ---"
    if [[ $validation_result -eq 0 ]]; then
        print_success "✓ Configuration is valid"
        if [[ $warnings_found -gt 0 ]]; then
            print_info "Found $warnings_found warning(s) - review recommended"
        else
            print_info "All checks passed successfully"
        fi
    else
        print_error "✗ Configuration has issues"
        print_info "Found $issues_found error(s) that need attention"
        
        if confirm_action "Would you like to create a backup before attempting fixes?" "y"; then
            backup_config "$config_file"
            print_success "Backup created"
        fi
    fi
    
    press_any_key
    return $validation_result
} 
# --- MODULE: modules/ufw.sh ---
# ufw.sh
# UFW (firewall) management functions 

# --- UFW Management ---
manage_ufw_add() {
    local port=$1 transport=$2 suffix=$3
    local proto="tcp" && [[ "$transport" == "udp" ]] && proto="udp"

    if ! command -v ufw &> /dev/null; then
        print_warning "UFW is not installed. Skipping firewall rule addition."
        return
    fi
    if ! ufw status | grep -q "Status: active"; then
        print_warning "UFW is not active."
        read -p "Do you want to enable UFW and add the required rules? (y/n): " enable_ufw
        if [[ "${enable_ufw,,}" == "y" ]]; then
            # Detect SSH port(s) from sshd_config and listening ports
            local ssh_ports
            ssh_ports=$(ss -tnlp | grep sshd | awk '{print $4}' | sed 's/.*://')
            if [ -z "$ssh_ports" ]; then
                ssh_ports=$(grep -E '^Port ' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
            fi
            if [ -z "$ssh_ports" ]; then
                ssh_ports=22
            fi
            print_info "Adding SSH port(s) to UFW: $ssh_ports"
            for p in $ssh_ports; do
                ufw allow "$p/tcp" comment "SSH (auto-added by EasyBackhaul)"
            done
            ufw enable
            print_success "UFW enabled and SSH port(s) allowed."
        else
            print_warning "Skipping firewall rule addition."
            return
        fi
    fi
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
}

manage_ufw_delete() {
    local suffix=$1
    if ! command -v ufw &> /dev/null; then
        print_warning "UFW is not installed. Skipping firewall rule removal."
        return
    fi
    if ! ufw status | grep -q "Status: active"; then
        print_warning "UFW is not active. Skipping firewall rule removal."
        return
    fi
    if [ -f "$UFW_METADATA_FILE" ]; then
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

create_ufw_rules() {
    local tunnel_name="$1"
    local server_ip="$2"
    local server_port="$3"
    local local_port="$4"
    local protocol="$5"
    
    # Input validation
    if ! validate_ip "$server_ip" || ! validate_port "$server_port" || ! validate_port "$local_port"; then
        log_message "ERROR" "Invalid UFW rule parameters for tunnel $tunnel_name"
        return 1
    fi
    
    # Sanitize tunnel name for UFW rule description
    local sanitized_name=$(sanitize_input "$tunnel_name" 30)
    
    # Check if UFW is active
    if ! ufw status | grep -q "Status: active"; then
        log_message "WARNING" "UFW is not active. Rules will be created but not applied."
    fi
    
    # Create outbound rule for tunnel connection
    ufw allow out to "$server_ip" port "$server_port" proto "$protocol" comment "EasyBackhaul tunnel $sanitized_name outbound" 2>/dev/null
    
    # Create inbound rule for local port
    ufw allow in on lo to any port "$local_port" proto "$protocol" comment "EasyBackhaul tunnel $sanitized_name inbound" 2>/dev/null
    
    # Log the rule creation
    secure_log_message "INFO" "Created UFW rules for tunnel $tunnel_name"
    
    return 0
}

remove_ufw_rules() {
    local tunnel_name="$1"
    
    # Input sanitization
    tunnel_name=$(sanitize_input "$tunnel_name" 30)
    
    # Find and remove UFW rules for this tunnel
    local rule_numbers=$(ufw status numbered | grep "EasyBackhaul tunnel $tunnel_name" | awk -F'[][]' '{print $2}' | sort -nr)
    
    if [ -n "$rule_numbers" ]; then
        for rule_num in $rule_numbers; do
            echo "y" | ufw delete "$rule_num" >/dev/null 2>&1
        done
        
        secure_log_message "INFO" "Removed UFW rules for tunnel $tunnel_name"
    fi
}

ufw_menu() {
    clear
    echo "=== UFW Firewall Rules Management ==="
    echo ""
    
    # Check UFW status
    local ufw_status=$(ufw status | grep "Status:" | awk '{print $2}')
    echo "🔒 UFW Status: $ufw_status"
    echo ""
    
    echo "UFW Options:"
    echo "1) View all UFW rules"
    echo "2) View EasyBackhaul rules only"
    echo "3) Enable UFW"
    echo "4) Disable UFW"
    echo "5) Reset UFW rules"
    echo "6) Security audit UFW rules"
    echo "0) Back to main menu"
    
    read -p "Enter choice (0-6): " choice
    
    case $choice in
        0) return ;;
        1) view_all_ufw_rules ;;
        2) view_easybackhaul_rules ;;
        3) enable_ufw ;;
        4) disable_ufw ;;
        5) reset_ufw_rules ;;
        6) audit_ufw_rules ;;
        *) echo "❌ Invalid choice" ;;
    esac
}

view_all_ufw_rules() {
    echo ""
    echo "=== All UFW Rules ==="
    ufw status numbered
}

view_easybackhaul_rules() {
    echo ""
    echo "=== EasyBackhaul UFW Rules ==="
    ufw status numbered | grep -E "(EasyBackhaul|easybackhaul)" || echo "No EasyBackhaul rules found"
}

enable_ufw() {
    echo ""
    echo "=== Enable UFW ==="
    
    if ufw status | grep -q "Status: active"; then
        echo "✅ UFW is already active"
        return
    fi
    
    echo "⚠ This will enable UFW firewall. Make sure you have SSH access configured."
    read -p "Proceed? (y/n): " choice
    
    if [ "$choice" = "y" ]; then
        ufw --force enable
        echo "✅ UFW enabled successfully"
        secure_log_message "INFO" "UFW firewall enabled"
    else
        echo "❌ UFW enable cancelled"
    fi
}

disable_ufw() {
    echo ""
    echo "=== Disable UFW ==="
    
    if ! ufw status | grep -q "Status: active"; then
        echo "⚠ UFW is not active"
        return
    fi
    
    echo "⚠ WARNING: Disabling UFW will remove firewall protection."
    read -p "Are you sure? (y/n): " choice
    
    if [ "$choice" = "y" ]; then
        ufw --force disable
        echo "✅ UFW disabled"
        secure_log_message "WARNING" "UFW firewall disabled"
    else
        echo "❌ UFW disable cancelled"
    fi
}

reset_ufw_rules() {
    echo ""
    echo "=== Reset UFW Rules ==="
    
    echo "⚠ WARNING: This will remove ALL UFW rules and reset to default."
    echo "   This action cannot be undone."
    read -p "Type 'RESET' to confirm: " confirmation
    
    if [ "$confirmation" = "RESET" ]; then
        ufw --force reset
        echo "✅ UFW rules reset to default"
        secure_log_message "WARNING" "UFW rules reset to default"
    else
        echo "❌ UFW reset cancelled"
    fi
}

audit_ufw_rules() {
    echo ""
    echo "=== UFW Security Audit ==="
    
    local issues=0
    
    # Check if UFW is active
    if ! ufw status | grep -q "Status: active"; then
        echo "❌ UFW is not active - no firewall protection"
        ((issues++))
    else
        echo "✅ UFW is active"
    fi
    
    # Check for overly permissive rules
    local permissive_rules=$(ufw status | grep -E "(allow.*any|allow.*0\.0\.0\.0)" | wc -l)
    if [ "$permissive_rules" -gt 0 ]; then
        echo "⚠ Found $permissive_rules potentially permissive rules"
        ((issues++))
    fi
    
    # Check EasyBackhaul rules
    local easybackhaul_rules=$(ufw status | grep -c "EasyBackhaul")
    echo "📊 EasyBackhaul rules: $easybackhaul_rules"
    
    # Check for orphaned rules (rules without corresponding tunnels)
    local orphaned_rules=0
    for rule in $(ufw status | grep "EasyBackhaul tunnel" | awk '{print $NF}'); do
        local tunnel_name=$(echo "$rule" | sed 's/EasyBackhaul tunnel //')
        if [ ! -d "$TUNNEL_DIR/$tunnel_name" ]; then
            echo "⚠ Orphaned UFW rule for non-existent tunnel: $tunnel_name"
            ((orphaned_rules++))
            ((issues++))
        fi
    done
    
    if [ $issues -eq 0 ]; then
        echo "✅ UFW security audit passed"
    else
        echo ""
        echo "🔧 Fix issues? (y/n): "
        read -p "" fix_choice
        if [ "$fix_choice" = "y" ]; then
            fix_ufw_issues
        fi
    fi
}

fix_ufw_issues() {
    echo ""
    echo "=== Fixing UFW Issues ==="
    
    # Remove orphaned rules
    for rule in $(ufw status | grep "EasyBackhaul tunnel" | awk '{print $NF}'); do
        local tunnel_name=$(echo "$rule" | sed 's/EasyBackhaul tunnel //')
        if [ ! -d "$TUNNEL_DIR/$tunnel_name" ]; then
            echo "🧹 Removing orphaned rule for tunnel: $tunnel_name"
            remove_ufw_rules "$tunnel_name"
        fi
    done
    
    # Enable UFW if not active
    if ! ufw status | grep -q "Status: active"; then
        echo "🔒 Enabling UFW..."
        ufw --force enable
    fi
    
    echo "✅ UFW issues fixed"
} 
# --- MODULE: modules/systemd.sh ---
# systemd.sh
# Systemd service creation and management 

# --- Systemd Service Management ---
create_systemd_service() {
    local name_suffix=$1 config_path=$2
    local service_file="$SERVICE_DIR/backhaul-${name_suffix}.service"

    if ! command -v systemctl &>/dev/null; then
        print_warning "Systemd is not available on this system."
        read -p "Do you want to run the tunnel in the foreground instead? (y/n): " fg_run
        if [[ "${fg_run,,}" == "y" ]]; then
            print_info "Running: $BIN_PATH -c $config_path"
            "$BIN_PATH" -c "$config_path"
        else
            print_error "Cannot create a persistent service without systemd."
        fi
        return
    fi

    print_info "--> Creating systemd service file: $service_file"
    cat > "$service_file" <<EOL
[Unit]
Description=Backhaul Service (${name_suffix})
After=network.target

[Service]
Type=simple
ExecStart="${BIN_PATH}" -c "${config_path}"
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
        read -p "Show the last 20 lines of the service log? (y/n): " showlog
        if [[ "${showlog,,}" == "y" ]]; then
            journalctl -u "backhaul-${name_suffix}.service" -n 20 --no-pager
        fi
        return 1
    fi
    print_success "Service backhaul-${name_suffix}.service created and started."

    read -p "Check service status now? (y/n) [y]: " check_status
    if [[ "${check_status:-y}" == "y" ]]; then
        systemctl status "backhaul-${name_suffix}.service" --no-pager
    fi
} 
# --- MODULE: modules/tunnel_mgmt.sh ---
#!/bin/bash
# tunnel_mgmt.sh
# List/manage tunnels, single tunnel management, connection test 

# Ensure helpers.sh is sourced for logging and restart helpers
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}" )" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

# --- Tunnel Management ---
manage_tunnels() {
    while true; do
        clear
        print_server_info_banner
        print_info "--- Available Backhaul Services ---"
        mapfile -t services < <(systemctl list-unit-files --type=service 'backhaul-*.service' --no-legend | awk '{print $1}' | grep -v 'backhaul-watcher-')

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
    local service_file="$SERVICE_DIR/$service"
    local certs_to_delete=""
    if [[ "$suffix" == server-wss* || "$suffix" == server-wssmux* ]]; then
        # Try to find certs referenced in config
        if [ -f "$config_file" ]; then
            local cert_path key_path
            cert_path=$(grep '^tls_cert' "$config_file" | cut -d'"' -f2)
            key_path=$(grep '^tls_key' "$config_file" | cut -d'"' -f2)
            if [ -n "$cert_path" ] && [ -f "$cert_path" ]; then
                certs_to_delete+="$cert_path\n"
            fi
            if [ -n "$key_path" ] && [ -f "$key_path" ]; then
                certs_to_delete+="$key_path\n"
            fi
        fi
    fi

    while true; do
        clear
        print_server_info_banner
        local status
        status=$(systemctl is-active "$service")
        local status_text
        if [[ "$status" == "active" ]]; then
             status_text="\e[32mActive\e[0m"
        else
             status_text="\e[31mInactive\e[0m"
        fi
        print_info "--- Managing: $service (Status: $status_text) ---"
        print_info "Tip: Press '?' for help about tunnel features."

        # Show service status
        local service_status
        if systemctl is-active --quiet "$service"; then
            service_status="\e[32mRunning\e[0m"
        else
            service_status="\e[31mStopped\e[0m"
        fi
        print_info "Service Status: $service_status"
        # Show watcher status
        local watcher_pid_file="/tmp/backhaul-watcher-${suffix}.pid"
        if [[ -f "$watcher_pid_file" ]]; then
            print_info "Watcher: \e[32mEnabled\e[0m (PID: $(cat $watcher_pid_file))"
        else
            print_info "Watcher: \e[31mDisabled\e[0m"
        fi

        echo " 1. Start"
        echo " 2. Stop"
        echo " 3. Restart"
        echo " 4. View Service Status (summary + last logs)"
        echo " 5. View Full Logs (scroll/search/live)"
        echo " 6. View Configuration"
        echo " 7. Edit Configuration (nano)"
        echo " 8. Change Log Level"
        echo " 9. Test Connection"
        echo "10. Hot Reload Config"
        echo "11. Manage Cron Auto-Restart"
        echo "12. Manage Coordinated Restart Watcher"
        echo "13. Health Check & Performance"
        echo "14. Validate Configuration"
        echo "15. Graceful Restart"
        echo "16. Delete Service"
        echo " ?. Help"
        echo " 0. Back to Service List"

        local choice
        read -p "Enter choice [0-16, ? for help]: " choice
        
        case $choice in
            1) with_spinner "Starting service" systemctl start "$service"; print_success "Service started successfully. You can now connect to this tunnel."; press_any_key;;
            2) with_spinner "Stopping service" systemctl stop "$service"; print_success "Service stopped. Connections will be refused until restarted."; press_any_key;;
            3) with_spinner "Restarting service" systemctl restart "$service"; print_success "Service restarted. Check logs if you encounter issues."; press_any_key;;
            \?) 
                print_info "================= Tunnel Management Help ================="
                echo
                echo "Tunnel Management Options:"
                echo " 1. Start - Start the tunnel service"
                echo " 2. Stop - Stop the tunnel service"
                echo " 3. Restart - Restart the tunnel service"
                echo " 4. View Service Status - Show service status and recent logs"
                echo " 5. View Full Logs - Interactive log viewing with search/follow"
                echo " 6. View Configuration - Display current tunnel configuration"
                echo " 7. Edit Configuration - Edit config file with nano editor"
                echo " 8. Change Log Level - Modify logging verbosity"
                echo " 9. Test Connection - Test tunnel connectivity"
                echo "10. Hot Reload Config - Reload config without restart"
                echo "11. Manage Cron Auto-Restart - Set up automatic restarts"
                echo "12. Manage Coordinated Restart Watcher - Advanced restart coordination"
                echo "13. Health Check & Performance - Monitor tunnel health"
                echo "14. Validate Configuration - Check config for errors"
                echo "15. Graceful Restart - Coordinated restart with remote side"
                echo "16. Delete Service - Remove the tunnel, config, and related files."
                echo
                echo "- For more details, see the main help from the main menu."
                echo "================================================================"
                press_any_key
                ;;
            4)
                systemctl status "$service" --no-pager
                echo
                print_info "Tip: For full logs, including scrolling/searching, use option 5 in this menu."
                press_any_key
                ;;
            5)
                print_info "Choose log viewing mode:"
                echo " 1) Live follow (Ctrl+C to exit log view and return to menu)"
                echo " 2) Interactive (scroll/search, press q to quit, F to follow live, Ctrl+C to exit log view and return to menu)"
                read -p "Select [1-2, default 2]: " log_mode
                log_mode=${log_mode:-2}
                if [[ "$log_mode" == "1" ]]; then
                    print_warning "You are about to enter live log view. Press Ctrl+C to exit log view and return to the menu."
                    sleep 2
                    # Save current SIGINT trap
                    old_trap=$(trap -p SIGINT)
                    # Ignore SIGINT in parent
                    trap '' SIGINT
                    # Run log viewer in subshell with default SIGINT
                    (
                        trap - SIGINT
                        journalctl -u "$service" -f --no-pager
                    )
                    # Restore old SIGINT trap
                    eval "$old_trap"
                else
                    print_info "Interactive log view: Use arrow keys to scroll, / to search, F to follow live, q to quit. Press Ctrl+C to exit log view and return to the menu."
                    sleep 2
                    old_trap=$(trap -p SIGINT)
                    trap '' SIGINT
                    (
                        trap - SIGINT
                        journalctl -u "$service" --no-pager | less +F
                    )
                    eval "$old_trap"
                fi
                ;;
            6)
                print_info "Viewing configuration. Press 'q' to exit and return to the menu."
                sleep 1
                less "$config_file"
                ;;
            7) 
                if [ ! -f "$config_file" ]; then print_error "Config file not found for this tunnel. Please check your configuration and try again."; press_any_key; continue; fi
                backup_config "$config_file"
                nano "$config_file"
                if confirm_action "Restart service to apply changes?" "y"; then 
                    systemctl restart "$service"
                    print_success "Service restarted."
                fi
                ;;
            8)
                # Change log level submenu
                print_info "--- Change Log Level ---"
                echo "Log levels control the verbosity of logs:"
                echo "  debug: Most detailed, for troubleshooting."
                echo "  info:  Normal operation messages (default)."
                echo "  warn:  Only warnings and errors."
                echo "  error: Only errors."
                echo
                current_level=$(grep -E '^\s*log_level\s*=\s*"' "$config_file" | head -n1 | cut -d'"' -f2)
                print_info "Current log level: ${current_level:-info}"
                echo "Select new log level:"
                select new_level in debug info warn error cancel; do
                    case $new_level in
                        debug|info|warn|error)
                                # Update log_level in config file using unified function
                                update_config_value "$config_file" "log_level" "$new_level"
                            print_success "Log level updated to $new_level."
                                if confirm_action "Restart service to apply new log level?" "y"; then
                                systemctl restart "$service"
                                print_success "Service restarted."
                            fi
                            break
                            ;;
                        cancel)
                            print_info "Log level change cancelled."
                            break
                            ;;
                        *)
                            print_warning "Invalid selection."
                            ;;
                    esac
                done
                ;;
            9) test_connection "$config_file"; press_any_key;;
            10) hot_reload_service "$service"; press_any_key;;
            11) manage_cron_menu "$service";;
            12)
                manage_watcher_submenu "$service" "$suffix" "$config_file" ;;
            13)
                show_health_and_performance "$suffix" "$service" ;;
            14)
                validate_tunnel_config "$config_file" ;;
            15)
                graceful_restart_with_ui "$suffix" ;;
            16)
                print_warning "You are about to delete the following:"
                echo "  - Service: $service_file"
                echo "  - Config: $config_file"
                
                # Check for watcher files
                local watcher_script="/tmp/backhaul-watcher-${suffix}.sh"
                local watcher_pid_file="/tmp/backhaul-watcher-${suffix}.pid"
                local watcher_log="/tmp/backhaul-watcher-${suffix}.log"
                
                if [[ -f "$watcher_script" ]]; then
                    echo "  - Watcher script: $watcher_script"
                fi
                if [[ -f "$watcher_pid_file" ]]; then
                    echo "  - Watcher process file: $watcher_pid_file"
                fi
                if [[ -f "$watcher_log" ]]; then
                    echo "  - Watcher logs: $watcher_log"
                fi
                
                if [ -n "$certs_to_delete" ]; then
                    echo -e "  - TLS Cert/Key(s):\n$certs_to_delete"
                fi
                if grep -q "^$suffix:" "$UFW_METADATA_FILE" 2>/dev/null; then
                    echo "  - UFW rule: $(grep "^$suffix:" "$UFW_METADATA_FILE" | cut -d':' -f2)"
                fi
                if crontab -l 2>/dev/null | grep -q "$service"; then
                    echo "  - Cron job for $service"
                fi
                read -p "Are you sure you want to PERMANENTLY delete all of the above? (y/n): " confirm_delete
                if [[ "${confirm_delete,,}" == "y" ]]; then
                    print_warning "Stopping and disabling service..."
                    with_spinner "Stopping service" systemctl stop "$service" &>/dev/null
                    with_spinner "Disabling service" systemctl disable "$service" &>/dev/null
                    
                    # Clean up watcher if it exists with robust process termination
                    if [[ -f "$watcher_pid_file" ]]; then
                        local watcher_pid=$(cat "$watcher_pid_file")
                        if [[ -n "$watcher_pid" ]]; then
                            print_info "Stopping watcher process (PID: $watcher_pid)..."
                            
                            # Try graceful termination first
                            kill "$watcher_pid" 2>/dev/null
                            
                            # Wait up to 5 seconds for graceful shutdown
                            local count=0
                            while kill -0 "$watcher_pid" 2>/dev/null && [[ $count -lt 5 ]]; do
                                sleep 1
                                ((count++))
                            done
                            
                            # If still running, force kill
                            if kill -0 "$watcher_pid" 2>/dev/null; then
                                print_warning "Process not responding to SIGTERM, forcing termination..."
                                kill -9 "$watcher_pid" 2>/dev/null
                                sleep 1
                            fi
                            
                            # Verify process is dead
                            if kill -0 "$watcher_pid" 2>/dev/null; then
                                print_error "Failed to terminate watcher process (PID: $watcher_pid)"
                            else
                                print_success "Watcher process terminated successfully"
                            fi
                        fi
                        rm -f "$watcher_pid_file"
                    fi
                    
                    # Kill any remaining child processes of the watcher
                    pkill -f "backhaul-watcher-${suffix}" 2>/dev/null
                    
                    if [[ -f "$watcher_script" ]]; then
                        rm -f "$watcher_script"
                        print_info "Removed watcher script"
                    fi
                    if [[ -f "$watcher_log" ]]; then
                        rm -f "$watcher_log"
                        print_info "Removed watcher logs"
                    fi
                    
                    # Remove any temporary ACK files
                    rm -f "/tmp/restart_ack_${service}"
                    
                    print_warning "Removing files..."
                    rm -f "$config_file" "$service_file"
                    if [ -n "$certs_to_delete" ]; then
                        echo -e "$certs_to_delete" | xargs rm -f
                    fi
                    manage_ufw_delete "$suffix"
                    remove_cron_job "$service"
                    systemctl daemon-reload
                    # Run zombie cleanup
                    cleanup_zombie_processes
                    
                    print_success "Service $service and all associated files (including watcher) have been deleted. You may now create a new tunnel or exit.";
                    press_any_key
                    return
                fi
                ;;
            0) return ;;
            \?)
                clear
                print_info "================= Tunnel Management Help ================="
                echo "This menu lets you manage a specific Backhaul tunnel/service."
                echo
                echo " 1. Start: Start the selected tunnel service."
                echo " 2. Stop: Stop the tunnel service."
                echo " 3. Restart: Restart the tunnel service."
                echo " 4. View Service Status: Show summary and last logs."
                echo " 5. View Full Logs: Scroll/search or follow logs live."
                echo " 6. View Configuration: View the TOML config (press q to exit)."
                echo " 7. Edit Configuration: Edit config in nano, then optionally restart."
                echo " 8. Change Log Level: Adjust log verbosity (debug/info/warn/error)."
                echo " 9. Test Connection: Test if the tunnel is reachable."
                echo "10. Hot Reload Config: Reload config without restart (if supported)."
                echo "11. Manage Cron Auto-Restart: Set up or remove auto-restart jobs."
                echo "12. Manage Coordinated Restart Watcher: All watcher options (enable/disable, config, status, logs, test) in a dedicated submenu."
                echo "    - The watcher coordinates restarts between client and server on error."
                echo "    - You must set the same secret and compatible ports on both sides."
                echo "    - Use the watcher submenu for config, status, logs, and testing."
                echo "13. Health Check & Performance: Monitor tunnel health, resource usage, and performance metrics."
                echo "14. Validate Configuration: Check config file syntax and validate settings."
                echo "15. Graceful Restart: Restart with health checks and error recovery."
                echo "16. Delete Service: Remove the tunnel, config, and related files."
                echo " 0. Back to Service List: Return to the previous menu."
                echo
                echo "Tips:"
                echo "- Use Ctrl+C to exit log views and return to this menu."
                echo "- Use 'q' to exit configuration view."
                echo "- For more details, see the main help from the main menu."
                press_any_key
                ;;
            *) print_warning "Invalid option."; press_any_key;;
        esac
    done
}

hot_reload_service() {
    local service=$1
    print_info "Sending SIGHUP to $service for hot reload..."
    if systemctl kill -s HUP "$service" 2>/dev/null; then
        print_success "Hot reload signal sent to $service."
        print_info "If the Backhaul binary supports hot reload, config changes should now be applied."
    else
        print_error "Failed to send hot reload signal. Your system or Backhaul version may not support this."
    fi
}

test_connection() {
    local config_file=$1
    if [ ! -f "$config_file" ]; then print_error "Config file not found."; return 1; fi

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

# --- Watcher Submenu ---
manage_watcher_submenu() {
    local service="$1"
    local suffix="$2"
    local config_file="$3"
    while true; do
        clear
        print_info "--- Coordinated Restart Watcher Submenu ---"
        print_info "Tip: Press '?' for help about watcher features."
        echo "1. Enable watcher (create/start background process)"
        echo "2. Disable watcher (stop/remove background process)"
        echo "3. Edit watcher config (pattern, delays, secret, ports)"
        echo "4. Show watcher status"
        echo "5. Show watcher logs"
        echo "6. Test watcher (send/receive signal)"
        echo "?. Help"
        echo "0. Back"
        read -p "Select [0-6, ? for help]: " wopt
        case $wopt in
            1) enable_watcher "$service" "$suffix" "$config_file" ;;
            2) disable_watcher "$service" "$suffix" "$config_file" ;;
            3) edit_watcher_config "$service" "$suffix" "$config_file" ;;
            4) show_watcher_status "$service" "$suffix" "$config_file" ;;
            5) show_watcher_logs "$service" "$suffix" "$config_file" ;;
            6) test_watcher "$service" "$suffix" "$config_file" ;;
            \?) watcher_submenu_help ;;
            0) return ;;
            *) print_warning "Invalid option."; press_any_key ;;
        esac
    done
}

enable_watcher() {
    local service="$1"
    local suffix="$2"
    local config_file="$3"
    local role remote_host local_ip

    clear
    print_info "=== Watcher Setup ==="
    echo
    print_info "The watcher coordinates restarts between both sides."
    echo
    
    # Determine role for better guidance
    if grep -q '^\[server\]' "$config_file"; then
        role="server"
        print_info "This is a SERVER tunnel"
        echo
        read -p "Enter client IP address: " remote_host
        if [[ -z "$remote_host" ]]; then
            print_error "Client IP is required."
            press_any_key
            return
        fi
    else
        role="client"
        print_info "This is a CLIENT tunnel"
        # For client, remote host is the server IP from tunnel config
        remote_host=$(grep '^remote_addr' "$config_file" | cut -d'"' -f2 | cut -d':' -f1)
        if [[ -z "$remote_host" ]]; then
            print_error "Could not find server IP in tunnel config."
            press_any_key
            return
        fi
        print_info "Server IP: $remote_host"
        
        # Get client's own IPv4 IP for server configuration
        local_ip=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 ipinfo.io/ip 2>/dev/null || echo "unknown")
        if [[ "$local_ip" != "unknown" ]]; then
            echo
            print_info "Your IPv4 address: $local_ip"
            print_info "Use this IP when configuring the server side watcher."
        fi
    fi

    # Simple port setup - server uses higher ports, client uses lower ports
    echo
    local listen_port remote_port
    if [[ "$role" == "server" ]]; then
        listen_port=45690  # Server receives on higher port
        remote_port=45680  # Server sends to lower port
    else
        listen_port=45680  # Client receives on lower port  
        remote_port=45690  # Client sends to higher port
    fi
    
    print_info "Checking port availability..."
    
    # Check if listen port is available using unified port checking
    if ! check_port_availability "$listen_port"; then
        read -p "Enter different receive port: " listen_port
        if [[ -z "$listen_port" ]]; then
            print_error "Port is required."
            press_any_key
            return 1
        fi
        # Re-check the new port
        if ! check_port_availability "$listen_port"; then
            print_error "Selected port is also in use."
            press_any_key
            return 1
        fi
    fi
    
    # Check if remote port is available (for local testing)
    if ! check_port_availability "$remote_port"; then
        print_warning "Port $remote_port is in use locally. This might cause issues."
    fi
    
    # Check for conflicts with main tunnel ports
    local tunnel_port
    tunnel_port=$(grep '^bind_addr\|^remote_addr' "$config_file" | cut -d'"' -f2 | cut -d':' -f2 | head -1)
    if [[ -n "$tunnel_port" ]]; then
        if [[ "$listen_port" == "$tunnel_port" || "$remote_port" == "$tunnel_port" ]]; then
            print_warning "Watcher port ($listen_port or $remote_port) conflicts with tunnel port ($tunnel_port)."
            print_info "This is not recommended but will work."
        fi
    fi
    
    # Check for conflicts with other watchers
    for existing_pid in /tmp/backhaul-watcher-*.pid; do
        if [[ -f "$existing_pid" ]]; then
            local existing_suffix=$(basename "$existing_pid" .pid | sed 's/backhaul-watcher-//')
            if [[ "$existing_suffix" != "$suffix" ]]; then
                local existing_config="$CONFIG_DIR/config-${existing_suffix}.toml"
                if [[ -f "$existing_config" ]]; then
                    local existing_listen=$(grep '^restart_watcher_listen_port' "$existing_config" | awk -F'=' '{print $2}' | tr -d ' "')
                    local existing_remote=$(grep '^restart_watcher_remote_port' "$existing_config" | awk -F'=' '{print $2}' | tr -d ' "')
                    if [[ "$listen_port" == "$existing_listen" || "$listen_port" == "$existing_remote" || "$remote_port" == "$existing_listen" || "$remote_port" == "$existing_remote" ]]; then
                        print_warning "Port conflict detected with existing watcher for tunnel: $existing_suffix"
                        print_info "This might cause communication issues between watchers."
                    fi
                fi
            fi
        fi
    done
    
    print_success "Ports are available."

    # Use default secret
    local secret="backhaul-watcher-naxon"

    # Add UFW rule for listen port
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
        print_info "--> UFW is active. Adding rule for port ${listen_port}/tcp..."
        ufw allow ${listen_port}/tcp >/dev/null 2>&1
        if [[ $? -eq 0 ]]; then
            print_success "UFW rule added successfully."
        else
            print_warning "Failed to add UFW rule. You may need to add it manually."
        fi
    fi

    # Create simple background watcher script with proper signal handling
    local watcher_script="/tmp/backhaul-watcher-${suffix}.sh"
    cat > "$watcher_script" <<EOL
#!/bin/bash
# Simple watcher for $service
# This script runs in background and coordinates restarts

SERVICE_NAME="$service"
REMOTE_HOST="$remote_host"
REMOTE_PORT="$remote_port"
LISTEN_PORT="$listen_port"
SECRET="$secret"
ROLE="$role"

log() { echo "[Watcher][\$ROLE][\$(date +'%F %T')] \$1"; }

# Global variables for cleanup
LISTENER_PID=""
JOURNAL_PID=""

# Cleanup function
cleanup() {
    log "Cleaning up watcher processes..."
    
    # Kill listener process
    if [[ -n "\$LISTENER_PID" ]]; then
        kill "\$LISTENER_PID" 2>/dev/null
        # Wait for graceful termination
        local count=0
        while kill -0 "\$LISTENER_PID" 2>/dev/null && [[ \$count -lt 3 ]]; do
            sleep 1
            ((count++))
        done
        # Force kill if still running
        if kill -0 "\$LISTENER_PID" 2>/dev/null; then
            kill -9 "\$LISTENER_PID" 2>/dev/null
        fi
    fi
    
    # Kill journalctl process
    if [[ -n "\$JOURNAL_PID" ]]; then
        kill "\$JOURNAL_PID" 2>/dev/null
        # Wait for graceful termination
        local count=0
        while kill -0 "\$JOURNAL_PID" 2>/dev/null && [[ \$count -lt 3 ]]; do
            sleep 1
            ((count++))
        done
        # Force kill if still running
        if kill -0 "\$JOURNAL_PID" 2>/dev/null; then
            kill -9 "\$JOURNAL_PID" 2>/dev/null
        fi
    fi
    
    # Clean up temporary files
    rm -f "/tmp/restart_ack_\${SERVICE_NAME}"
    
    log "Cleanup completed"
    exit 0
}

# Set up signal handlers
trap cleanup SIGTERM SIGINT SIGQUIT

# Function to send restart request and wait for ACK
send_restart_request() {
    log "Sending restart request to \$REMOTE_HOST:\$REMOTE_PORT"
    echo "RESTART_REQUEST:\$SECRET:\$ROLE" | nc "\$REMOTE_HOST" "\$REMOTE_PORT" -w 2 2>/dev/null
    
    # Wait for ACK (up to 10 seconds)
    log "Waiting for ACK from remote side..."
    for i in {1..10}; do
        # Check for ACK file (created by listener)
        if [[ -f "/tmp/restart_ack_\${SERVICE_NAME}" ]]; then
            rm -f "/tmp/restart_ack_\${SERVICE_NAME}"
            log "ACK received. Coordinated restart will proceed."
            return 0
        fi
        sleep 1
    done
    log "No ACK received. Proceeding with local restart only."
    return 1
}

# Function to listen for restart requests
listen_for_requests() {
    while true; do
        # Use timeout to prevent hanging
        msg=\$(timeout 30 nc -l -p "\$LISTEN_PORT" 2>/dev/null)
        if [[ "\$msg" =~ ^RESTART_REQUEST:\$SECRET: ]]; then
            local sender_role=\${msg##*:}
            log "Received restart request from \$sender_role. Sending ACK and restarting service."
            
            # Send ACK back to sender
            echo "RESTART_ACK:\$SECRET:\$ROLE" | nc "\$REMOTE_HOST" "\$REMOTE_PORT" -w 2 2>/dev/null
            
            # Create ACK file for local coordination
            touch "/tmp/restart_ack_\${SERVICE_NAME}"
            
            # Wait a bit then restart
            sleep 5
            if systemctl list-unit-files | grep -q "\$SERVICE_NAME"; then
                systemctl restart "\$SERVICE_NAME"
                log "Service restarted (coordinated)"
            else
                log "ERROR: Service \$SERVICE_NAME not found"
            fi
        elif [[ "\$msg" =~ ^RESTART_ACK:\$SECRET: ]]; then
            # This is an ACK for a request we sent
            local ack_role=\${msg##*:}
            log "Received ACK from \$ack_role"
            # Create ACK file for coordination
            touch "/tmp/restart_ack_\${SERVICE_NAME}"
        fi
        # Small sleep to prevent CPU hogging
        sleep 1
    done
}

# Start listener in background
listen_for_requests &
LISTENER_PID=\$!

# Monitor service logs for errors (with resource limits)
log "Starting watcher for \$SERVICE_NAME"
# Use timeout and limit log lines to prevent resource exhaustion
timeout 3600 journalctl -u "\$SERVICE_NAME" -f --no-pager --lines=100 | while read -r line; do
    if [[ "\$line" =~ ERROR|FATAL ]]; then
        log "Error detected. Initiating coordinated restart."
        
        # Try coordinated restart first
        if send_restart_request; then
            # ACK received, wait for coordination
            sleep 5
            if systemctl list-unit-files | grep -q "\$SERVICE_NAME"; then
                systemctl restart "\$SERVICE_NAME"
                log "Service restarted (coordinated)"
            else
                log "ERROR: Service \$SERVICE_NAME not found"
            fi
        else
            # No ACK, restart locally only
            sleep 5
            if systemctl list-unit-files | grep -q "\$SERVICE_NAME"; then
                systemctl restart "\$SERVICE_NAME"
                log "Service restarted (local only)"
            else
                log "ERROR: Service \$SERVICE_NAME not found"
            fi
        fi
        break
    fi
done &
JOURNAL_PID=\$!

# Wait for either process to exit
wait
EOL

    chmod +x "$watcher_script"
    
    # Start the watcher in background
    # Log rotation: keep last 5 logs
    for i in 5 4 3 2 1; do
        if [[ -f "/tmp/backhaul-watcher-${suffix}.log.$i" ]]; then
            mv "/tmp/backhaul-watcher-${suffix}.log.$i" "/tmp/backhaul-watcher-${suffix}.log.$((i+1))"
        fi
    done
    if [[ -f "/tmp/backhaul-watcher-${suffix}.log" ]]; then
        mv "/tmp/backhaul-watcher-${suffix}.log" "/tmp/backhaul-watcher-${suffix}.log.1"
    fi
    nohup "$watcher_script" > "/tmp/backhaul-watcher-${suffix}.log" 2>&1 &
    local watcher_pid=$!
    
    # Wait a moment to ensure process started
    sleep 1
    
    # Verify process is still running before saving PID
    if kill -0 "$watcher_pid" 2>/dev/null; then
        # Save PID for later management
        echo "$watcher_pid" > "/tmp/backhaul-watcher-${suffix}.pid"
    else
        print_error "Watcher process failed to start properly"
        press_any_key
        return 1
    fi
    
    # Update config file using unified functions
    update_config_value "$config_file" "restart_watcher_enabled" "y"
    update_config_numeric "$config_file" "restart_watcher_listen_port" "$listen_port"
    update_config_numeric "$config_file" "restart_watcher_remote_port" "$remote_port"
    update_config_value "$config_file" "restart_watcher_secret" "$secret"
    update_config_numeric "$config_file" "restart_watcher_pid" "$watcher_pid"
    
    print_success "Watcher enabled and started."
    echo
    print_info "--- Configuration ---"
    echo "Secret: $secret"
    echo "Receive port: $listen_port"
    echo "Send port: $remote_port"
    echo
    if [[ "$role" == "client" && "$local_ip" != "unknown" ]]; then
        print_info "Use your IPv4 address ($local_ip) when configuring the server side."
    fi
    press_any_key
}

disable_watcher() {
    local service="$1"
    local suffix="$2"
    local config_file="$3"
    local watcher_script="/tmp/backhaul-watcher-${suffix}.sh"
    local watcher_pid_file="/tmp/backhaul-watcher-${suffix}.pid"
    local watcher_log="/tmp/backhaul-watcher-${suffix}.log"
    
    # Stop background process with proper cleanup
    if [[ -f "$watcher_pid_file" ]]; then
        local watcher_pid=$(cat "$watcher_pid_file")
        if [[ -n "$watcher_pid" ]]; then
            print_info "Stopping watcher process (PID: $watcher_pid)..."
            
            # Try graceful termination first
            kill "$watcher_pid" 2>/dev/null
            
            # Wait up to 5 seconds for graceful shutdown
            local count=0
            while kill -0 "$watcher_pid" 2>/dev/null && [[ $count -lt 5 ]]; do
                sleep 1
                ((count++))
            done
            
            # If still running, force kill
            if kill -0 "$watcher_pid" 2>/dev/null; then
                print_warning "Process not responding to SIGTERM, forcing termination..."
                kill -9 "$watcher_pid" 2>/dev/null
                sleep 1
            fi
            
            # Verify process is dead
            if kill -0 "$watcher_pid" 2>/dev/null; then
                print_error "Failed to terminate watcher process (PID: $watcher_pid)"
            else
                print_success "Watcher process terminated successfully"
            fi
            
            rm -f "$watcher_pid_file"
        fi
    fi
    
    # Kill any remaining child processes of the watcher
    pkill -f "backhaul-watcher-${suffix}" 2>/dev/null
    
    # Remove watcher script
    if [[ -f "$watcher_script" ]]; then
        rm -f "$watcher_script"
        print_info "Removed watcher script"
    fi
    
    # Remove watcher log
    if [[ -f "$watcher_log" ]]; then
        rm -f "$watcher_log"
        print_info "Removed watcher log"
    fi
    
    # Remove any temporary ACK files
    rm -f "/tmp/restart_ack_${service}"
    
    # Remove UFW rule for listen port (if present in config)
    local listen_port
    listen_port=$(grep '^restart_watcher_listen_port' "$config_file" | awk -F'=' '{print $2}' | tr -d ' "')
    if [ -n "$listen_port" ]; then
        manage_ufw_delete "${suffix}-watcher"
    fi
    
    # Update config file
    sed -i '/^restart_watcher_enabled/d' "$config_file"
    sed -i '/^restart_watcher_pid/d' "$config_file"
    echo "restart_watcher_enabled = \"n\"" >> "$config_file"
    print_success "Watcher disabled and all processes removed."
    press_any_key
}

edit_watcher_config() {
    local service="$1"
    local suffix="$2"
    local config_file="$3"
    local role remote_host remote_port listen_port secret
    
    # Determine role and extract config
    if grep -q '^\[server\]' "$config_file"; then
        role="server"
        print_info "This is a SERVER tunnel"
    else
        role="client"
        print_info "This is a CLIENT tunnel"
    fi
    
    remote_host=$(grep '^remote_addr' "$config_file" | cut -d'"' -f2 | cut -d':' -f1)
    remote_port=$(grep '^restart_watcher_remote_port' "$config_file" | awk -F'=' '{print $2}' | tr -d ' "')
    listen_port=$(grep '^restart_watcher_listen_port' "$config_file" | awk -F'=' '{print $2}' | tr -d ' "')
    secret=$(grep '^restart_watcher_secret' "$config_file" | cut -d'"' -f2)
    remote_port=${remote_port:-45680}
    listen_port=${listen_port:-45679}
    secret=${secret:-$RESTART_WATCHER_SECRET}

    clear
    print_info "=== Watcher Configuration ==="
    echo
    
    echo
    print_info "The watcher helps both sides restart together when there are problems."
    echo
    
    # Show current secret
    if [[ -n "$secret" ]]; then
        print_info "Current secret: $secret"
        echo "Copy this to the other side."
        echo
    else
        print_info "No secret configured yet."
        echo
    fi
    
    # Port configuration with role-based defaults
    print_info "--- Ports ---"
    
    local default_listen_port default_remote_port
    if [[ "$role" == "server" ]]; then
        default_listen_port=45690
        default_remote_port=45680
        # Get remote host from config or ask user
        remote_host=$(grep '^restart_watcher_remote_host' "$config_file" | cut -d'"' -f2 2>/dev/null)
        if [[ -z "$remote_host" ]]; then
            read -p "Enter client IP address: " remote_host
        fi
    else
        default_listen_port=45680
        default_remote_port=45690
        # Get remote host from tunnel config
        remote_host=$(grep '^remote_addr' "$config_file" | cut -d'"' -f2 | cut -d':' -f1)
    fi
    
    # Use unified default value handling
    echo "Current receive port: ${listen_port:-$default_listen_port}"
    while true; do
        read -p "Port for receiving messages [${listen_port:-$default_listen_port}]: " new_listen_port
        new_listen_port=$(get_default_value "$new_listen_port" "${listen_port:-$default_listen_port}")
        if ! validate_port "$new_listen_port"; then
            print_warning "Invalid port number. Please enter a value between 1 and 65535."
            continue
        fi
        break
    done
    echo "Current send port: ${remote_port:-$default_remote_port}"
    while true; do
        read -p "Port for sending messages [${remote_port:-$default_remote_port}]: " new_remote_port
        new_remote_port=$(get_default_value "$new_remote_port" "${remote_port:-$default_remote_port}")
        if ! validate_port "$new_remote_port"; then
            print_warning "Invalid port number. Please enter a value between 1 and 65535."
            continue
        fi
        break
    done
    
    # Validate ports are different
    if [[ "$new_listen_port" == "$new_remote_port" ]]; then
        print_error "Receive and send ports must be different!"
        press_any_key
        return
    fi

    # Secret configuration
    echo
    print_info "--- Secret ---"
    if [[ -n "$secret" ]]; then
        if confirm_action "Keep current secret?" "y"; then
            new_secret="$secret"
        else
            new_secret="backhaul-watcher-naxon"
            print_info "New secret: $new_secret"
        fi
    else
        new_secret="backhaul-watcher-naxon"
        print_info "Generated secret: $new_secret"
    fi

    # Update config file
        sed -i '/^restart_watcher_secret/d' "$config_file"
        sed -i '/^restart_watcher_listen_port/d' "$config_file"
        sed -i '/^restart_watcher_remote_port/d' "$config_file"
    sed -i '/^restart_watcher_pid/d' "$config_file"
        echo "restart_watcher_secret = \"$new_secret\"" >> "$config_file"
        echo "restart_watcher_listen_port = $new_listen_port" >> "$config_file"
        echo "restart_watcher_remote_port = $new_remote_port" >> "$config_file"
    echo "restart_watcher_pid = $watcher_pid" >> "$config_file"
    
        print_success "Watcher config updated."
    press_any_key
}

test_watcher() {
    local service="$1"
    local suffix="$2"
    local config_file="$3"
    local role remote_host remote_port listen_port secret
    
    # Determine role and extract config
    if grep -q '^\[server\]' "$config_file"; then
        role="server"
        # For server, we need to get the client IP from the user since it's not in config
        print_info "This is a SERVER tunnel. You need to provide the client IP for testing."
        read -p "Enter client IP address for testing: " remote_host
        if [[ -z "$remote_host" ]]; then
            print_error "Client IP is required for testing."
            press_any_key
            return
        fi
    else
        role="client"
        remote_host=$(grep '^remote_addr' "$config_file" | cut -d'"' -f2 | cut -d':' -f1)
        if [[ -z "$remote_host" ]]; then
            print_error "Could not determine remote host from config."
            press_any_key
            return
        fi
    fi
    
    remote_port=$(grep '^restart_watcher_remote_port' "$config_file" | awk -F'=' '{print $2}' | tr -d ' "')
    listen_port=$(grep '^restart_watcher_listen_port' "$config_file" | awk -F'=' '{print $2}' | tr -d ' "')
    secret=$(grep '^restart_watcher_secret' "$config_file" | cut -d'"' -f2)
    remote_port=${remote_port:-45680}
    listen_port=${listen_port:-45679}
    secret=${secret:-backhaul-watcher-naxon}

    clear
    print_info "--- Watcher Test ---"
    echo "Remote host: $remote_host"
    echo "Remote port: $remote_port"
    echo "Listen port: $listen_port"
    echo "Role: $role"
    echo
    echo "1. Send test restart signal to remote"
    echo "2. Listen for test restart signal (manual receive)"
    echo "0. Back"
    read -p "Select [0-2]: " testopt
    case $testopt in
        1)
            print_info "Sending test RESTART_REQUEST to $remote_host:$remote_port ..."
            echo "RESTART_REQUEST:$secret:$role" | nc "$remote_host" "$remote_port" -w 2
            if [[ $? -eq 0 ]]; then
                print_success "Signal sent successfully."
            else
                print_error "Failed to send signal. Check network connectivity and firewall."
            fi
            press_any_key
            ;;
        2)
            print_info "Listening for test RESTART_REQUEST on port $listen_port ..."
            print_info "Press Ctrl+C to cancel"
            echo
            cancelled=0
            trap 'cancelled=1' SIGINT
            msg=$(nc -l -p "$listen_port" -w 30 2>/dev/null)
            trap - SIGINT
            if [[ $cancelled -eq 1 ]]; then
                echo
                print_info "Listen cancelled by user."
                press_any_key
                return
            fi
            if [[ "$msg" =~ ^RESTART_REQUEST:$secret: ]]; then
                local sender_role=${msg##*:}
                print_success "Received RESTART_REQUEST from $sender_role. Sending ACK back."
                echo "RESTART_ACK:$secret:$role" | nc "$remote_host" "$remote_port" -w 2
                print_info "ACK sent."
            else
                print_error "No valid RESTART_REQUEST received or timeout."
            fi
            press_any_key
            ;;
        0|*)
            return
            ;;
    esac
}

show_watcher_status() {
    local service="$1"
    local suffix="$2"
    local config_file="$3"
    local watcher_script="/tmp/backhaul-watcher-${suffix}.sh"
    local watcher_pid_file="/tmp/backhaul-watcher-${suffix}.pid"
    local watcher_log="/tmp/backhaul-watcher-${suffix}.log"
    
    clear
    print_info "=== Watcher Status ==="
    echo
    
    # Check if watcher is enabled in config
    local enabled=$(grep '^restart_watcher_enabled' "$config_file" | cut -d'"' -f2 2>/dev/null)
    if [[ "$enabled" == "y" ]]; then
        print_success "Watcher is enabled in configuration"
    else
        print_warning "Watcher is not enabled in configuration"
    fi
    
    # Check if watcher script exists
    if [[ -f "$watcher_script" ]]; then
        print_success "Watcher script exists: $watcher_script"
    else
        print_warning "Watcher script not found"
    fi
    
    # Check if watcher process is running
    if [[ -f "$watcher_pid_file" ]]; then
        local watcher_pid=$(cat "$watcher_pid_file")
        if [[ -n "$watcher_pid" ]] && kill -0 "$watcher_pid" 2>/dev/null; then
            print_success "Watcher process is running (PID: $watcher_pid)"
        else
            print_error "Watcher process is not running (PID file exists but process dead)"
        fi
    else
        print_warning "Watcher process not found"
    fi
    
    # Show configuration
    echo
    print_info "--- Configuration ---"
    local secret listen_port remote_port
    secret=$(grep '^restart_watcher_secret' "$config_file" | cut -d'"' -f2)
    listen_port=$(grep '^restart_watcher_listen_port' "$config_file" | awk -F'=' '{print $2}' | tr -d ' "')
    remote_port=$(grep '^restart_watcher_remote_port' "$config_file" | awk -F'=' '{print $2}' | tr -d ' "')
    
    echo "Secret: ${secret:-not set}"
    echo "Listen port: ${listen_port:-not set}"
    echo "Remote port: ${remote_port:-not set}"
    
    # Show recent logs if available
    if [[ -f "$watcher_log" ]]; then
        echo
        print_info "--- Recent Logs ---"
        tail -n 5 "$watcher_log" 2>/dev/null || echo "No logs available"
    fi
    
    press_any_key
}

show_watcher_logs() {
    local service="$1"
    local suffix="$2"
    local config_file="$3"
    local watcher_log="/tmp/backhaul-watcher-${suffix}.log"
    clear
    print_info "=== Watcher Logs ==="
    if [[ -f "$watcher_log" ]]; then
    print_info "Last 20 lines of watcher logs:"
        tail -n 20 "$watcher_log"
    echo
        read -p "View full log? (y/n) [n]: " viewfull
        viewfull=${viewfull:-n}
    if [[ "${viewfull,,}" == "y" ]]; then
            less "$watcher_log"
        fi
    else
        print_warning "The watcher may not be running or has not generated any logs yet."
    fi
    press_any_key
}

# --- Watcher Submenu Help ---
watcher_submenu_help() {
    clear
    print_info "================= Coordinated Restart Watcher Help ================="
    echo "This submenu lets you manage the coordinated restart watcher for this tunnel."
    echo
    print_info "What the watcher does:"
    echo "• Monitors tunnel logs for error patterns (e.g., ERROR|FATAL)"
    echo "• When an error is detected, coordinates a restart with the remote side"
    echo "• Uses a secure netcat-based protocol for communication"
    echo "• Automatically restarts both sides in a coordinated manner"
    echo
    print_info "Configuration requirements:"
    echo "• Listen port: Where this side receives restart requests from remote"
    echo "• Remote port: Where this side sends restart requests to remote"
    echo "• Secret: Must be identical on both sides (client and server)"
    echo "• Error pattern: Regex pattern to trigger restarts (default: ERROR|FATAL)"
    echo "• Delays: Time to wait before restarting each side"
    echo
    print_warning "IMPORTANT: Port configuration must be opposite on both sides!"
    echo "  If this side listens on 45679, remote must send to 45679"
    echo "  If this side sends to 45680, remote must listen on 45680"
    echo
    echo "Menu options:"
    echo " 1. Enable watcher: Set up and start the watcher background process."
    echo " 2. Disable watcher: Stop and remove the watcher background process."
    echo " 3. Edit watcher config: Change error pattern, delays, secret, and ports."
    echo " 4. Show watcher status: View watcher script content."
    echo " 5. Show watcher logs: View recent logs for the watcher."
    echo " 6. Test watcher: Send or receive a test restart signal."
    echo " 0. Back: Return to tunnel management."
    press_any_key
}

# --- Technical Enhancement Functions ---

# Show health and performance metrics for a tunnel
show_health_and_performance() {
    local tunnel_name="$1"
    local service="$2"
    
    clear
    print_info "=== Health Check & Performance Metrics ==="
    echo
    
    # Initialize logging if not already done
    init_logging
    
    # Check tunnel health
    print_info "--- Tunnel Health Status ---"
    local health_status
    health_status=$(check_tunnel_health "$tunnel_name")
    
    case "$health_status" in
        "running")
            print_success "✓ Tunnel is running"
            ;;
        "dead")
            print_error "✗ Tunnel process is dead"
            ;;
        "not_started")
            print_warning "⚠ Tunnel is not started"
            ;;
        *)
            print_warning "? Tunnel status unknown"
            ;;
    esac
    
    # Check system resources
    echo
    print_info "--- System Resources ---"
    check_system_resources
    
    # Show performance metrics
    echo
    print_info "--- Performance Metrics ---"
    if [[ -f "$PERFORMANCE_LOG_FILE" ]]; then
        local recent_ops
        recent_ops=$(tail -n 10 "$PERFORMANCE_LOG_FILE" 2>/dev/null)
        if [[ -n "$recent_ops" ]]; then
            echo "Recent operations:"
            echo "$recent_ops" | while IFS= read -r line; do
                if [[ "$line" =~ \"operation\":\"([^\"]+)\",\"duration\":([0-9]+),\"success\":(true|false) ]]; then
                    local op="${BASH_REMATCH[1]}"
                    local duration="${BASH_REMATCH[2]}"
                    local success="${BASH_REMATCH[3]}"
                    local status_icon=$([[ "$success" == "true" ]] && echo "✓" || echo "✗")
                    echo "  $status_icon $op: ${duration}s"
                fi
            done
        else
            echo "No performance data available"
        fi
    else
        echo "No performance data available"
    fi
    
    # Show health history
    echo
    print_info "--- Health History ---"
    if [[ -f "$HEALTH_LOG_FILE" ]]; then
        local recent_health
        recent_health=$(tail -n 5 "$HEALTH_LOG_FILE" 2>/dev/null)
        if [[ -n "$recent_health" ]]; then
            echo "Recent health checks:"
            echo "$recent_health" | while IFS= read -r line; do
                if [[ "$line" =~ \"timestamp\":\"([^\"]+)\",\"tunnel\":\"([^\"]+)\",\"status\":\"([^\"]+)\" ]]; then
                    local timestamp="${BASH_REMATCH[1]}"
                    local tunnel="${BASH_REMATCH[2]}"
                    local status="${BASH_REMATCH[3]}"
                    local status_icon
                    case "$status" in
                        "running") status_icon="✓" ;;
                        "dead") status_icon="✗" ;;
                        "not_started") status_icon="⚠" ;;
                        *) status_icon="?" ;;
                    esac
                    echo "  $status_icon $timestamp: $status"
                fi
            done
        else
            echo "No health history available"
        fi
    else
        echo "No health history available"
    fi
    
    # Optimize process priority
    echo
    print_info "--- Process Optimization ---"
    optimize_process_priority "$tunnel_name"
    
    press_any_key
}

# Validate tunnel configuration
validate_tunnel_config() {
    local config_file="$1"
    
    if [[ ! -f "$config_file" ]]; then
        print_error "Configuration file not found: $config_file"
        press_any_key
        return 1
    fi
    
    # Initialize logging if not already done
    init_logging
    
    # Run comprehensive validation using the validation module
    validate_config_detailed "$config_file"
    return $?
}

# Graceful restart with health checks and error recovery
graceful_restart_with_ui() {
    local tunnel_name="$1"
    local service="backhaul-$tunnel_name"
    
    clear
    print_info "=== Graceful Restart ==="
    echo
    
    # Initialize logging if not already done
    init_logging
    
    print_info "Starting graceful restart for tunnel: $tunnel_name"
    echo
    
    # Check current health
    print_info "--- Pre-restart Health Check ---"
    local pre_health
    pre_health=$(check_tunnel_health "$tunnel_name")
    print_info "Current status: $pre_health"
    
    # Check system resources
    print_info "--- System Resources ---"
    check_system_resources
    
    # Perform graceful restart with performance tracking
    echo
    print_info "--- Performing Graceful Restart ---"
    with_performance_tracking "graceful_restart" graceful_restart "$tunnel_name"
    local restart_result=$?
    
    # Post-restart health check
    echo
    print_info "--- Post-restart Health Check ---"
    sleep 3  # Give service time to stabilize
    local post_health
    post_health=$(check_tunnel_health "$tunnel_name")
    print_info "New status: $post_health"
    
    # Summary
    echo
    print_info "--- Restart Summary ---"
    if [[ $restart_result -eq 0 && "$post_health" == "running" ]]; then
        print_success "\u2713 Graceful restart completed successfully"
        print_info "Tunnel is healthy and running"
    else
        print_error "\u2717 Graceful restart failed or tunnel is unhealthy"
        print_info "Current status: $post_health"
        
        if confirm_action "Would you like to attempt recovery?" "y"; then
            print_info "Attempting error recovery..."
            attempt_error_recovery "tunnel_start" "Graceful restart failed"
        fi
    fi
    
    press_any_key
    return $restart_result
}

create_tunnel() {
    local tunnel_name
    local server_ip
    local server_port
    local local_port
    local protocol
    
    # Rate limiting check
    if ! rate_limit_check "create_tunnel" 5; then
        echo "⚠ Rate limit exceeded. Please wait before creating another tunnel."
        return 1
    fi
    
    echo "=== Create New Tunnel ==="
    echo "💡 Tip: Use descriptive names like 'office-vpn' or 'home-connection'"
    
    # Input validation with sanitization
    while true; do
        read -p "Enter tunnel name: " tunnel_name
        tunnel_name=$(sanitize_input "$tunnel_name" 50)
        
        if [ -z "$tunnel_name" ]; then
            echo "❌ Tunnel name cannot be empty"
            continue
        fi
        
        if [[ ! "$tunnel_name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
            echo "❌ Tunnel name can only contain letters, numbers, hyphens, and underscores"
            continue
        fi
        
        if [ -d "$TUNNEL_DIR/$tunnel_name" ]; then
            echo "❌ Tunnel '$tunnel_name' already exists"
            continue
        fi
        
        break
    done
    
    while true; do
        read -p "Enter server IP address: " server_ip
        server_ip=$(sanitize_input "$server_ip" 15)
        
        if ! validate_ip "$server_ip"; then
            echo "❌ Invalid IP address format"
            continue
        fi
        
        break
    done
    
    while true; do
        read -p "Enter server port (1-65535): " server_port
        server_port=$(sanitize_input "$server_port" 5)
        
        if ! validate_port "$server_port"; then
            echo "❌ Invalid port number (must be 1-65535)"
            continue
        fi
        
        break
    done
    
    while true; do
        read -p "Enter local port (1-65535): " local_port
        local_port=$(sanitize_input "$local_port" 5)
        
        if ! validate_port "$local_port"; then
            echo "❌ Invalid port number (must be 1-65535)"
            continue
        fi
        
        # Check if port is already in use
        if is_port_in_use "$local_port"; then
            echo "❌ Port $local_port is already in use"
            continue
        fi
        
        break
    done
    
    echo "Select protocol:"
    echo "1) TCP"
    echo "2) UDP"
    read -p "Enter choice (1-2): " protocol_choice
    
    case $protocol_choice in
        1) protocol="tcp" ;;
        2) protocol="udp" ;;
        *) protocol="tcp" ;;
    esac
    
    # Performance monitoring wrapper
    monitor_performance "create_tunnel_impl" "$tunnel_name" "$server_ip" "$server_port" "$local_port" "$protocol"
}

create_tunnel_impl() {
    local tunnel_name="$1"
    local server_ip="$2"
    local server_port="$3"
    local local_port="$4"
    local protocol="$5"
    
    local tunnel_dir="$TUNNEL_DIR/$tunnel_name"
    local config_file="$tunnel_dir/config"
    
    # Create tunnel directory with secure permissions
    mkdir -p "$tunnel_dir"
    harden_permissions "$tunnel_dir"
    
    # Create configuration with secure write
    local config_content="TUNNEL_NAME=$tunnel_name
SERVER_IP=$server_ip
SERVER_PORT=$server_port
LOCAL_PORT=$local_port
PROTOCOL=$protocol
CREATED_DATE=$(date '+%Y-%m-%d %H:%M:%S')
STATUS=stopped"
    
    secure_write "$config_file" "$config_content"
    secure_config_file "$config_file"
    
    # Create tunnel script with secure permissions
    local tunnel_script="$tunnel_dir/tunnel.sh"
    cat > "$tunnel_script" << EOF
#!/bin/bash
# Secure tunnel script for $tunnel_name
# Auto-generated by EasyBackhaul

source "$SCRIPT_DIR/globals.sh"
source "$SCRIPT_DIR/helpers.sh"

TUNNEL_NAME="$tunnel_name"
SERVER_IP="$server_ip"
SERVER_PORT="$server_port"
LOCAL_PORT="$local_port"
PROTOCOL="$protocol"

# Security: Drop privileges if running as root
if [ "\$(id -u)" -eq 0 ]; then
    exec su -s /bin/bash -c "\$0 \$*" "\$SUDO_USER"
fi

# Rate limiting
if ! rate_limit_check "tunnel_connect" 10; then
    log_message "ERROR" "Rate limit exceeded for tunnel $tunnel_name"
    exit 1
fi

# Input validation
if ! validate_ip "\$SERVER_IP" || ! validate_port "\$SERVER_PORT" || ! validate_port "\$LOCAL_PORT"; then
    log_message "ERROR" "Invalid configuration for tunnel $tunnel_name"
    exit 1
fi

# Secure logging
secure_log_message "INFO" "Starting tunnel $tunnel_name"

# Start tunnel with performance monitoring
monitor_performance "start_tunnel_connection" "\$SERVER_IP" "\$SERVER_PORT" "\$LOCAL_PORT" "\$PROTOCOL"
EOF
    
    chmod 700 "$tunnel_script"
    
    # Create UFW rules
    create_ufw_rules "$tunnel_name" "$server_ip" "$server_port" "$local_port" "$protocol"
    
    # Update main config
    update_config_file "$tunnel_name" "$server_ip" "$server_port" "$local_port" "$protocol"
    
    echo "✅ Tunnel '$tunnel_name' created successfully"
    echo "📁 Location: $tunnel_dir"
    echo "🔒 Permissions hardened for security"
    
    # Security audit
    audit_security
    
    # Performance optimization
    cleanup_temp_files
}

delete_tunnel() {
    local tunnel_name="$1"
    
    if [ -z "$tunnel_name" ]; then
        echo "❌ Tunnel name is required"
        return 1
    fi
    
    # Input sanitization
    tunnel_name=$(sanitize_input "$tunnel_name" 50)
    
    local tunnel_dir="$TUNNEL_DIR/$tunnel_name"
    
    if [ ! -d "$tunnel_dir" ]; then
        echo "❌ Tunnel '$tunnel_name' not found"
        return 1
    fi
    
    # Confirm deletion with security warning
    echo "⚠ SECURITY WARNING: This will permanently delete tunnel '$tunnel_name'"
    echo "   - All configuration files will be securely erased"
    echo "   - UFW rules will be removed"
    echo "   - Any running processes will be terminated"
    echo ""
    read -p "Type 'DELETE' to confirm: " confirmation
    
    if [ "$confirmation" != "DELETE" ]; then
        echo "❌ Deletion cancelled"
        return 1
    fi
    
    # Performance monitoring wrapper
    monitor_performance "delete_tunnel_impl" "$tunnel_name"
}

delete_tunnel_impl() {
    local tunnel_name="$1"
    local tunnel_dir="$TUNNEL_DIR/$tunnel_name"
    
    # Stop tunnel if running
    stop_tunnel "$tunnel_name" 2>/dev/null
    
    # Remove UFW rules
    remove_ufw_rules "$tunnel_name"
    
    # Securely delete all files
    if [ -d "$tunnel_dir" ]; then
        find "$tunnel_dir" -type f -exec secure_delete {} \;
        rm -rf "$tunnel_dir"
    fi
    
    # Remove from main config
    remove_from_config "$tunnel_name"
    
    # Clean up watcher files if they exist
    cleanup_watcher_files "$tunnel_name"
    
    echo "✅ Tunnel '$tunnel_name' securely deleted"
    
    # Performance optimization
    cleanup_temp_files
}

start_tunnel() {
    local tunnel_name="$1"
    
    if [ -z "$tunnel_name" ]; then
        echo "❌ Tunnel name is required"
        return 1
    fi
    
    # Input sanitization
    tunnel_name=$(sanitize_input "$tunnel_name" 50)
    
    # Rate limiting check
    if ! rate_limit_check "start_tunnel" 10; then
        echo "⚠ Rate limit exceeded. Please wait before starting another tunnel."
        return 1
    fi
    
    local tunnel_dir="$TUNNEL_DIR/$tunnel_name"
    local config_file="$tunnel_dir/config"
    local tunnel_script="$tunnel_dir/tunnel.sh"
    
    if [ ! -d "$tunnel_dir" ]; then
        echo "❌ Tunnel '$tunnel_name' not found"
        return 1
    fi
    
    if [ ! -f "$config_file" ]; then
        echo "❌ Configuration file not found"
        return 1
    fi
    
    # Load configuration with validation
    source "$config_file"
    
    if ! validate_ip "$SERVER_IP" || ! validate_port "$SERVER_PORT" || ! validate_port "$LOCAL_PORT"; then
        echo "❌ Invalid configuration detected"
        return 1
    fi
    
    # Check if already running
    if is_tunnel_running "$tunnel_name"; then
        echo "⚠ Tunnel '$tunnel_name' is already running"
        return 0
    fi
    
    # Performance monitoring wrapper
    monitor_performance "start_tunnel_impl" "$tunnel_name"
}

start_tunnel_impl() {
    local tunnel_name="$1"
    local tunnel_dir="$TUNNEL_DIR/$tunnel_name"
    local tunnel_script="$tunnel_dir/tunnel.sh"
    
    # Security: Verify script permissions
    if [ "$(stat -c %a "$tunnel_script" 2>/dev/null)" != "700" ]; then
        echo "❌ Security: Tunnel script has insecure permissions"
        chmod 700 "$tunnel_script"
    fi
    
    # Start tunnel in background with secure logging
    nohup "$tunnel_script" > "$tunnel_dir/tunnel.log" 2>&1 &
    local pid=$!
    
    # Create PID file with secure permissions
    echo "$pid" > "$tunnel_dir/tunnel.pid"
    chmod 600 "$tunnel_dir/tunnel.pid"
    
    # Update status
    update_tunnel_status "$tunnel_name" "running"
    
    # Secure logging
    secure_log_message "INFO" "Started tunnel $tunnel_name (PID: $pid)"
    
    echo "✅ Tunnel '$tunnel_name' started successfully"
    echo "📊 PID: $pid"
    echo "📝 Logs: $tunnel_dir/tunnel.log"
    
    # Performance monitoring
    echo "💻 System resources: $(get_system_resources)"
}

stop_tunnel() {
    local tunnel_name="$1"
    
    if [ -z "$tunnel_name" ]; then
        echo "❌ Tunnel name is required"
        return 1
    fi
    
    # Input sanitization
    tunnel_name=$(sanitize_input "$tunnel_name" 50)
    
    local tunnel_dir="$TUNNEL_DIR/$tunnel_name"
    local pid_file="$tunnel_dir/tunnel.pid"
    
    if [ ! -d "$tunnel_dir" ]; then
        echo "❌ Tunnel '$tunnel_name' not found"
        return 1
    fi
    
    if [ ! -f "$pid_file" ]; then
        echo "⚠ Tunnel '$tunnel_name' is not running"
        return 0
    fi
    
    # Performance monitoring wrapper
    monitor_performance "stop_tunnel_impl" "$tunnel_name"
}

stop_tunnel_impl() {
    local tunnel_name="$1"
    local tunnel_dir="$TUNNEL_DIR/$tunnel_name"
    local pid_file="$tunnel_dir/tunnel.pid"
    
    local pid=$(cat "$pid_file" 2>/dev/null)
    
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        # Graceful shutdown
        kill -TERM "$pid" 2>/dev/null
        
        # Wait for graceful shutdown
        local count=0
        while kill -0 "$pid" 2>/dev/null && [ $count -lt 10 ]; do
            sleep 1
            ((count++))
        done
        
        # Force kill if still running
        if kill -0 "$pid" 2>/dev/null; then
            kill -KILL "$pid" 2>/dev/null
            echo "⚠ Force killed tunnel process"
        fi
    fi
    
    # Securely delete PID file
    secure_delete "$pid_file"
    
    # Update status
    update_tunnel_status "$tunnel_name" "stopped"
    
    # Secure logging
    secure_log_message "INFO" "Stopped tunnel $tunnel_name"
    
    echo "✅ Tunnel '$tunnel_name' stopped successfully"
    
    # Performance optimization
    optimize_memory_usage
} 
# --- MODULE: modules/restart_watcher.sh ---
#!/bin/bash
# restart_watcher.sh - Per-tunnel coordinated restart watcher for EasyBackhaul
# This script is intended to be sourced or built into the main script, or run as a systemd service.

# Required environment/config variables (set by main script or systemd):
#   SERVICE_NAME         - systemd service name (e.g. backhaul-client-xxx.service)
#   LOG_PATTERN          - regex for error detection (e.g. 'ERROR|FATAL')
#   REMOTE_HOST          - IP or hostname of the remote side
#   REMOTE_PORT          - netcat port on remote (default: 45678)
#   RESTART_SECRET       - shared secret for authentication
#   RESTART_DELAY_LOCAL  - seconds to wait before local restart (default: 10)
#   RESTART_DELAY_REMOTE - seconds to wait before remote restart (default: 10)
#   MAX_RETRIES          - max restart request attempts (default: 3)
#   ROLE                 - 'client' or 'server' (for logging)
#   LISTEN_PORT          - local port to listen for restart requests (default: 45678)

# --- Defaults ---
RESTART_DELAY_LOCAL=${RESTART_DELAY_LOCAL:-10}
RESTART_DELAY_REMOTE=${RESTART_DELAY_REMOTE:-10}
MAX_RETRIES=${MAX_RETRIES:-3}
LISTEN_PORT=${LISTEN_PORT:-45679}
REMOTE_PORT=${REMOTE_PORT:-45680}
RESTART_SECRET=${RESTART_SECRET:-$RESTART_WATCHER_SECRET}
ROLE=${ROLE:-unknown}

# --- Helper: Log ---
log() { echo "[RestartWatcher][$ROLE][$(date +'%F %T')] $1"; }

# --- Main Entrypoint ---
restart_watcher_main() {
    # Set defaults if not provided
    RESTART_DELAY_LOCAL=${RESTART_DELAY_LOCAL:-10}
    RESTART_DELAY_REMOTE=${RESTART_DELAY_REMOTE:-10}
    MAX_RETRIES=${MAX_RETRIES:-3}
    LISTEN_PORT=${LISTEN_PORT:-45679}
    REMOTE_PORT=${REMOTE_PORT:-45680}
    RESTART_SECRET=${RESTART_SECRET:-$RESTART_WATCHER_SECRET}
    ROLE=${ROLE:-unknown}
    
    # Validate required environment variables
    if [[ -z "$SERVICE_NAME" ]]; then
        log "ERROR: SERVICE_NAME environment variable is required"
        exit 1
    fi
    
    if [[ -z "$REMOTE_HOST" || "$REMOTE_HOST" == "0.0.0.0" ]]; then
        log "ERROR: REMOTE_HOST environment variable is required and cannot be 0.0.0.0"
        exit 1
    fi
    
    log "Starting restart watcher for service: $SERVICE_NAME"
    log "Remote host: $REMOTE_HOST:$REMOTE_PORT"
    log "Listen port: $LISTEN_PORT"
    log "Role: $ROLE"
    
    # Start listener in background
    restart_listener &
    LISTENER_PID=$!
    
    # Set up signal handlers for clean shutdown
    trap 'log "Received shutdown signal. Cleaning up..."; kill $LISTENER_PID 2>/dev/null; exit 0' SIGTERM SIGINT
    
    # Start log monitor
    monitor_and_restart
    
    # Cleanup
    kill $LISTENER_PID 2>/dev/null
}

# --- Function: Listen for restart requests (in background) ---
restart_listener() {
    while true; do
        # Listen for a single line (timeout 60s to allow clean exit)
        local msg
        msg=$(nc -l -p "$LISTEN_PORT" -w 60 2>/dev/null)
        if [[ "$msg" =~ ^RESTART_REQUEST:(.+):(.+)$ ]]; then
            local secret=${BASH_REMATCH[1]}
            local sender_role=${BASH_REMATCH[2]}
            if [[ "$secret" == "$RESTART_SECRET" ]]; then
                log "Received RESTART_REQUEST from $sender_role. Sending ACK and scheduling restart."
                # Send ACK back to sender
                echo "RESTART_ACK:$RESTART_SECRET:$ROLE" | nc "$REMOTE_HOST" "$REMOTE_PORT" -w 2
                # Schedule restart after delay
                (sleep "$RESTART_DELAY_REMOTE"; systemctl restart "$SERVICE_NAME"; log "Service restarted (listener)") &
            else
                log "Received RESTART_REQUEST with invalid secret. Ignoring."
            fi
        elif [[ "$msg" =~ ^RESTART_ACK:(.+):(.+)$ ]]; then
            # This is an ACK for a request we sent
            local secret=${BASH_REMATCH[1]}
            local ack_role=${BASH_REMATCH[2]}
            if [[ "$secret" == "$RESTART_SECRET" ]]; then
                log "Received RESTART_ACK from $ack_role."
                # Touch a file to signal ACK received
                touch "/tmp/restart_ack_${SERVICE_NAME}"
            fi
        fi
    done
}

# --- Function: Monitor logs and trigger coordinated restart ---
monitor_and_restart() {
    log "Starting log monitor for $SERVICE_NAME (pattern: $LOG_PATTERN)"
    journalctl -u "$SERVICE_NAME" -f --no-pager | while read -r line; do
        if [[ "$line" =~ $LOG_PATTERN ]]; then
            log "Error detected in logs. Initiating coordinated restart."
            # Try to send restart request and wait for ACK
            local attempt=1
            while (( attempt <= MAX_RETRIES )); do
                log "Sending RESTART_REQUEST to $REMOTE_HOST:$REMOTE_PORT (attempt $attempt)"
                echo "RESTART_REQUEST:$RESTART_SECRET:$ROLE" | nc "$REMOTE_HOST" "$REMOTE_PORT" -w 2
                # Wait for ACK (up to 10s)
                for i in {1..10}; do
                    if [ -f "/tmp/restart_ack_${SERVICE_NAME}" ]; then
                        rm -f "/tmp/restart_ack_${SERVICE_NAME}"
                        log "ACK received. Scheduling local restart in $RESTART_DELAY_LOCAL seconds."
                        sleep "$RESTART_DELAY_LOCAL"
                        systemctl restart "$SERVICE_NAME"
                        log "Service restarted (initiator)"
                        return
                    fi
                    sleep 1
                done
                log "No ACK received. Retrying..."
                ((attempt++))
            done
            log "Failed to coordinate restart after $MAX_RETRIES attempts. Local restart only."
            sleep "$RESTART_DELAY_LOCAL"
            systemctl restart "$SERVICE_NAME"
            log "Service restarted (local only)"
            return
        fi
    done
} 
# --- MODULE: modules/cron.sh ---
# cron.sh
# Cron job management for auto-restart 

# --- Cron Management ---
manage_cron_menu() {
    local service=$1
    while true; do
        clear
        print_server_info_banner
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
       (crontab -l 2>/dev/null | grep -v "$service") | crontab -
       print_success "Cron job for $service removed."
    fi
} 
# --- MODULE: modules/menu.sh ---
# menu.sh
# Main menu logic and script entrypoint 

# --- Installation Wizard ---
installation_wizard() {
    print_menu_header "EasyBackhaul Installation Wizard (v13.0-beta)" "Core by Musixal  |  Installer by @N4Xon"
    echo
    print_info "Welcome to EasyBackhaul! This wizard will help you install the Backhaul binary."
    echo
    print_info "Please choose your preferred installation method:"
    echo
    echo " 1. Automatic GitHub Download (Recommended)"
    echo "    - Downloads latest version from GitHub"
    echo "    - Includes connection testing and fallback options"
    echo
    echo " 2. Local File Installation"
    echo "    - Use a binary file you've downloaded manually"
    echo "    - Supports .tar.gz, .zip, or direct binary files"
    echo
    echo " 3. Alternative Download Source"
    echo "    - Download from your own server or alternative URL"
    echo "    - Useful when GitHub is not accessible"
    echo
    echo " 4. Network Diagnostics"
    echo "    - Test connectivity to various sources"
    echo "    - Help diagnose network issues"
    echo
    echo " 5. Skip Installation (Advanced)"
    echo "    - Continue without installing binary"
    echo "    - You can install manually later"
    echo
    echo " ?. Help & Information"
    echo " 0. Exit"
    echo
    print_info "----------------------------------------------------------------"
    read -p "Please select an option [0-5, ? for help]: " install_choice

    case $install_choice in
        1) 
            print_info "Starting automatic GitHub download..."
            if download_backhaul; then
                print_success "Installation completed successfully!"
                press_any_key
                return 0
            else
                print_warning "Installation failed or was cancelled."
                press_any_key
                return 1
            fi
            ;;
        2) 
            print_info "Starting local file installation..."
            local os=$(uname -s | tr '[:upper:]' '[:lower:]')
            local arch=$(uname -m)
            case $arch in
                x86_64) arch="amd64" ;;
                aarch64) arch="arm64" ;;
                *) print_error "Unsupported architecture: $arch"; press_any_key; return 1 ;;
            esac
            if download_from_local_file "$os" "$arch"; then
                print_success "Local installation completed successfully!"
                press_any_key
                return 0
            else
                print_warning "Local installation failed or was cancelled."
                press_any_key
                return 1
            fi
            ;;
        3) 
            print_info "Starting alternative source download..."
            local os=$(uname -s | tr '[:upper:]' '[:lower:]')
            local arch=$(uname -m)
            case $arch in
                x86_64) arch="amd64" ;;
                aarch64) arch="arm64" ;;
                *) print_error "Unsupported architecture: $arch"; press_any_key; return 1 ;;
            esac
            if download_from_alternative_source "$os" "$arch"; then
                print_success "Alternative installation completed successfully!"
                press_any_key
                return 0
            else
                print_warning "Alternative installation failed or was cancelled."
                press_any_key
                return 1
            fi
            ;;
        4) 
            test_network_connectivity
            # After testing, return to installation wizard
            installation_wizard
            return 0
            ;;
        5) 
            print_warning "Skipping binary installation."
            print_info "You can install the binary manually later using option 3 in the main menu."
            print_info "Make sure to place it at: $BIN_PATH"
            press_any_key
            return 0
            ;;
        \?) 
            show_installation_help
            installation_wizard
            return 0
            ;;
        0) 
            print_info "Exiting EasyBackhaul installer."
            exit 0
            ;;
        *) 
            print_warning "Invalid option."
            press_any_key
            installation_wizard
            return 0
            ;;
    esac
}

# Show installation-specific help
show_installation_help() {
    clear
    print_server_info_banner
    print_info "--- Installation Help ---"
    echo
    print_info "Installation Methods:"
    echo
    echo "1. Automatic GitHub Download:"
    echo "   - Best for most users with internet access"
    echo "   - Automatically tests connectivity and provides fallbacks"
    echo "   - Downloads the latest stable version"
    echo
    echo "2. Local File Installation:"
    echo "   - Use when you have the binary file locally"
    echo "   - Download from: https://github.com/Musixal/Backhaul/releases"
    echo "   - Look for: backhaul_linux_amd64.tar.gz (or arm64)"
    echo
    echo "3. Alternative Download Source:"
    echo "   - Use when GitHub is blocked or inaccessible"
    echo "   - Provide URL to your own server or mirror"
    echo "   - Must point to a .tar.gz file containing the binary"
    echo
    echo "4. Network Diagnostics:"
    echo "   - Test connectivity to various sources"
    echo "   - Help identify network issues"
    echo "   - Useful for troubleshooting"
    echo
    echo "5. Skip Installation:"
    echo "   - Continue without binary (advanced users)"
    echo "   - Install manually later if needed"
    echo
    print_info "System Requirements:"
    echo "- Linux system (x86_64 or aarch64)"
    echo "- Root/sudo access"
    echo "- Internet connection (for automatic download)"
    echo "- Basic system tools (curl, wget, tar, etc.)"
    echo
    press_any_key
}

# --- System Health & Performance Monitor ---
show_system_health_monitor() {
    clear
    print_info "=== System Health & Performance Monitor ==="
    echo
    
    # Initialize logging if not already done
    init_logging
    
    # Check system resources
    print_info "--- System Resources ---"
    check_system_resources
    
    # Check all tunnels health
    echo
    print_info "--- Tunnel Health Status ---"
    local tunnels
    tunnels=$(find "$CONFIG_DIR" -name "*.conf" -exec basename {} .conf \; 2>/dev/null)
    
    if [[ -n "$tunnels" ]]; then
        local healthy_count=0
        local total_count=0
        
        for tunnel in $tunnels; do
            local health_status
            health_status=$(check_tunnel_health "$tunnel")
            ((total_count++))
            
            case "$health_status" in
                "running")
                    print_success "✓ $tunnel: Running"
                    ((healthy_count++))
                    ;;
                "dead")
                    print_error "✗ $tunnel: Dead"
                    ;;
                "not_started")
                    print_warning "⚠ $tunnel: Not Started"
                    ;;
                *)
                    print_warning "? $tunnel: Unknown"
                    ;;
            esac
        done
        
        echo
        print_info "Health Summary: $healthy_count/$total_count tunnels healthy"
        
        if [[ $healthy_count -eq $total_count ]]; then
            print_success "All tunnels are healthy!"
        elif [[ $healthy_count -eq 0 ]]; then
            print_error "No tunnels are healthy!"
        else
            print_warning "Some tunnels need attention"
        fi
    else
        print_warning "No tunnels found"
    fi
    
    # Show performance metrics
    echo
    print_info "--- Performance Metrics ---"
    if [[ -f "$PERFORMANCE_LOG_FILE" ]]; then
        local recent_ops
        recent_ops=$(tail -n 10 "$PERFORMANCE_LOG_FILE" 2>/dev/null)
        if [[ -n "$recent_ops" ]]; then
            echo "Recent operations:"
            echo "$recent_ops" | while IFS= read -r line; do
                if [[ "$line" =~ \"operation\":\"([^\"]+)\",\"duration\":([0-9]+),\"success\":(true|false) ]]; then
                    local op="${BASH_REMATCH[1]}"
                    local duration="${BASH_REMATCH[2]}"
                    local success="${BASH_REMATCH[3]}"
                    local status_icon=$([[ "$success" == "true" ]] && echo "✓" || echo "✗")
                    echo "  $status_icon $op: ${duration}s"
                fi
            done
        else
            echo "No performance data available"
        fi
    else
        echo "No performance data available"
    fi
    
    # Show system services status
    echo
    print_info "--- System Services ---"
    local backhaul_services
    backhaul_services=$(systemctl list-unit-files --type=service 'backhaul-*.service' --no-legend | awk '{print $1}' | grep -v 'backhaul-watcher-')
    
    if [[ -n "$backhaul_services" ]]; then
        for service in $backhaul_services; do
            if systemctl is-active --quiet "$service"; then
                print_success "✓ $service: Active"
            else
                print_error "✗ $service: Inactive"
            fi
        done
    else
        print_warning "No Backhaul services found"
    fi
    
    # Show watcher status
    echo
    print_info "--- Watcher Status ---"
    local watcher_pid_files
    watcher_pid_files=$(find /tmp -name "backhaul-watcher-*.pid" 2>/dev/null)
    
    if [[ -n "$watcher_pid_files" ]]; then
        for pid_file in $watcher_pid_files; do
            local tunnel_name
            tunnel_name=$(basename "$pid_file" .pid | sed 's/backhaul-watcher-//')
            local pid
            pid=$(cat "$pid_file" 2>/dev/null)
            
            if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
                print_success "✓ Watcher for $tunnel_name: Running (PID: $pid)"
            else
                print_error "✗ Watcher for $tunnel_name: Dead"
            fi
        done
    else
        print_warning "No watchers found"
    fi
    
    # Show disk usage
    echo
    print_info "--- Disk Usage ---"
    local disk_usage
    disk_usage=$(df -h / | awk 'NR==2 {print $5}')
    local usage_percent
    usage_percent=$(echo "$disk_usage" | sed 's/%//')
    
    if [[ $usage_percent -gt 90 ]]; then
        print_error "Critical disk usage: $disk_usage"
    elif [[ $usage_percent -gt 80 ]]; then
        print_warning "High disk usage: $disk_usage"
    else
        print_success "Disk usage: $disk_usage"
    fi
    
    # Show log file sizes
    echo
    print_info "--- Log Files ---"
    if [[ -d "$LOG_DIR" ]]; then
        local log_files
        log_files=$(find "$LOG_DIR" -name "*.log" -type f 2>/dev/null)
        if [[ -n "$log_files" ]]; then
            for log_file in $log_files; do
                local size
                size=$(du -h "$log_file" 2>/dev/null | cut -f1)
                local filename
                filename=$(basename "$log_file")
                echo "  $filename: $size"
            done
        else
            echo "No log files found"
        fi
    else
        echo "Log directory not found"
    fi
    
    # Action menu
    echo
    print_info "--- Actions ---"
    echo " 1. Refresh health status"
    echo " 2. Clean up zombie processes"
    echo " 3. View detailed logs"
    echo " 4. Optimize all tunnel processes"
    echo " 0. Back to main menu"
    
    read -p "Select action [0-4]: " action_choice
    
    case $action_choice in
        1)
            show_system_health_monitor
            ;;
        2)
            cleanup_zombie_processes
            press_any_key
            show_system_health_monitor
            ;;
        3)
            if [[ -d "$LOG_DIR" ]]; then
                clear
                print_info "=== Log Files ==="
                echo
                local log_files
                log_files=$(find "$LOG_DIR" -name "*.log" -type f 2>/dev/null)
                if [[ -n "$log_files" ]]; then
                    local i=1
                    for log_file in $log_files; do
                        echo " $i. $(basename "$log_file")"
                        ((i++))
                    done
                    echo " 0. Back"
                    
                    read -p "Select log file to view [0-$((i-1))]: " log_choice
                    if [[ "$log_choice" =~ ^[1-9][0-9]*$ ]] && [[ $log_choice -lt $i ]]; then
                        local selected_log
                        selected_log=$(echo "$log_files" | sed -n "${log_choice}p")
                        if [[ -f "$selected_log" ]]; then
                            clear
                            print_info "=== $(basename "$selected_log") ==="
                            echo
                            if command -v less >/dev/null 2>&1; then
                                less "$selected_log"
                            else
                                cat "$selected_log"
                            fi
                        fi
                    fi
                else
                    print_warning "No log files found"
                    press_any_key
                fi
            else
                print_warning "Log directory not found"
                press_any_key
            fi
            show_system_health_monitor
            ;;
        4)
            print_info "Optimizing all tunnel processes..."
            optimize_all_tunnel_processes
            press_any_key
            show_system_health_monitor
            ;;
        0)
            return
            ;;
        *)
            print_warning "Invalid option."
            press_any_key
            show_system_health_monitor
            ;;
    esac
}

# --- Main Menu Logic & Entrypoint ---
main_menu() {
    print_menu_header "EasyBackhaul Installer & Management Menu (v13.0-beta)" "Core by Musixal  |  Installer by @N4Xon"
    
    # Show binary status
    if [[ -f "$BIN_PATH" ]]; then
        # Check if binary is executable
        if [[ ! -x "$BIN_PATH" ]]; then
            print_warning "⚠ Binary Status: Found but not executable"
        else
            # Try to get version, but don't fail if it doesn't work
            local version_output=""
            if "$BIN_PATH" -v >/dev/null 2>&1; then
                version_output=$("$BIN_PATH" -v 2>/dev/null | head -n1)
            elif "$BIN_PATH" --version >/dev/null 2>&1; then
                version_output=$("$BIN_PATH" --version 2>/dev/null | head -n1)
            fi
            
            # Check if any backhaul services are running
            local running_services
            running_services=$(systemctl list-units --type=service --state=running | grep -c "backhaul-" 2>/dev/null || echo "0")
            
            if [[ "$running_services" -gt 0 ]]; then
                if [[ -n "$version_output" ]]; then
                    print_success "✓ Binary Status: $version_output (Services: $running_services running)"
                else
                    print_success "✓ Binary Status: Found and working (Services: $running_services running)"
                fi
            else
                if [[ -n "$version_output" ]]; then
                    print_success "✓ Binary Status: $version_output (No services running)"
                else
                    print_success "✓ Binary Status: Found and executable (No services running)"
                fi
            fi
        fi
    else
        print_error "✗ Binary Status: Not installed"
    fi
    echo
    
    echo " 1. Configure a New Tunnel"
    echo " 2. Manage Existing Tunnels"
    echo " 3. Update/Re-install Backhaul Binary"
    echo " 4. Generate Self-Signed TLS Certificate"
    echo " 5. Select Backhaul Binary Directory (current: $BIN_PATH)"
    echo " 6. System Health & Performance Monitor"
    echo " 7. Clean Up Zombie/Orphaned Processes"
    echo " 8. Uninstall EasyBackhaul (Removes binary and ALL configs)"
    echo " ?. Help & Documentation"
    echo " 0. Exit"
    print_info "----------------------------------------------------------------"
    read -p "Please select an option [0-8, ? for help]: " choice

    case $choice in
        1) configure_new_tunnel; press_any_key ;;
        2) manage_tunnels ;;
        3) download_backhaul; press_any_key ;;
        4) generate_self_signed_cert; press_any_key ;;
        5)
           read -e -p "Enter the full path for the Backhaul binary (e.g., /usr/local/bin/backhaul): " new_bin_path
           if [[ -n "$new_bin_path" ]]; then
               BIN_PATH="$new_bin_path"
               print_success "Backhaul binary path set to: $BIN_PATH (for this session)"
           else
               print_warning "No path entered. Keeping current: $BIN_PATH"
           fi
           press_any_key
           ;;
        6)
           show_system_health_monitor
           press_any_key
           ;;
        7)
           clear
           print_server_info_banner
           print_info "--- Clean Up Zombie/Orphaned Processes ---"
           echo
           print_info "This will clean up any zombie processes and orphaned watcher processes."
           echo
           cleanup_zombie_processes
           press_any_key
           ;;
        8)
           read -p "This will REMOVE the binary and ALL configs/services. This is irreversible. Are you sure? (y/n): " confirm
           if [[ "${confirm,,}" == "y" ]]; then
                echo
                print_warning "Summary of what will be deleted:"
                echo "  - Backhaul binary: $BIN_PATH"
                echo "  - All configs: $CONFIG_DIR"
                echo "  - All backups: $BACKUP_DIR"
                echo "  - All systemd services: $SERVICE_DIR/backhaul-*.service"
                echo "  - All watcher scripts, logs, and PID files in /tmp/"
                echo "  - All UFW rules and metadata: $UFW_METADATA_FILE"
                echo "  - All cron jobs managed by EasyBackhaul"
                echo
                read -p "Type DELETE to confirm: " really_delete
                if [[ "$really_delete" != "DELETE" ]]; then
                    print_warning "Uninstall cancelled. Nothing was deleted."
                    press_any_key
                    return
                fi
                
                print_warning "Stopping and disabling all backhaul services..."
                systemctl stop backhaul-*.service &>/dev/null
                systemctl disable backhaul-*.service &>/dev/null
                
                # Clean up all watcher processes and files with robust termination
                print_warning "Cleaning up all watcher processes and files..."
                for pid_file in /tmp/backhaul-watcher-*.pid; do
                    if [[ -f "$pid_file" ]]; then
                        local watcher_pid=$(cat "$pid_file")
                        if [[ -n "$watcher_pid" ]]; then
                            print_info "Stopping watcher process (PID: $watcher_pid)..."
                            
                            # Try graceful termination first
                            kill "$watcher_pid" 2>/dev/null
                            
                            # Wait up to 5 seconds for graceful shutdown
                            local count=0
                            while kill -0 "$watcher_pid" 2>/dev/null && [[ $count -lt 5 ]]; do
                                sleep 1
                                ((count++))
                            done
                            
                            # If still running, force kill
                            if kill -0 "$watcher_pid" 2>/dev/null; then
                                print_warning "Process not responding to SIGTERM, forcing termination..."
                                kill -9 "$watcher_pid" 2>/dev/null
                                sleep 1
                            fi
                            
                            # Verify process is dead
                            if kill -0 "$watcher_pid" 2>/dev/null; then
                                print_error "Failed to terminate watcher process (PID: $watcher_pid)"
                            else
                                print_success "Watcher process terminated successfully"
                            fi
                        fi
                        rm -f "$pid_file"
                    fi
                done
                
                # Kill any remaining watcher processes by pattern
                pkill -f "backhaul-watcher" 2>/dev/null
                
                # Remove all watcher scripts and logs
                rm -f /tmp/backhaul-watcher-*.sh
                rm -f /tmp/backhaul-watcher-*.log
                rm -f /tmp/restart_ack_*
                print_info "Removed all watcher scripts, logs, and temporary files"
                
                print_warning "Removing all related files..."
                rm -f "$BIN_PATH"
                rm -rf "$CONFIG_DIR"
                rm -rf "$BACKUP_DIR"
                rm -f "$SERVICE_DIR"/backhaul-*.service
                rm -f "$UFW_METADATA_FILE"
                (crontab -l 2>/dev/null | grep -v "$CRON_COMMENT_TAG") | crontab -
                systemctl daemon-reload
                
                # Clean up UFW rules
                if command -v ufw >/dev/null 2>&1; then
                    print_info "Cleaning up UFW rules..."
                    # Remove all backhaul-related UFW rules
                    ufw status numbered | grep -E "(backhaul|45680|45690)" | awk '{print $1}' | tac | while read -r rule_num; do
                        if [[ -n "$rule_num" ]]; then
                            echo "y" | ufw delete "$rule_num" >/dev/null 2>&1
                        fi
                    done
                fi
                
                # Cert removal prompt
                local CERT_DIR="/etc/backhaul/certs"
                if [ -d "$CERT_DIR" ] && compgen -G "$CERT_DIR/*.crt" > /dev/null; then
                    read -p "Do you also want to delete all TLS certificates in $CERT_DIR? (y/n): " delcerts
                    if [[ "${delcerts,,}" == "y" ]]; then
                        rm -rf "$CERT_DIR"
                        print_success "All certificates in $CERT_DIR have been deleted."
                    else
                        print_info "Certificates in $CERT_DIR have been preserved."
                    fi
                fi
                
                # Run zombie cleanup
                cleanup_zombie_processes
                
                print_success "EasyBackhaul has been completely uninstalled (including all watchers and related files)."
                exit 0
           fi
           press_any_key
           ;;
        \?) show_help; press_any_key ;;
        0) exit 0 ;;
        *) print_warning "Invalid option."; press_any_key ;;
    esac
}

# --- Script Entrypoint ---
get_server_info
check_root
check_dependencies
mkdir -p "$CONFIG_DIR" "$BACKUP_DIR"

# Initialize enhanced logging system
init_logging

# Check if binary exists, if not run installation wizard
if [ ! -f "$BIN_PATH" ]; then
    print_warning "Backhaul binary not found. Starting installation wizard..."
    echo
    print_info "The Backhaul binary is required to create and manage tunnels."
    print_info "Please complete the installation to continue."
    echo
    press_any_key
    
    # Run installation wizard
    installation_wizard
    
    # Check if installation was successful
    if [ ! -f "$BIN_PATH" ]; then
        print_warning "Binary installation was not completed."
        print_info "You can still use the script to manage existing tunnels or install later."
        echo
        print_info "To install the binary later, use option 3 in the main menu."
        press_any_key
    fi
fi

while true; do
    main_menu
done 
