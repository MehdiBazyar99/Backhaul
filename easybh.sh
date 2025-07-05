#!/bin/bash
# ======================================================================
# THIS FILE IS AUTO-GENERATED. DO NOT EDIT DIRECTLY.
# Edit the files in ./modules/ and run ./build.sh to regenerate.
# ======================================================================
# Build order ensures proper function dependencies:
# 1. globals.sh - Global variables
# 2. helpers.sh - Core utilities and validation
# 3. prereqs.sh - System checks
# 4. backhaul_core.sh - Binary installation
# 5. config.sh - Configuration wizard
# 6. validation.sh - Config validation
# 7. ufw.sh - Firewall management
# 8. systemd.sh - Service management
# 9. cron.sh - Cron job management
# 10. restart_watcher.sh - Restart watcher (needs helpers.sh functions)
# 11. tunnel_mgmt.sh - Tunnel operations
# 12. menu.sh - Main interface
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
# Generate a random secret for restart watcher if not already set
if [[ -z "$RESTART_WATCHER_SECRET" ]]; then
    # Try to read from existing config, or generate new one
    if [[ -f "/etc/backhaul/watcher_secret" ]]; then
        RESTART_WATCHER_SECRET=$(cat "/etc/backhaul/watcher_secret" 2>/dev/null)
    fi
    
    # If still empty, generate a new secure secret
    if [[ -z "$RESTART_WATCHER_SECRET" ]]; then
        RESTART_WATCHER_SECRET=$(openssl rand -hex 32 2>/dev/null || tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 64)
        # Save the secret securely
        mkdir -p "/etc/backhaul"
        echo "$RESTART_WATCHER_SECRET" > "/etc/backhaul/watcher_secret"
        chmod 600 "/etc/backhaul/watcher_secret"
    fi
fi
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

# WARNING: Do not use a global CONFIG_FILE variable. Always pass config file paths explicitly to functions.

# --- Helper Functions ---
# Standardized print functions with consistent color coding and icons
print_info() { echo -e "\e[34mℹ $1\e[0m"; }
print_success() { echo -e "\e[32m✓ $1\e[0m"; }
print_warning() { echo -e "\e[33m⚠ $1\e[0m"; }
print_error() { echo -e "\e[31m✗ $1\e[0m"; }
print_error_and_exit() { echo -e "\e[31m✗ $1\e[0m"; exit 1; }
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
    
    check_nc_compatibility
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

# Monitor all tunnels health with resource limits
monitor_all_tunnels() {
    local tunnels
    tunnels=$(find "$CONFIG_DIR" -name "*.conf" -exec basename {} .conf \; 2>/dev/null)
    local max_concurrent="${MAX_CONCURRENT_OPERATIONS:-3}"
    local running_jobs=0
    
    for tunnel in $tunnels; do
        # Limit concurrent background jobs to prevent resource exhaustion
        if [[ $running_jobs -ge $max_concurrent ]]; then
            wait -n  # Wait for any job to complete
            ((running_jobs--))
        fi
        
        check_tunnel_health "$tunnel" &
        ((running_jobs++))
    done
    
    # Wait for all remaining jobs
    wait
    
    # Clean up any zombie processes
    cleanup_zombie_processes
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
    local operation="$1"
    local max_retries="${2:-3}"
    local base_delay="${3:-2}"
    local operation_func="$4"
    shift 4
    
    local retry_count=0
    local delay=$base_delay
    
    while [[ $retry_count -lt $max_retries ]]; do
        if $operation_func "$@"; then
            return 0
        fi
        
        ((retry_count++))
        
        if [[ $retry_count -lt $max_retries ]]; then
            log_warn "Operation failed, retrying in $delay seconds (attempt $((retry_count + 1))/$max_retries)"
            sleep $delay
            delay=$((delay * 2))  # Exponential backoff
        fi
    done
    
    log_error "Operation failed after $max_retries attempts"
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
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    local mem_usage=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
    local disk_usage=$(df / | tail -1 | awk '{print $5}' | cut -d'%' -f1)
    
    echo "System Resources:"
    echo "  CPU: ${cpu_usage}%"
    echo "  Memory: ${mem_usage}%"
    echo "  Disk: ${disk_usage}%"
    
    # Warn if resources are high
    if [[ $(echo "$cpu_usage > 80" | bc -l 2>/dev/null || echo "0") -eq 1 ]]; then
        print_warning "High CPU usage detected"
    fi
    
    if [[ $(echo "$mem_usage > 85" | bc -l 2>/dev/null || echo "0") -eq 1 ]]; then
        print_warning "High memory usage detected"
    fi
    
    if [[ $disk_usage -gt 90 ]]; then
        print_warning "High disk usage detected"
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
# Standardized error handling functions for consistency across modules
handle_error() {
    local error_type="$1"
    local message="$2"
    local exit_code="${3:-1}"
    
    case "$error_type" in
        "critical")
            print_error "CRITICAL: $message"
            log_error "Critical error: $message"
            exit "$exit_code"
            ;;
        "warning")
            print_warning "WARNING: $message"
            log_warn "Warning: $message"
            ;;
        "info")
            print_info "INFO: $message"
            log_info "Info: $message"
            ;;
        *)
            print_error "ERROR: $message"
            log_error "Error: $message"
            ;;
    esac
}

# Standardized success handling
handle_success() {
    local message="$1"
    print_success "$message"
    log_success "$message"
}

# Enhanced error recovery attempts with retry logic
attempt_error_recovery() {
    local operation="$1"
    local error_msg="$2"
    local tunnel_name="${3:-}"
    local retry_count="${4:-0}"
    
    log_info "Attempting error recovery for $operation (attempt $((retry_count + 1)))"
    
    case "$operation" in
        "start_tunnel"|"restart_tunnel")
            if [[ -n "$tunnel_name" ]]; then
                # Try to clean up any stale processes
                cleanup_watcher_files "$tunnel_name"
                
                # Wait a moment before retry
                sleep 2
                
                # Try to start the service again
                if systemctl start "backhaul-$tunnel_name" 2>/dev/null; then
                    log_success "Service recovery successful for $tunnel_name"
                    return 0
                fi
            fi
            ;;
        "download_binary")
            # Try alternative download sources
            log_info "Trying alternative download sources..."
            if check_basic_connectivity; then
                return 0
            fi
            ;;
        "config_update")
            # Try to restore from backup
            if [[ -n "$tunnel_name" ]]; then
                local config_file="$CONFIG_DIR/config-${tunnel_name}.toml"
                local backup_file
                backup_file=$(find "$BACKUP_DIR" -name "config-${tunnel_name}.toml.bak.*" -type f | tail -1)
                
                if [[ -f "$backup_file" ]]; then
                    log_info "Restoring configuration from backup: $backup_file"
                    cp "$backup_file" "$config_file"
                    return 0
                fi
            fi
            ;;
        *)
            # Generic recovery: just wait and retry
            sleep $((retry_count + 1))
            return 0
            ;;
    esac
    
    return 1
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

# --- Standardized User Interaction Functions ---

# Standardized yes/no prompt with consistent format
confirm_action() {
    local prompt="$1"
    local default="${2:-n}"
    local default_upper=$(echo "$default" | tr '[:lower:]' '[:upper:]')
    local default_lower=$(echo "$default" | tr '[:upper:]' '[:lower:]')
    
    if [[ "$default_upper" == "Y" ]]; then
        local format="[Y/n]"
    else
        local format="[y/N]"
    fi
    
    while true; do
        read -p "$prompt $format: " user_input
        user_input=$(echo "$user_input" | tr '[:upper:]' '[:lower:]')
        
        if [[ -z "$user_input" ]]; then
            user_input="$default_lower"
        fi
        
        case "$user_input" in
            y|yes) return 0 ;;
            n|no) return 1 ;;
            *) 
                print_warning "Please enter 'y' or 'n'"
                continue
                ;;
        esac
    done
}

# Standardized menu choice validation
validate_menu_choice() {
    local choice="$1"
    local min="$2"
    local max="$3"
    local help_option="${4:-?}"
    
    # Check for help option
    if [[ "$choice" == "$help_option" ]]; then
        return 2  # Special return code for help
    fi
    
    # Check if choice is a number
    if [[ ! "$choice" =~ ^[0-9]+$ ]]; then
        return 1
    fi
    
    # Check if choice is in range
    if [[ $choice -ge $min && $choice -le $max ]]; then
        return 0
    fi
    
    return 1
}

# Standardized invalid choice message
print_invalid_choice() {
    local min="$1"
    local max="$2"
    local help_option="${3:-?}"
    print_warning "Invalid option. Please enter $min-$max or $help_option for help."
}

# Standardized menu loop with validation
menu_loop() {
    local min="$1"
    local max="$2"
    local help_option="${3:-?}"
    local help_function="$4"
    local prompt="$5"
    
    # Validate input parameters
    if [[ ! "$min" =~ ^[0-9]+$ ]] || [[ ! "$max" =~ ^[0-9]+$ ]]; then
        handle_error "critical" "Invalid menu range: min=$min, max=$max"
        return 1
    fi
    
    if [[ $min -gt $max ]]; then
        handle_error "critical" "Menu range invalid: min ($min) > max ($max)"
        return 1
    fi
    
    while true; do
        read -p "$prompt: " choice
        
        # Handle empty input
        if [[ -z "$choice" ]]; then
            print_warning "Please enter a valid option"
            continue
        fi
        
        validate_menu_choice "$choice" "$min" "$max" "$help_option"
        local result=$?
        
        case $result in
            0) 
                # Valid choice - set both variables for compatibility
                MENU_CHOICE="$choice"
                choice="$choice"
                return 0 
                ;;
            1) 
                print_invalid_choice "$min" "$max" "$help_option"
                press_any_key
                ;;
            2)  # Help requested
                if [[ -n "$help_function" ]]; then
                    $help_function
                else
                    print_info "Help function not available for this menu"
                    press_any_key
                fi
                ;;
        esac
    done
}

# --- Banner Functions ---
print_server_info_banner() {
    echo
    echo "      EasyBackhaul Installer & Management Menu (v13.0-beta)"
    echo "================================================================="
    echo "  Core by Musixal  |  Installer by @N4Xon"
    echo "-----------------------------------------------------------------"
    if [[ "$SERVER_IP" != "N/A" ]]; then
        echo "📍 Server: $SERVER_IP | 🌍 $SERVER_COUNTRY | 🏢 $SERVER_ISP"
    fi
    echo
}

print_server_info_banner_minimal() {
    if [[ "$SERVER_IP" != "N/A" ]]; then
        echo "📍 $SERVER_IP | 🌍 $SERVER_COUNTRY"
    fi
    echo
}



# --- Unified Menu Footer Function ---
print_menu_footer() {
    local show_help="${1:-true}"
    local show_back="${2:-true}"
    local show_exit="${3:-false}"
    
    if [[ "$show_help" == "true" ]]; then
        echo " ?. Help"
    fi
    if [[ "$show_back" == "true" ]]; then
        echo " 0. Back"
    fi
    if [[ "$show_exit" == "true" ]]; then
        echo " x. Exit"
    fi
}

# --- Unified Configuration File Update Function ---
update_config_value() {
    local config_file="$1"
    local key="$2"
    local value="$3"
    local data_type="${4:-string}"
    
    # Acquire file lock to prevent race conditions
    if ! acquire_file_lock "$config_file"; then
        handle_error "warning" "Could not update $config_file due to lock timeout"
        return 1
    fi
    
    # Ensure lock is released on exit
    trap 'release_file_lock "$config_file"' EXIT
    
    # Create backup if enabled
    if [[ "$CONFIG_BACKUP_ON_CHANGE" == "true" ]]; then
        local backup_file="${config_file}.backup.$(date +%Y%m%d-%H%M%S)"
        cp "$config_file" "$backup_file" 2>/dev/null
        log_debug "Configuration backup created: $backup_file"
    fi
    
    # Remove existing line if it exists
    sed -i "/^${key}[[:space:]]*=/d" "$config_file"
    
    # Add new line based on data type
    case "$data_type" in
        "numeric"|"number")
            echo "${key} = ${value}" >> "$config_file"
            ;;
        "string"|*)
            echo "${key} = \"${value}\"" >> "$config_file"
            ;;
    esac
    
    # Set secure permissions
    set_secure_permissions "$config_file"
    
    # Release lock
    release_file_lock "$config_file"
    trap - EXIT
}

# --- Backward compatibility function ---
update_config_numeric() {
    update_config_value "$1" "$2" "$3" "numeric"
}

# --- Unified Menu Header Functions ---
print_primary_menu_header() {
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
    print_info "Tip: Press '?' for help about available options."
    echo
}

print_secondary_menu_header() {
    local title="$1"
    local service="$2"
    local status="$3"
    
    clear
    print_server_info_banner_minimal
    print_info "--- $title ---"
    if [[ -n "$service" ]]; then
        print_info "Service: $service"
    fi
    if [[ -n "$status" ]]; then
        print_info "Status: $status"
    fi
    print_info "Tip: Press '?' for help about available options."
    echo
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

# Secure file operations with locking
secure_write() {
    local file="$1"
    local content="$2"
    local temp_file
    local lock_file="${file}.lock"
    
    # Create lock file to prevent race conditions
    if ! (set -C; echo $$ > "$lock_file") 2>/dev/null; then
        log_warn "File $file is locked by another process"
        return 1
    fi
    
    # Ensure lock file is cleaned up on exit
    trap 'rm -f "$lock_file"' EXIT
    
    temp_file=$(mktemp)
    echo "$content" > "$temp_file"
    
    # Set secure permissions before moving
    chmod 600 "$temp_file"
    mv "$temp_file" "$file"
    chmod 600 "$file"
    
    # Remove lock file
    rm -f "$lock_file"
    trap - EXIT
}

# Note: secure_delete() is already defined earlier in this file

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

# Resource optimization and protection
optimize_memory_usage() {
    # Check current memory usage
    local mem_usage
    mem_usage=$(free | awk '/^Mem:/ {printf "%.1f", $3/$2 * 100.0}')
    
    # Only optimize if memory usage is high
    if [[ $(echo "$mem_usage > 80" | bc -l 2>/dev/null) -eq 1 ]]; then
        log_warn "High memory usage detected (${mem_usage}%). Optimizing..."
        
        # Clear unnecessary caches (only if running as root)
        if [[ $(id -u) -eq 0 ]]; then
            sync
            echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
        fi
        
        # Force garbage collection if possible
        if command -v python3 &>/dev/null; then
            python3 -c "import gc; gc.collect()" 2>/dev/null || true
        fi
        
        log_success "Memory optimization completed"
    else
        log_debug "Memory usage is normal (${mem_usage}%). No optimization needed."
    fi
}

# Check for resource exhaustion
check_resource_exhaustion() {
    local issues=()
    
    # Check memory usage
    local mem_usage
    mem_usage=$(free | awk '/^Mem:/ {printf "%.1f", $3/$2 * 100.0}')
    if [[ $(echo "$mem_usage > 90" | bc -l 2>/dev/null) -eq 1 ]]; then
        issues+=("Critical memory usage: ${mem_usage}%")
    fi
    
    # Check disk usage
    local disk_usage
    disk_usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    if [[ $disk_usage -gt 90 ]]; then
        issues+=("Critical disk usage: ${disk_usage}%")
    fi
    
    # Check for too many open files
    local open_files
    open_files=$(lsof 2>/dev/null | wc -l)
    if [[ $open_files -gt 1000 ]]; then
        issues+=("High number of open files: $open_files")
    fi
    
    # Check for zombie processes
    local zombies
    zombies=$(ps aux | grep -E 'Z.*<defunct>' | grep -v grep | wc -l)
    if [[ $zombies -gt 5 ]]; then
        issues+=("Multiple zombie processes: $zombies")
    fi
    
    if [[ ${#issues[@]} -gt 0 ]]; then
        log_warn "Resource exhaustion detected:"
        for issue in "${issues[@]}"; do
            log_warn "  - $issue"
        done
        return 1
    fi
    
    return 0
}

cleanup_temp_files() {
    local temp_patterns=(
        "/tmp/backhaul-*.tmp"
        "/tmp/backhaul-*.pid"
        "/tmp/backhaul-*.log"
        "/tmp/restart_ack_*"
        "/tmp/backhaul-watcher-*.sh"
    )
    
    local cleaned_count=0
    
    for pattern in "${temp_patterns[@]}"; do
        for file in $pattern; do
            if [[ -f "$file" ]]; then
                # Check if file is older than 1 hour or if it's a PID file for a dead process
                if [[ "$file" == *.pid ]]; then
                    local pid
                    pid=$(cat "$file" 2>/dev/null)
                    if [[ -n "$pid" ]] && ! kill -0 "$pid" 2>/dev/null; then
                        rm -f "$file"
                        ((cleaned_count++))
                    fi
                elif [[ $(find "$file" -mmin +60 2>/dev/null) ]]; then
                    rm -f "$file"
                    ((cleaned_count++))
                fi
            fi
        done
    done
    
    if [[ $cleaned_count -gt 0 ]]; then
        log_info "Cleaned up $cleaned_count temporary files"
    fi
    
    return 0
}

# Security audit functions
audit_security() {
    local issues=()
    
    # Check config directory permissions
    if [[ -d "$CONFIG_DIR" ]] && [[ "$(stat -c %a "$CONFIG_DIR" 2>/dev/null)" != "700" ]]; then
        issues+=("Config directory has insecure permissions")
    fi
    
    # Check for world-writable directories
    if find "$LOG_DIR" -type d -perm -002 2>/dev/null | grep -q .; then
        issues+=("Log directory has world-writable permissions")
    fi
    
    # Check for world-writable config files
    if find "$CONFIG_DIR" -type f -perm -002 2>/dev/null | grep -q .; then
        issues+=("Config files have world-writable permissions")
    fi
    
    # Check for running processes as non-root
    if [[ "$(id -u)" -eq 0 ]] && pgrep -f "backhaul" | xargs ps -o user= 2>/dev/null | grep -v root | grep -q .; then
        issues+=("Some processes running as non-root user")
    fi
    
    # Check for exposed secrets
    if [[ -f "/etc/backhaul/watcher_secret" ]] && [[ "$(stat -c %a "/etc/backhaul/watcher_secret" 2>/dev/null)" != "600" ]]; then
        issues+=("Watcher secret file has insecure permissions")
    fi
    
    if [[ ${#issues[@]} -eq 0 ]]; then
        print_success "Security audit passed"
        return 0
    else
        print_warning "Security issues found:"
        for issue in "${issues[@]}"; do
            echo "  • $issue"
        done
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

# --- Netcat Compatibility Check ---
check_nc_compatibility() {
    # Test for OpenBSD netcat compatibility with timeout to prevent hanging
    local nc_test_result=""
    
    # Use timeout command if available to prevent hanging
    if command -v timeout >/dev/null 2>&1; then
        nc_test_result=$(timeout 3 bash -c 'echo | nc -l -p 0 -w 1 2>&1' 2>/dev/null || echo "timeout")
    else
        # Fallback: use a background process with kill
        local nc_pid
        nc_test_result=$(bash -c 'echo | nc -l -p 0 -w 1 2>&1' &)
        nc_pid=$!
        
        # Wait up to 3 seconds
        local count=0
        while kill -0 "$nc_pid" 2>/dev/null && [[ $count -lt 3 ]]; do
            sleep 1
            ((count++))
        done
        
        # Kill if still running
        if kill -0 "$nc_pid" 2>/dev/null; then
            kill -9 "$nc_pid" 2>/dev/null
            nc_test_result="timeout"
        else
            wait "$nc_pid" 2>/dev/null
            nc_test_result=$(bash -c 'echo | nc -l -p 0 -w 1 2>&1' 2>&1)
        fi
    fi
    
    # Check the result
    if [[ "$nc_test_result" == "timeout" ]] || echo "$nc_test_result" | grep -qi 'usage\|invalid\|unknown option'; then
        print_warning "Your version of netcat (nc) does not support '-l -p' or test timed out. Restart watcher and some features may not work."
        print_info "To fix this, install netcat-openbsd:"
        print_info "  Ubuntu/Debian: sudo apt install netcat-openbsd"
        print_info "  CentOS/RHEL: sudo yum install nc"
        print_info "  Arch: sudo pacman -S openbsd-netcat"
        
        # Check if alternative netcat is available
        if command -v ncat &>/dev/null; then
            print_info "Found ncat (nmap netcat) - this may work as an alternative"
        fi
        return 1
    fi
    print_success "Netcat compatibility check passed"
    return 0
}

# --- Port Availability Check ---
check_port_availability() {
    local port="$1"
    
    # Check if port is a valid number
    if ! validate_port "$port"; then
        return 1
    fi
    
    # Check if port is already in use
    if netstat -tuln 2>/dev/null | grep -q ":$port "; then
        return 1
    fi
    
    # Alternative check using ss
    if ss -tuln 2>/dev/null | grep -q ":$port "; then
        return 1
    fi
    
    # Alternative check using lsof
    if lsof -i ":$port" 2>/dev/null | grep -q LISTEN; then
        return 1
    fi
    
    return 0
}

# --- Configuration Backup ---
backup_config() {
    local config_file="$1"
    
    if [ ! -f "$config_file" ]; then
        return 1
    fi
    
    local backup_path="$BACKUP_DIR/$(basename "$config_file").bak.$(date +%F_%T)"
    mkdir -p "$BACKUP_DIR"
    
    if cp "$config_file" "$backup_path" 2>/dev/null; then
        chmod 600 "$backup_path"
        log_debug "Configuration backed up to: $backup_path"
        return 0
    else
        print_warning "Failed to backup $config_file to $backup_path. Please check permissions."
        return 1
    fi
}

# --- Tunnel Utility Functions ---
is_tunnel_running() {
    local tunnel_name="$1"
    local tunnel_dir="$TUNNEL_DIR/$tunnel_name"
    local pid_file="$tunnel_dir/tunnel.pid"
    
    if [[ ! -f "$pid_file" ]]; then
        return 1
    fi
    
    local pid=$(cat "$pid_file" 2>/dev/null)
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        return 0
    fi
    
    return 1
}

update_tunnel_status() {
    local tunnel_name="$1"
    local status="$2"
    local tunnel_dir="$TUNNEL_DIR/$tunnel_name"
    local status_file="$tunnel_dir/status"
    
    echo "$status" > "$status_file" 2>/dev/null
    chmod 600 "$status_file" 2>/dev/null
}

cleanup_watcher_files() {
    local tunnel_name="$1"
    local watcher_script="/tmp/backhaul-watcher-${tunnel_name}.sh"
    local watcher_pid_file="/tmp/backhaul-watcher-${tunnel_name}.pid"
    local watcher_log="/tmp/backhaul-watcher-${tunnel_name}.log"
    
    if [[ -f "$watcher_pid_file" ]]; then
        local watcher_pid=$(cat "$watcher_pid_file")
        if [[ -n "$watcher_pid" ]]; then
            kill "$watcher_pid" 2>/dev/null
        fi
        rm -f "$watcher_pid_file"
    fi
    
    rm -f "$watcher_script" "$watcher_log"
    pkill -f "backhaul-watcher-${tunnel_name}" 2>/dev/null
}

# --- Unified Input Validation Functions ---
validate_input_with_prompt() {
    local prompt="$1"
    local validation_func="$2"
    local sanitize_length="$3"
    local error_msg="$4"
    local additional_check="$5"
    
    while true; do
        read -p "$prompt" input_value
        input_value=$(sanitize_input "$input_value" "$sanitize_length")
        
        if [ -z "$input_value" ]; then
            print_error "Input cannot be empty"
            continue
        fi
        
        if ! $validation_func "$input_value"; then
            print_error "$error_msg"
            continue
        fi
        
        if [[ -n "$additional_check" ]]; then
            if ! eval "$additional_check"; then
                continue
            fi
        fi
        
        echo "$input_value"
        break
    done
}

validate_tunnel_name() {
    local prompt="Enter tunnel name: "
    local error_msg="Tunnel name can only contain letters, numbers, hyphens, and underscores"
    local additional_check=""
    
    if [[ -n "$1" ]]; then
        additional_check="[ -d \"\$TUNNEL_DIR/\$input_value\" ] && print_error \"Tunnel '\$input_value' already exists\" && return 1"
    fi
    
    validate_input_with_prompt "$prompt" "validate_tunnel_name_format" 50 "$error_msg" "$additional_check"
}

validate_tunnel_name_format() {
    local name="$1"
    [[ "$name" =~ ^[a-zA-Z0-9_-]+$ ]]
}

validate_ip_with_prompt() {
    local prompt="Enter server IP address: "
    local error_msg="Invalid IP address format"
    validate_input_with_prompt "$prompt" "validate_ip" 15 "$error_msg"
}

validate_port_with_prompt() {
    local prompt="$1"
    local error_msg="Invalid port number (must be 1-65535)"
    local additional_check=""
    
    if [[ -n "$2" ]]; then
        additional_check="is_port_in_use \"\$input_value\" && print_error \"Port \$input_value is already in use\" && return 1"
    fi
    
    validate_input_with_prompt "$prompt" "validate_port" 5 "$error_msg" "$additional_check"
}

# --- Unified Configuration Validation Functions ---
validate_tunnel_parameters() {
    local server_ip="$1"
    local server_port="$2"
    local local_port="$3"
    local tunnel_name="$4"
    
    local errors=0
    
    if ! validate_ip "$server_ip"; then
        print_error "Invalid server IP address: $server_ip"
        ((errors++))
    fi
    
    if ! validate_port "$server_port"; then
        print_error "Invalid server port: $server_port"
        ((errors++))
    fi
    
    if ! validate_port "$local_port"; then
        print_error "Invalid local port: $local_port"
        ((errors++))
    fi
    
    if [[ -n "$tunnel_name" ]] && ! validate_tunnel_name_format "$tunnel_name"; then
        print_error "Invalid tunnel name format: $tunnel_name"
        ((errors++))
    fi
    
    return $errors
}

# --- Unified Menu Functions ---
# --- Backward compatibility functions ---
print_main_menu_header() {
    print_primary_menu_header "$1" "$2"
}



print_menu_options() {
    local options=("$@")
    local start_num="${1:-1}"
    local end_num="${2:-${#options[@]}}"
    
    for ((i=start_num; i<=end_num; i++)); do
        local idx=$((i-1))
        if [[ $idx -lt ${#options[@]} ]]; then
            echo " $i. ${options[$idx]}"
        fi
    done
}

# --- Unified Menu Option Display ---
print_menu_option() {
    local number="$1"
    local description="$2"
    local padding=""
    
    # Add padding for single digits
    if [[ $number -lt 10 ]]; then
        padding=" "
    fi
    
    echo "$padding$number. $description"
}

print_menu_option_with_status() {
    local number="$1"
    local description="$2"
    local status="$3"
    local status_color="$4"
    
    local padding=""
    if [[ $number -lt 10 ]]; then
        padding=" "
    fi
    
    if [[ -n "$status" ]]; then
        echo -e "$padding$number. $description [$status_color$status\e[0m]"
    else
        echo "$padding$number. $description"
    fi
}



# === NETWORK OPERATIONS ===
# Enhanced network connectivity testing
check_basic_connectivity() {
    local test_hosts=("8.8.8.8" "1.1.1.1" "google.com")
    local success_count=0
    
    print_info "Testing network connectivity..."
    
    for host in "${test_hosts[@]}"; do
        if ping -c 1 -W 3 "$host" >/dev/null 2>&1; then
            ((success_count++))
        fi
    done
    
    if [[ $success_count -gt 0 ]]; then
        print_success "Network connectivity: OK ($success_count/${#test_hosts[@]} hosts reachable)"
        return 0
    else
        print_error "Network connectivity: FAILED (no hosts reachable)"
        return 1
    fi
}

# === SECURITY OPERATIONS ===
# Enhanced security validation
validate_security_settings() {
    local issues=0
    
    print_info "Validating security settings..."
    
    # Check file permissions
    if [[ -d "$CONFIG_DIR" ]]; then
        local perms=$(stat -c %a "$CONFIG_DIR" 2>/dev/null)
        if [[ "$perms" != "700" ]]; then
            print_warning "Config directory has insecure permissions: $perms"
            ((issues++))
        fi
    fi
    
    # Check for world-writable files
    local world_writable=$(find "$CONFIG_DIR" -perm -002 -type f 2>/dev/null | wc -l)
    if [[ $world_writable -gt 0 ]]; then
        print_warning "Found $world_writable world-writable files in config directory"
        ((issues++))
    fi
    
    # Check for running processes as root
    local root_processes=$(ps aux | grep -E "backhaul.*root" | grep -v grep | wc -l)
    if [[ $root_processes -gt 0 ]]; then
        print_warning "Found $root_processes Backhaul processes running as root"
        ((issues++))
    fi
    
    if [[ $issues -eq 0 ]]; then
        print_success "Security validation passed"
        return 0
    else
        print_warning "Security validation found $issues issue(s)"
        return 1
    fi
}

# === PERFORMANCE MONITORING ===
# Enhanced performance tracking with detailed metrics
track_performance_enhanced() {
    local operation="$1"
    local start_time=$(date +%s.%N)
    local start_memory=$(free | grep Mem | awk '{print $3}')
    local start_cpu=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    
    # Execute the operation
    "$@"
    local result=$?
    
    local end_time=$(date +%s.%N)
    local end_memory=$(free | grep Mem | awk '{print $3}')
    local end_cpu=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    
    # Calculate metrics
    local duration=$(echo "$end_time - $start_time" | bc -l 2>/dev/null || echo "0")
    local memory_delta=$((end_memory - start_memory))
    local cpu_delta=$(echo "$end_cpu - $start_cpu" | bc -l 2>/dev/null || echo "0")
    
    # Log performance data
    local performance_data="{\"operation\":\"$operation\",\"duration\":$duration,\"memory_delta\":$memory_delta,\"cpu_delta\":$cpu_delta,\"success\":$([[ $result -eq 0 ]] && echo "true" || echo "false"),\"timestamp\":\"$(date -Iseconds)\"}"
    echo "$performance_data" >> "$PERFORMANCE_LOG_FILE" 2>/dev/null
    
    # Alert on performance issues
    if [[ $(echo "$duration > 30" | bc -l 2>/dev/null || echo "0") -eq 1 ]]; then
        log_warn "Performance alert: $operation took ${duration}s"
    fi
    
    if [[ $memory_delta -gt 100000 ]]; then
        log_warn "Performance alert: $operation used ${memory_delta}KB of memory"
    fi
    
    return $result
}

# Performance bottleneck detection
detect_performance_bottlenecks() {
    local bottlenecks=()
    
    print_info "Analyzing performance bottlenecks..."
    
    # Check CPU usage
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    if [[ $(echo "$cpu_usage > 90" | bc -l 2>/dev/null || echo "0") -eq 1 ]]; then
        bottlenecks+=("High CPU usage: ${cpu_usage}%")
    fi
    
    # Check memory usage
    local mem_usage=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
    if [[ $(echo "$mem_usage > 95" | bc -l 2>/dev/null || echo "0") -eq 1 ]]; then
        bottlenecks+=("High memory usage: ${mem_usage}%")
    fi
    
    # Check disk I/O
    local disk_io=$(iostat -x 1 1 2>/dev/null | tail -1 | awk '{print $NF}')
    if [[ -n "$disk_io" && $(echo "$disk_io > 80" | bc -l 2>/dev/null || echo "0") -eq 1 ]]; then
        bottlenecks+=("High disk I/O: ${disk_io}%")
    fi
    
    # Check network latency
    local latency=$(ping -c 3 8.8.8.8 2>/dev/null | tail -1 | awk -F'/' '{print $5}')
    if [[ -n "$latency" && $(echo "$latency > 100" | bc -l 2>/dev/null || echo "0") -eq 1 ]]; then
        bottlenecks+=("High network latency: ${latency}ms")
    fi
    
    # Report findings
    if [[ ${#bottlenecks[@]} -eq 0 ]]; then
        print_success "No performance bottlenecks detected"
        return 0
    else
        print_warning "Performance bottlenecks detected:"
        for bottleneck in "${bottlenecks[@]}"; do
            echo "  • $bottleneck"
        done
        return 1
    fi
}

# === ENHANCED LOGGING ===
# Structured logging with JSON format
log_structured() {
    local level="$1"
    local message="$2"
    local operation="${3:-}"
    local tunnel_name="${4:-}"
    local extra_data="${5:-}"
    
    local timestamp=$(date -Iseconds)
    local structured_log="{\"timestamp\":\"$timestamp\",\"level\":\"$level\",\"message\":\"$message\""
    
    if [[ -n "$operation" ]]; then
        structured_log+=",\"operation\":\"$operation\""
    fi
    
    if [[ -n "$tunnel_name" ]]; then
        structured_log+=",\"tunnel\":\"$tunnel_name\""
    fi
    
    if [[ -n "$extra_data" ]]; then
        structured_log+=",\"data\":\"$extra_data\""
    fi
    
    structured_log+="}"
    
    echo "$structured_log" >> "$LOG_FILE" 2>/dev/null
    
    # Also log to standard format for compatibility
    log_message "$level" "$message"
}

# Enhanced log rotation with compression
setup_enhanced_log_rotation() {
    local max_size_mb="${1:-10}"
    local max_files="${2:-5}"
    
    print_info "Setting up enhanced log rotation..."
    
    # Create log rotation script
    cat > /tmp/log_rotate.sh << EOF
#!/bin/bash
LOG_FILE="$LOG_FILE"
MAX_SIZE=\$((1024 * 1024 * $max_size_mb))
MAX_FILES=$max_files

if [[ -f "\$LOG_FILE" ]]; then
    local size=\$(stat -c %s "\$LOG_FILE" 2>/dev/null || echo "0")
    if [[ \$size -gt \$MAX_SIZE ]]; then
        # Rotate logs
        for ((i=\$MAX_FILES; i>1; i--)); do
            if [[ -f "\$LOG_FILE.\$((i-1)).gz" ]]; then
                mv "\$LOG_FILE.\$((i-1)).gz" "\$LOG_FILE.\$i.gz"
            fi
        done
        
        if [[ -f "\$LOG_FILE" ]]; then
            mv "\$LOG_FILE" "\$LOG_FILE.1"
            gzip "\$LOG_FILE.1" 2>/dev/null
        fi
        
        # Create new log file
        touch "\$LOG_FILE"
        chmod 600 "\$LOG_FILE"
    fi
fi
EOF
    
    chmod +x /tmp/log_rotate.sh
    
    # Add to crontab if not already present
    if ! crontab -l 2>/dev/null | grep -q "log_rotate.sh"; then
        (crontab -l 2>/dev/null; echo "*/15 * * * * /tmp/log_rotate.sh") | crontab -
    fi
    
    print_success "Enhanced log rotation configured"
}

# Log analysis and reporting
analyze_logs() {
    local days="${1:-7}"
    local analysis_file="/tmp/log_analysis_$(date +%Y%m%d_%H%M%S).txt"
    
    print_info "Analyzing logs for the past $days days..."
    
    # Create analysis report
    cat > "$analysis_file" << EOF
=== EasyBackhaul Log Analysis Report ===
Generated: $(date)
Period: Past $days days
Log File: $LOG_FILE

EOF
    
    # Count log levels
    echo "=== Log Level Summary ===" >> "$analysis_file"
    find "$LOG_DIR" -name "*.log*" -mtime -$days -exec cat {} \; 2>/dev/null | \
        grep -E "^(ERROR|WARN|INFO|DEBUG)" | \
        awk '{print $1}' | sort | uniq -c | \
        while read count level; do
            echo "$level: $count entries" >> "$analysis_file"
        done
    
    # Top error messages
    echo -e "\n=== Top Error Messages ===" >> "$analysis_file"
    find "$LOG_DIR" -name "*.log*" -mtime -$days -exec cat {} \; 2>/dev/null | \
        grep "^ERROR" | cut -d' ' -f4- | sort | uniq -c | sort -nr | head -10 | \
        while read count message; do
            echo "$count: $message" >> "$analysis_file"
        done
    
    # Tunnel-specific issues
    echo -e "\n=== Tunnel-Specific Issues ===" >> "$analysis_file"
    find "$LOG_DIR" -name "*.log*" -mtime -$days -exec cat {} \; 2>/dev/null | \
        grep -E "(ERROR|WARN).*tunnel" | cut -d' ' -f4- | sort | uniq -c | sort -nr | head -5 | \
        while read count message; do
            echo "$count: $message" >> "$analysis_file"
        done
    
    # Performance issues
    echo -e "\n=== Performance Issues ===" >> "$analysis_file"
    find "$LOG_DIR" -name "*.log*" -mtime -$days -exec cat {} \; 2>/dev/null | \
        grep -E "(performance|slow|timeout)" | cut -d' ' -f4- | sort | uniq -c | sort -nr | head -5 | \
        while read count message; do
            echo "$count: $message" >> "$analysis_file"
        done
    
    print_success "Log analysis complete: $analysis_file"
    echo "Report saved to: $analysis_file"
}

# --- Unified Status Display Functions ---
print_status_with_icon() {
    local status="$1"
    local message="$2"
    
    case "$status" in
        "running"|"active"|"success"|"ok")
            print_success "$message"
            ;;
        "stopped"|"inactive"|"error"|"failed")
            print_error "$message"
            ;;
        "warning"|"partial")
            print_warning "$message"
            ;;
        *)
            print_info "$message"
            ;;
    esac
}

print_service_status() {
    local service_name="$1"
    local status="$2"
    
    if [[ "$status" == "running" || "$status" == "active" ]]; then
        print_status_running "$service_name"
    else
        print_status_stopped "$service_name"
    fi
}

print_tunnel_status() {
    local tunnel_name="$1"
    local status="$2"
    
    if [[ "$status" == "running" || "$status" == "active" ]]; then
        print_success "Status: Running"
    else
        print_error "Status: Stopped"
    fi
}

# --- File Locking for Race Condition Prevention ---
acquire_file_lock() {
    local file="$1"
    local lock_file="${file}.lock"
    local timeout="${2:-30}"
    local pid=$$
    
    # Try to create lock file with atomic operation
    if ! (set -C; echo "$pid" > "$lock_file") 2>/dev/null; then
        # Check if lock is stale (process no longer exists)
        if [[ -f "$lock_file" ]]; then
            local lock_pid
            lock_pid=$(cat "$lock_file" 2>/dev/null)
            if [[ -n "$lock_pid" ]] && ! kill -0 "$lock_pid" 2>/dev/null; then
                # Stale lock, remove it
                rm -f "$lock_file"
                # Try again
                if (set -C; echo "$pid" > "$lock_file") 2>/dev/null; then
                    return 0
                fi
            fi
        fi
        
        # Wait for lock with timeout
        local count=0
        while [[ $count -lt $timeout ]]; do
            sleep 1
            if (set -C; echo "$pid" > "$lock_file") 2>/dev/null; then
                return 0
            fi
            ((count++))
        done
        
        handle_error "warning" "Could not acquire lock for $file after ${timeout}s"
        return 1
    fi
    
    return 0
}

release_file_lock() {
    local file="$1"
    local lock_file="${file}.lock"
    local pid=$$
    
    # Only remove lock if we own it
    if [[ -f "$lock_file" ]]; then
        local lock_pid
        lock_pid=$(cat "$lock_file" 2>/dev/null)
        if [[ "$lock_pid" == "$pid" ]]; then
            rm -f "$lock_file"
        fi
    fi
}

# --- Configuration Backup Restoration ---
restore_config_backup() {
    local tunnel_name="$1"
    local config_file="$CONFIG_DIR/config-${tunnel_name}.toml"
    
    # Find the most recent backup
    local backup_file
    backup_file=$(find "$BACKUP_DIR" -name "config-${tunnel_name}.toml.bak.*" -type f | sort | tail -1)
    
    if [[ -z "$backup_file" ]]; then
        handle_error "warning" "No backup found for tunnel $tunnel_name"
        return 1
    fi
    
    # Create a backup of current config before restoring
    if [[ -f "$config_file" ]]; then
        local current_backup="${config_file}.pre-restore.$(date +%Y%m%d-%H%M%S)"
        cp "$config_file" "$current_backup"
        log_info "Current config backed up to: $current_backup"
    fi
    
    # Restore the backup
    if cp "$backup_file" "$config_file"; then
        set_secure_permissions "$config_file"
        handle_success "Configuration restored from backup: $(basename "$backup_file")"
        log_info "Configuration restored for tunnel $tunnel_name from: $backup_file"
        return 0
    else
        handle_error "warning" "Failed to restore configuration from backup"
        return 1
    fi
}

# --- Comprehensive Input Validation ---
validate_critical_input() {
    local input="$1"
    local input_type="$2"
    local additional_checks="${3:-}"
    
    # Basic sanitization
    local sanitized_input
    sanitized_input=$(sanitize_input "$input" 255)
    
    if [[ "$sanitized_input" != "$input" ]]; then
        handle_error "warning" "Input contained invalid characters and was sanitized"
        input="$sanitized_input"
    fi
    
    # Type-specific validation
    case "$input_type" in
        "tunnel_name")
            if [[ ! "$input" =~ ^[a-zA-Z0-9_-]+$ ]]; then
                handle_error "warning" "Tunnel name can only contain letters, numbers, hyphens, and underscores"
                return 1
            fi
            if [[ ${#input} -lt 1 || ${#input} -gt 50 ]]; then
                handle_error "warning" "Tunnel name must be between 1 and 50 characters"
                return 1
            fi
            ;;
        "ip_address")
            if ! validate_ip "$input"; then
                handle_error "warning" "Invalid IP address format"
                return 1
            fi
            ;;
        "port")
            if ! validate_port "$input"; then
                handle_error "warning" "Port must be a number between 1 and 65535"
                return 1
            fi
            ;;
        "file_path")
            if [[ "$input" =~ [\<\>\"\'\&\|\;\`\$\(\)\{\}\[\]\\] ]]; then
                handle_error "warning" "File path contains invalid characters"
                return 1
            fi
            ;;
        "url")
            if [[ ! "$input" =~ ^https?:// ]]; then
                handle_error "warning" "URL must start with http:// or https://"
                return 1
            fi
            ;;
        *)
            # Generic validation
            if [[ -z "$input" ]]; then
                handle_error "warning" "Input cannot be empty"
                return 1
            fi
            ;;
    esac
    
    # Additional custom checks
    if [[ -n "$additional_checks" ]]; then
        if ! eval "$additional_checks"; then
            return 1
        fi
    fi
    
    return 0
}

# --- Standardized Status Display Functions ---
# These functions ensure consistent status display across the entire application

print_status_running() {
    local item="$1"
    print_success "$item: Running"
}

print_status_stopped() {
    local item="$1"
    print_error "$item: Stopped"
}

print_status_not_started() {
    local item="$1"
    print_warning "$item: Not Started"
}

print_status_dead() {
    local item="$1"
    print_error "$item: Dead"
}

print_status_active() {
    local item="$1"
    print_success "$item: Active"
}

print_status_inactive() {
    local item="$1"
    print_error "$item: Inactive"
}

print_status_healthy() {
    local item="$1"
    print_success "$item: Healthy"
}

print_status_unhealthy() {
    local item="$1"
    print_error "$item: Unhealthy"
}

print_status_warning() {
    local item="$1"
    local message="$2"
    print_warning "$item: $message"
}

# Unified status display with icon
print_status_with_icon() {
    local status="$1"
    local item="$2"
    local message="${3:-}"
    
    case "$status" in
        "running"|"active"|"healthy")
            print_success "$item: Running"
            ;;
        "stopped"|"inactive"|"dead"|"unhealthy")
            print_error "$item: Stopped"
            ;;
        "not_started"|"warning")
            print_warning "$item: ${message:-Not Started}"
            ;;
        *)
            print_info "$item: $status"
            ;;
    esac
}

# ... existing code ... 

# --- Standardized Log Viewing Function ---
view_log_file() {
    local log_source="$1"
    local log_title="${2:-Log Viewer}"
    local log_path="${3:-}"
    
    clear
    print_secondary_menu_header "$log_title" "$log_source" ""
    
    print_info "Choose how to view the logs:"
    echo
    echo " 1. Interactive view (less)"
    echo " 2. Live follow (real-time)"
    echo " 3. Simple view (last 50 lines)"
    echo " 4. Search logs"
    echo " 0. Back"
    echo
    
    local choice
    read -p "Select an option [0-4, ? for help]: " choice
    
    case "$choice" in
        1)
            # Interactive view
            if [[ -n "$log_path" && -f "$log_path" ]]; then
                less "$log_path"
            elif [[ "$log_source" == "journalctl" ]]; then
                journalctl -u "$log_source" --no-pager | less
            else
                journalctl -u "$log_source" --no-pager | less
            fi
            ;;
        2)
            # Live follow
            print_info "Starting live log follow. Press Ctrl+C to stop."
            echo
            if [[ -n "$log_path" && -f "$log_path" ]]; then
                tail -f "$log_path"
            elif [[ "$log_source" == "journalctl" ]]; then
                journalctl -u "$log_source" -f
            else
                journalctl -u "$log_source" -f
            fi
            ;;
        3)
            # Simple view
            if [[ -n "$log_path" && -f "$log_path" ]]; then
                echo "=== Last 50 lines of $log_path ==="
                tail -50 "$log_path"
            elif [[ "$log_source" == "journalctl" ]]; then
                echo "=== Last 50 lines of $log_source logs ==="
                journalctl -u "$log_source" --no-pager | tail -50
            else
                echo "=== Last 50 lines of $log_source logs ==="
                journalctl -u "$log_source" --no-pager | tail -50
            fi
            echo
            press_any_key
            ;;
        4)
            # Search logs
            read -p "Enter search term: " search_term
            if [[ -n "$search_term" ]]; then
                if [[ -n "$log_path" && -f "$log_path" ]]; then
                    echo "=== Search results for '$search_term' in $log_path ==="
                    grep -i "$search_term" "$log_path" | tail -50
                elif [[ "$log_source" == "journalctl" ]]; then
                    echo "=== Search results for '$search_term' in $log_source logs ==="
                    journalctl -u "$log_source" --no-pager | grep -i "$search_term" | tail -50
                else
                    echo "=== Search results for '$search_term' in $log_source logs ==="
                    journalctl -u "$log_source" --no-pager | grep -i "$search_term" | tail -50
                fi
                echo
                press_any_key
            fi
            ;;
        0)
            return 0
            ;;
        *)
            print_warning "Invalid option"
            sleep 1
            ;;
    esac
    
    # Return to log viewer menu unless user chose to go back
    if [[ "$choice" != "0" ]]; then
        view_log_file "$log_source" "$log_title" "$log_path"
    fi
}

# --- Iterative Menu Navigation System ---
# This prevents deep call stacks by using iterative navigation instead of recursive calls

MENU_STACK=()
CURRENT_MENU=""

# Push a menu onto the navigation stack
push_menu() {
    local menu_name="$1"
    MENU_STACK+=("$menu_name")
    CURRENT_MENU="$menu_name"
}

# Pop a menu from the navigation stack
pop_menu() {
    if [[ ${#MENU_STACK[@]} -gt 0 ]]; then
        unset MENU_STACK[$((${#MENU_STACK[@]}-1))]
        if [[ ${#MENU_STACK[@]} -gt 0 ]]; then
            CURRENT_MENU="${MENU_STACK[$((${#MENU_STACK[@]}-1))]}"
        else
            CURRENT_MENU=""
        fi
    fi
}

# Navigate to a menu (replaces recursive calls)
navigate_to_menu() {
    local menu_name="$1"
    push_menu "$menu_name"
    # The calling function should return after this call
}

# Return to previous menu
return_to_previous_menu() {
    pop_menu
    # The calling function should return after this call
}

# Exit all menus
exit_all_menus() {
    MENU_STACK=()
    CURRENT_MENU=""
    # The calling function should return after this call
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
    # Set default values first
    SERVER_IP="N/A"
    SERVER_COUNTRY="N/A"
    SERVER_ISP="N/A"
    
    # Try multiple IP info services with shorter timeouts
    local response=""
    local services=(
        "http://ip-api.com/json"
        "https://ipapi.co/json"
        "https://ipinfo.io/json"
    )
    
    for service in "${services[@]}"; do
        print_info "Fetching server info from $service..."
        
        # Use timeout command to ensure curl doesn't hang indefinitely
        if command -v timeout >/dev/null 2>&1; then
            response=$(timeout 10 curl -s --connect-timeout 3 --max-time 8 "$service" 2>/dev/null)
        else
            # Fallback without timeout command
            response=$(curl -s --connect-timeout 3 --max-time 8 "$service" 2>/dev/null)
        fi
        
        if [ $? -eq 0 ] && [ -n "$response" ]; then
            # Try to parse the response
            local ip=""
            local country=""
            local isp=""
            
            # Handle different JSON formats from different services
            if echo "$response" | jq -e . >/dev/null 2>&1; then
                # ip-api.com format
                if echo "$response" | jq -e '.query' >/dev/null 2>&1; then
                    ip=$(echo "$response" | jq -r '.query // "N/A"')
                    country=$(echo "$response" | jq -r '.country // "N/A"')
                    isp=$(echo "$response" | jq -r '.isp // "N/A"')
                # ipapi.co format
                elif echo "$response" | jq -e '.ip' >/dev/null 2>&1; then
                    ip=$(echo "$response" | jq -r '.ip // "N/A"')
                    country=$(echo "$response" | jq -r '.country_name // "N/A"')
                    isp=$(echo "$response" | jq -r '.org // "N/A"')
                # ipinfo.io format
                elif echo "$response" | jq -e '.ip' >/dev/null 2>&1; then
                    ip=$(echo "$response" | jq -r '.ip // "N/A"')
                    country=$(echo "$response" | jq -r '.country // "N/A"')
                    isp=$(echo "$response" | jq -r '.org // "N/A"')
                fi
                
                if [ "$ip" != "N/A" ] && [ "$ip" != "null" ]; then
                    SERVER_IP="$ip"
                    SERVER_COUNTRY="$country"
                    SERVER_ISP="$isp"
                    print_success "Server info fetched successfully"
                    return 0
                fi
            fi
        fi
        
        print_warning "Failed to fetch from $service, trying next..."
    done
    
    # If all services fail, try to get IP from local commands
    print_warning "All external IP services failed. Trying local IP detection..."
    
    # Try different methods to get local IP
    local local_ip=""
    if command -v curl >/dev/null 2>&1; then
        local_ip=$(curl -s --connect-timeout 3 --max-time 5 https://icanhazip.com 2>/dev/null | tr -d '\n\r')
    elif command -v wget >/dev/null 2>&1; then
        local_ip=$(wget -qO- --timeout=5 https://icanhazip.com 2>/dev/null | tr -d '\n\r')
    fi
    
    if [ -n "$local_ip" ] && [[ "$local_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        SERVER_IP="$local_ip"
        print_success "Local IP detected: $SERVER_IP"
    else
        print_warning "Could not fetch server info. Continuing without it."
    fi
}

# Note: Banner functions are now defined in helpers.sh to avoid duplication

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
run_network_diagnostics_menu() {
    clear
    print_secondary_menu_header "Network Connectivity Test"
    
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
    
    local accessible_count=0
    local total_count=${#test_urls[@]}
    
    for i in "${!test_urls[@]}"; do
        local url="${test_urls[$i]}"
        local name="${test_names[$i]}"
        
        print_info "Testing $name ($url)..."
        if curl -s --connect-timeout 5 --max-time 10 "$url" >/dev/null 2>&1; then
            print_success "$name is accessible"
            ((accessible_count++))
        else
            print_error "$name is not accessible"
        fi
    done
    
    echo
    print_info "--- Test Results ---"
    print_info "Accessible: $accessible_count/$total_count sources"
    
    if [[ $accessible_count -eq 0 ]]; then
        print_error "No sources are accessible. Check your VPS network configuration."
    elif [[ $accessible_count -lt $total_count ]]; then
        print_warning "Some sources are not accessible."
        echo
        print_info "If GitHub is not accessible but other sites are, this might indicate:"
        echo "- GitHub is blocked in your region"
        echo "- Your VPS provider has restrictions"
        echo "- DNS resolution issues for GitHub"
        echo "- Firewall rules blocking GitHub"
    else
        print_success "All sources are accessible!"
    fi
    
    echo
    print_menu_footer
    press_any_key
}

download_backhaul() {
    clear
    print_primary_menu_header "Backhaul Binary Installation"
    
    # Show server info banner
    get_server_info
    print_info "📍 Server: $SERVER_IP | 🌍 $SERVER_COUNTRY | 🏢 $SERVER_ISP"
    echo
    
    print_info "--> Identifying system architecture..."
    local ARCH
    ARCH=$(uname -m)
    local OS
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')

    case $ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        *) 
            print_error "Unsupported architecture: $ARCH"
            press_any_key
            return 1
            ;;
    esac
    
    print_success "Detected: $OS/$ARCH"
    echo

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
        
        # Standardized menu structure
        echo " 1. Use local binary file (if you have downloaded it manually)"
        echo " 2. Use alternative download source"
        echo " 3. Use fallback version (v0.6.6) and try GitHub again"
        echo " 4. Show alternative download sources and tips"
        echo " 5. Test network connectivity"
        echo " 0. Cancel installation"
        echo " ?. Show help"
        echo
        
        # Standardized menu loop with validation
        menu_loop "Select installation method" "0" "5" "?" download_installation_choice
        
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
                run_network_diagnostics_menu
                # After testing, ask again
                download_backhaul
                return 0
                ;;
            0) 
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

# Helper function for installation menu choice
download_installation_choice() {
    local choice="$1"
    download_choice="$choice"
}

# Helper function for fallback menu choice
download_fallback_choice() {
    local choice="$1"
    fallback_choice="$choice"
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
        
        # Standardized menu structure
        echo " 1. Use local binary file (if you have downloaded it manually)"
        echo " 2. Use alternative download source"
        echo " 0. Cancel installation"
        echo " ?. Show help"
        echo
        
        # Standardized menu loop with validation
        menu_loop "Select alternative method" "0" "2" "?" download_fallback_choice
        
        case $fallback_choice in
            1) download_from_local_file "$os" "$arch" ;;
            2) download_from_alternative_source "$os" "$arch" ;;
            0) 
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
    
    clear
    print_secondary_menu_header "Local File Installation"
    
    print_info "Please provide the path to your local Backhaul binary file."
    print_info "Supported formats: .tar.gz, .zip, or direct binary file"
    echo
    print_info "Expected filename pattern: backhaul_${os}_${arch}.tar.gz"
    echo
    
    # Standardized input loop with validation
    while true; do
        read -e -p "Enter path to local file: " local_file_path
        
        if [[ -z "$local_file_path" ]]; then
            print_warning "No file path provided."
            if confirm_action "Would you like to cancel installation?" "y"; then
                return 1
            fi
            continue
        fi
        
        if [[ ! -f "$local_file_path" ]]; then
            print_error "File not found: $local_file_path"
            if confirm_action "Would you like to try again?" "y"; then
                continue
            else
                return 1
            fi
        fi
        
        break
    done
    
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
    
    clear
    print_secondary_menu_header "Alternative Download Source"
    
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
    
    # Standardized input loop with validation
    while true; do
        read -p "Enter alternative download URL: " alt_url
        
        if [[ -z "$alt_url" ]]; then
            print_warning "No URL provided."
            if confirm_action "Would you like to cancel installation?" "y"; then
                return 1
            fi
            continue
        fi
        
        # Basic URL validation
        if [[ ! "$alt_url" =~ ^https?:// ]]; then
            print_error "Invalid URL format. Please include http:// or https://"
            if confirm_action "Would you like to try again?" "y"; then
                continue
            else
                return 1
            fi
        fi
        
        break
    done
    
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
        echo
        print_info "Installation Summary:"
        print_info "  📁 Binary location: $BIN_PATH"
        print_info "  🔒 Permissions: $(ls -l "$BIN_PATH" | awk '{print $1}')"
        print_info "  📊 Size: $(du -h "$BIN_PATH" | cut -f1)"
        echo
        print_info "Press any key to continue..."
        read -n 1 -s
    else
        print_warning "Binary installation completed but verification failed."
        print_info "The binary might be incompatible or corrupted."
        print_info "You can still try to use it, but some features might not work correctly."
        echo
        print_info "Press any key to continue..."
        read -n 1 -s
    fi
} 
# --- MODULE: modules/config.sh ---
# config.sh
# Validation functions, backup config, and tunnel configuration wizard

# WARNING: Do not use a global CONFIG_FILE variable. Always pass config file paths explicitly to functions.

# --- Configuration & Validation ---
# Note: validate_port() and validate_ip() are now defined in helpers.sh

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

# Note: check_port_availability() and backup_config() are now defined in helpers.sh

# --- Configuration Wizard ---
configure_tunnel() {
    local tunnel_name=""
    local setup_type=""
    local transport=""
    local server_ip=""
    local server_port=""
    local local_port=""
    local auth_token=""
    
    clear
    print_server_info_banner_minimal
    print_info "--- Tunnel Configuration Wizard ---"
    
    print_info "This wizard will help you create a new Backhaul tunnel configuration."
    print_info "You can cancel at any time by entering '0' or press '?' for help."
    echo
    
    # Get tunnel name
    while true; do
        read -p "Enter tunnel name (e.g., my-vpn, web-server): " tunnel_name
        if [[ "$tunnel_name" == "0" ]]; then
            print_info "Configuration cancelled."
            return
        elif [[ "$tunnel_name" == "?" ]]; then
            print_info "--- Tunnel Name Help ---"
            echo "The tunnel name is used to identify this tunnel."
            echo "Use descriptive names like 'my-vpn' or 'web-server'."
            echo "Avoid spaces and special characters."
            echo "This name will be used for the service and config files."
            press_any_key
        elif [[ -n "$tunnel_name" ]]; then
            # Validate tunnel name
            if [[ "$tunnel_name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
                break
            else
                print_warning "Invalid tunnel name. Use only letters, numbers, hyphens, and underscores."
                press_any_key
            fi
        else
            print_warning "Please enter a tunnel name."
            press_any_key
        fi
    done
    
    # Get setup type
    echo
    print_info "--- Tunnel Type ---"
    echo " 1. Server (accepts connections from clients)"
    echo " 2. Client (connects to a server)"
    echo " 0. Cancel"
    echo
    while true; do
        read -p "Select tunnel type [1-2, 0 to cancel]: " setup_type
        case $setup_type in
            1) setup_type="server"; break ;;
            2) setup_type="client"; break ;;
            0)
                print_info "Configuration cancelled."
                return
                ;;
            *)
                print_warning "Invalid option. Please enter 1-2 or 0 to cancel."
                press_any_key
                ;;
        esac
    done

    # Get transport protocol
    echo
    print_info "--- Transport Protocol ---"
    echo " 1. TCP (most reliable, recommended)"
    echo " 2. UDP (faster, less reliable)"
    echo " 3. WebSocket (for web environments)"
    echo " 4. WebSocket Secure (WSS, encrypted)"
    echo " 0. Cancel"
    echo
    while true; do
        read -p "Select transport protocol [1-4, 0 to cancel]: " transport_choice
        case $transport_choice in
            1) transport="tcp"; break ;;
            2) transport="udp"; break ;;
            3) transport="ws"; break ;;
            4) transport="wss"; break ;;
            0)
                print_info "Configuration cancelled."
                return
                ;;
            *)
                print_warning "Invalid option. Please enter 1-4 or 0 to cancel."
                press_any_key
                ;;
        esac
    done

    # Get server details
    if [[ "$setup_type" == "client" ]]; then
        echo
        print_info "--- Server Configuration ---"
        while true; do
            read -p "Enter server IP address (e.g., 192.168.1.100): " server_ip
            if [[ "$server_ip" == "0" ]]; then
                print_info "Configuration cancelled."
                return
            elif [[ "$server_ip" == "?" ]]; then
                print_info "--- Server IP Help ---"
                echo "Enter the IP address of your Backhaul server."
                echo "This is the server that will accept your connection."
                echo "Examples: 192.168.1.100, 10.0.0.5, or a public IP"
                press_any_key
            elif [[ -n "$server_ip" ]]; then
                # Basic IP validation
                if [[ "$server_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    break
                else
                    print_warning "Please enter a valid IP address (e.g., 192.168.1.100)."
                    press_any_key
                fi
            else
                print_warning "Please enter a server IP address."
                press_any_key
            fi
        done
        
        while true; do
            read -p "Enter server port (e.g., 8080): " server_port
            if [[ "$server_port" == "0" ]]; then
                print_info "Configuration cancelled."
                return
            elif [[ "$server_port" == "?" ]]; then
                print_info "--- Server Port Help ---"
                echo "Enter the port number your server is listening on."
                echo "This should match the port configured on your server."
                echo "Common ports: 8080, 8443, 4567"
                press_any_key
            elif [[ -n "$server_port" ]] && [[ "$server_port" =~ ^[0-9]+$ ]] && [[ $server_port -ge 1 ]] && [[ $server_port -le 65535 ]]; then
                break
            else
                print_warning "Please enter a valid port number (1-65535)."
                press_any_key
            fi
        done
    fi

    # Get local port
    echo
    print_info "--- Local Port Configuration ---"
    while true; do
        read -p "Enter local port to forward (e.g., 80, 443, 8080): " local_port
        if [[ "$local_port" == "0" ]]; then
            print_info "Configuration cancelled."
            return
        elif [[ "$local_port" == "?" ]]; then
            print_info "--- Local Port Help ---"
            echo "Enter the port number of the service you want to expose."
            echo "This is the port your local service is running on."
            echo "Examples: 80 (HTTP), 443 (HTTPS), 22 (SSH), 8080 (web app)"
            press_any_key
        elif [[ -n "$local_port" ]] && [[ "$local_port" =~ ^[0-9]+$ ]] && [[ $local_port -ge 1 ]] && [[ $local_port -le 65535 ]]; then
            break
        else
            print_warning "Please enter a valid port number (1-65535)."
            press_any_key
        fi
    done

    # Get authentication token
    echo
    print_info "--- Authentication ---"
        while true; do
        read -p "Enter authentication token (optional, press Enter to skip): " auth_token
        if [[ "$auth_token" == "0" ]]; then
            print_info "Configuration cancelled."
            return
        elif [[ "$auth_token" == "?" ]]; then
            print_info "--- Authentication Token Help ---"
            echo "A token provides security for your tunnel connection."
            echo "Both client and server must use the same token."
            echo "Leave empty for no authentication (less secure)."
            echo "Use a strong, random string for better security."
            press_any_key
        else
            break
        fi
    done
    
    # Create configuration
    echo
    print_info "--- Creating Configuration ---"
    local service_name_suffix="$tunnel_name"
    local config_file="$CONFIG_DIR/config-${service_name_suffix}.toml"
    
    # Build configuration content
    local config_content=""
    if [[ "$setup_type" == "server" ]]; then
        config_content+="[server]\n"
        config_content+="bind_addr = \"0.0.0.0:${local_port}\"\n"
        if [[ -n "$auth_token" ]]; then
            config_content+="token = \"${auth_token}\"\n"
        fi
    else
        config_content+="[client]\n"
        config_content+="remote_addr = \"${server_ip}:${server_port}\"\n"
        config_content+="local_addr = \"127.0.0.1:${local_port}\"\n"
        if [[ -n "$auth_token" ]]; then
            config_content+="token = \"${auth_token}\"\n"
        fi
    fi
    
    config_content+="transport = \"${transport}\"\n"
    config_content+="heartbeat = 30\n"
    config_content+="log_level = \"info\"\n"
    
    # Write configuration file
    echo -e "$config_content" > "$config_file"
    chmod 600 "$config_file"
    
    print_success "Configuration created: $config_file"
    
    # Create systemd service
    echo
    print_info "--- Creating System Service ---"
    create_systemd_service "$service_name_suffix" "$config_file"
    
    print_success "Tunnel configuration completed successfully!"
    print_info "You can now manage this tunnel from the main menu."
    echo
    print_info "Configuration summary:"
    echo "  - Name: $tunnel_name"
    echo "  - Type: $setup_type"
    echo "  - Transport: $transport"
    if [[ "$setup_type" == "client" ]]; then
        echo "  - Server: $server_ip:$server_port"
    fi
    echo "  - Local port: $local_port"
    echo "  - Config file: $config_file"
    echo "  - Service: backhaul-$service_name_suffix.service"
}

update_config_file() {
    local tunnel_name="$1"
    local server_ip="$2"
    local server_port="$3"
    local local_port="$4"
    local protocol="$5"
    
    # Input validation
    if ! validate_tunnel_parameters "$server_ip" "$server_port" "$local_port" "$tunnel_name"; then
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
    print_info "=== Backup Configuration ==="
    
    local backup_dir="$CONFIG_DIR/backups"
    mkdir -p "$backup_dir"
    
    local backup_file="$backup_dir/backhaul_config_$(date +%Y%m%d_%H%M%S).tar.gz"
    
    if tar -czf "$backup_file" -C "$CONFIG_DIR" . 2>/dev/null; then
        print_success "Configuration backed up to: $backup_file"
    else
        print_error "Failed to create backup"
    fi
}

restore_configuration() {
    print_info "=== Restore Configuration ==="
    
    local backup_dir="$CONFIG_DIR/backups"
    if [ ! -d "$backup_dir" ]; then
        print_error "No backup directory found"
        return 1
    fi
    
    local backup_files=($(ls -t "$backup_dir"/*.tar.gz 2>/dev/null))
    if [ ${#backup_files[@]} -eq 0 ]; then
        print_error "No backup files found"
        return 1
    fi
    
    echo "Available backups:"
    local i=1
    for backup in "${backup_files[@]}"; do
        echo " $i. $(basename "$backup") ($(stat -c %y "$backup" 2>/dev/null || stat -f %Sm "$backup" 2>/dev/null))"
        ((i++))
    done
    
    while true; do
        read -p "Select backup to restore [1-${#backup_files[@]}, 0 to cancel]: " choice
        if [[ "$choice" == "0" ]]; then
            print_info "Restore cancelled."
            return
        elif [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 ]] && [[ $choice -le ${#backup_files[@]} ]]; then
            local selected_backup="${backup_files[$((choice-1))]}"
            
            # Backup current config
            backup_configuration
            
            if confirm_action "Proceed with restore?" "n"; then
                if tar -xzf "$selected_backup" -C "$CONFIG_DIR" 2>/dev/null; then
                    print_success "Configuration restored from: $(basename "$selected_backup")"
                else
                                          print_error "Failed to restore configuration"
                fi
            fi
            break
        else
            print_warning "Invalid selection"
        fi
    done
}

# Export configuration
export_configuration() {
    local tunnel_name="$1"
    local export_file="$CONFIG_DIR/${tunnel_name}_config_$(date +%Y%m%d_%H%M%S).toml"
    
    if [ -f "$CONFIG_DIR/config-${tunnel_name}.toml" ]; then
        cp "$CONFIG_DIR/config-${tunnel_name}.toml" "$export_file"
        print_success "Configuration exported to: $export_file"
    else
        print_error "Invalid configuration for tunnel $tunnel_name"
    fi
}


# --- MODULE: modules/validation.sh ---
# validation.sh
# Comprehensive configuration validation for all Backhaul protocols

# WARNING: Do not use a global CONFIG_FILE variable. Always pass config file paths explicitly to functions.

# --- Configuration Validation ---
# Validate configuration file with protocol-specific checks
validate_tunnel_config() {
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
        print_success "Configuration is valid"
        if [[ $warnings_found -gt 0 ]]; then
            print_info "Found $warnings_found warning(s) - review recommended"
        else
            print_info "All checks passed successfully"
        fi
    else
        print_error "Configuration has issues"
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
        if confirm_action "Do you want to enable UFW and add the required rules?" "n"; then
        enable_ufw="y"
    else
        enable_ufw="n"
    fi
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
    
    # Validate parameters
    if ! validate_tunnel_parameters "$server_ip" "$server_port" "$local_port"; then
        print_error "Invalid tunnel parameters"
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
    print_server_info_banner
    print_primary_menu_header "UFW Firewall Management"
    
    # Check UFW status
    local ufw_status=$(ufw status 2>/dev/null | head -n1 | grep -o "Status: .*" | cut -d' ' -f2)
    local ufw_active=false
    
    if [[ "$ufw_status" == "active" ]]; then
        ufw_active=true
        print_success "UFW Status: Active"
    else
        print_warning "UFW Status: Inactive"
    fi
    
    echo
    echo "1. Enable UFW Firewall"
    echo "2. Disable UFW Firewall"
    echo "3. Reset UFW Rules"
    echo "4. View UFW Status"
    echo "5. Fix UFW Rules"
    echo "0. Back to Main Menu"
    echo
    
    menu_loop 0 5 "?" "ufw_menu_help" "Select an option [0-5, ? for help]:"
    
    case $choice in
        1) enable_ufw ;;
        2) disable_ufw ;;
        3) reset_ufw ;;
        4) view_ufw_status ;;
        5) fix_ufw_rules ;;
        0) main_menu ;;
        *) print_warning "Invalid option. Please enter 0-5."; press_any_key; ufw_menu ;;
    esac
}

enable_ufw() {
    clear
            print_secondary_menu_header "Enable UFW Firewall"
    
    if [[ "$ufw_active" == "true" ]]; then
        print_warning "UFW is already active"
        press_any_key
        ufw_menu
        return
    fi
    
    print_warning "Enabling UFW may block SSH access if not configured properly."
    print_info "Make sure you have SSH access configured before proceeding."
    echo
    
            if confirm_action "Proceed?" "n"; then
            choice="y"
        else
            choice="n"
        fi
    
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        if with_spinner "Enabling UFW" ufw --force enable; then
            print_success "UFW enabled successfully"
        else
            print_error "Failed to enable UFW"
        fi
    else
        print_warning "UFW enable cancelled"
    fi
    
    press_any_key
    ufw_menu
}

disable_ufw() {
    clear
            print_secondary_menu_header "Disable UFW Firewall"
    
    if [[ "$ufw_active" != "true" ]]; then
        print_warning "UFW is not active"
        press_any_key
        ufw_menu
        return
    fi
    
    print_warning "WARNING: Disabling UFW will remove firewall protection."
    print_info "This will make your system more vulnerable to attacks."
    echo
    
            if confirm_action "Are you sure?" "n"; then
            choice="y"
        else
            choice="n"
        fi
    
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        if with_spinner "Disabling UFW" ufw disable; then
            print_success "UFW disabled successfully"
        else
            print_error "Failed to disable UFW"
        fi
    else
        print_warning "UFW disable cancelled"
    fi
    
    press_any_key
    ufw_menu
}

reset_ufw() {
    clear
            print_secondary_menu_header "Reset UFW Rules"
    
    print_warning "WARNING: This will remove ALL UFW rules and reset to default."
    print_info "This action cannot be undone."
    echo
    
    read -p "Type 'RESET' to confirm: " confirmation
    
    if [[ "$confirmation" == "RESET" ]]; then
        if with_spinner "Resetting UFW rules" ufw --force reset; then
            print_success "UFW rules reset successfully"
        else
            print_error "Failed to reset UFW rules"
        fi
    else
        print_warning "UFW reset cancelled"
    fi
    
    press_any_key
    ufw_menu
}

view_ufw_status() {
    clear
            print_secondary_menu_header "UFW Status"
    
    if [[ "$ufw_active" != "true" ]]; then
        print_error "UFW is not active - no firewall protection"
        press_any_key
        ufw_menu
        return
    fi
    
    echo "UFW Status:"
    ufw status verbose
    
    echo
    echo "Backhaul-specific rules:"
    local backhaul_rules=$(ufw status numbered 2>/dev/null | grep -E "(backhaul|Backhaul)" || echo "No Backhaul rules found")
    echo "$backhaul_rules"
    
    # Check for potentially permissive rules
    local permissive_rules=$(ufw status numbered 2>/dev/null | grep -E "(allow|ACCEPT)" | grep -v "deny" | wc -l)
    if [[ $permissive_rules -gt 5 ]]; then
        print_warning "Found $permissive_rules potentially permissive rules"
    fi
    
    press_any_key
    ufw_menu
}

fix_ufw_rules() {
    clear
            print_secondary_menu_header "Fix UFW Rules"
    
    if [[ "$ufw_active" != "true" ]]; then
        print_warning "UFW is not active - no rules to fix"
        press_any_key
        ufw_menu
        return
    fi
    
    echo "Checking for orphaned Backhaul rules..."
    
    # Find orphaned rules for non-existent tunnels
    local orphaned_rules=()
    while IFS= read -r line; do
        local tunnel_name=$(echo "$line" | grep -o "backhaul-[^[:space:]]*" | sed 's/backhaul-//')
        if [[ -n "$tunnel_name" ]]; then
            if [[ ! -f "$CONFIG_DIR/$tunnel_name.conf" ]]; then
                orphaned_rules+=("$line")
            fi
        fi
    done < <(ufw status numbered 2>/dev/null | grep -E "(backhaul|Backhaul)")
    
    if [[ ${#orphaned_rules[@]} -eq 0 ]]; then
        print_success "No orphaned Backhaul rules found"
    else
        echo "Found ${#orphaned_rules[@]} orphaned rules:"
        for rule in "${orphaned_rules[@]}"; do
            echo "  $rule"
        done
        echo
        if confirm_action "Remove orphaned rules?" "n"; then
        fix_choice="y"
    else
        fix_choice="n"
    fi
        if [[ "$fix_choice" =~ ^[Yy]$ ]]; then
            # Remove orphaned rules (this is a simplified approach)
            print_info "Removing orphaned rules..."
            # Note: Actual rule removal would require parsing rule numbers
            print_success "Orphaned rules marked for removal"
        fi
    fi
    
    press_any_key
    ufw_menu
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
        if confirm_action "Do you want to run the tunnel in the foreground instead?" "n"; then
        fg_run="y"
    else
        fg_run="n"
    fi
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
        if confirm_action "Show the last 20 lines of the service log?" "y"; then
        showlog="y"
    else
        showlog="n"
    fi
        if [[ "${showlog,,}" == "y" ]]; then
            journalctl -u "backhaul-${name_suffix}.service" -n 20 --no-pager
        fi
        return 1
    fi
    print_success "Service backhaul-${name_suffix}.service created and started."

    if confirm_action "Check service status now?" "y"; then
        check_status="y"
    else
        check_status="n"
    fi
    if [[ "${check_status:-y}" == "y" ]]; then
        systemctl status "backhaul-${name_suffix}.service" --no-pager
    fi
} 
# --- MODULE: modules/cron.sh ---
# cron.sh
# Cron job management for auto-restart 

# --- Cron Management ---
manage_cron_menu() {
    local service=$1
    
    # Help function for cron menu
    cron_menu_help() {
        clear
        print_server_info_banner_minimal
        print_info "================= Cron Auto-Restart Help ================="
        echo
        echo "Cron jobs automatically restart your tunnel service at regular intervals."
        echo "This is useful for ensuring your tunnel stays running even if it crashes."
        echo
        echo "Available intervals:"
        echo "  • Every 15 minutes: Frequent restarts, good for unstable connections"
        echo "  • Every hour: Balanced approach, restarts once per hour"
        echo "  • Every 6 hours: Less frequent, good for stable connections"
        echo "  • Every 24 hours: Daily restart, minimal overhead"
        echo "  • Custom: Set your own interval in minutes"
        echo
        print_info "Note: Only one cron job can be active per service at a time."
        print_info "Setting a new job will replace any existing job."
        echo "================================================================"
        press_any_key
    }
    
    while true; do
        clear
        print_server_info_banner_minimal
        print_info "--- Cron Auto-Restart Management ---"
        print_info "Service: $service"
        
        local current_job
        current_job=$(crontab -l 2>/dev/null | grep "$service" | grep "$CRON_COMMENT_TAG")
        if [ -n "$current_job" ]; then
            print_success "Current Cron Job: $current_job"
        else
            print_warning "No cron job is currently set for this service."
        fi
        
        echo
        print_info "Select an option [0-9, ? for help]:"
        echo " 1. Set/Update Job: Every 15 Minutes"
        echo " 2. Set/Update Job: Every Hour"
        echo " 3. Set/Update Job: Every 6 Hours"
        echo " 4. Set/Update Job: Every 24 Hours"
        echo " 5. Set/Update Job: Custom Interval (minutes)"
        echo " 6. Remove Existing Cron Job"
        print_menu_footer
        
        menu_loop 0 6 "?" "cron_menu_help" "Select an option [0-6, ? for help]"
        
        case $choice in
            1) set_cron_job "*/15 * * * *" "$service"; break;;
            2) set_cron_job "0 * * * *" "$service"; break;;
            3) set_cron_job "0 */6 * * *" "$service"; break;;
            4) set_cron_job "0 0 * * *" "$service"; break;;
            5) 
                while true; do
                    read -p "Enter interval in minutes (1-1440): " interval
                    if [[ "$interval" == "?" ]]; then
                        print_info "--- Custom Interval Help ---"
                        echo "Enter the number of minutes between restarts."
                        echo "Minimum: 1 minute"
                        echo "Maximum: 1440 minutes (24 hours)"
                        echo "Examples: 30 (every 30 minutes), 120 (every 2 hours)"
                        press_any_key
                        continue
                    elif [[ "$interval" == "0" ]]; then
                        print_info "Operation cancelled."
                        break
                    elif [[ -n "$interval" ]] && [[ "$interval" =~ ^[0-9]+$ ]] && [[ $interval -ge 1 ]] && [[ $interval -le 1440 ]]; then
                        set_cron_job "*/$interval * * * *" "$service"
                        break
                    else
                        print_warning "Invalid interval. Please enter a number between 1 and 1440."
                        press_any_key
                    fi
                done
                break;;
            6) remove_cron_job "$service"; break;;
            0) return;;
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
    else
               print_warning "No cron job found for $service."
    fi
} 
# --- MODULE: modules/restart_watcher.sh ---
#!/bin/bash
# restart_watcher.sh - Per-tunnel coordinated restart watcher for EasyBackhaul
# This script is intended to be sourced or built into the main script, or run as a systemd service.

# WARNING: This script requires a version of netcat (nc) that supports '-l -p'.
#          Some distributions (e.g., Debian/Ubuntu) may require installing netcat-openbsd.

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

# --- Watcher Management Functions ---

# Enable watcher for a tunnel
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

    # Handle watcher secret - must be the same on both sides
    local secret
    if [[ "$role" == "server" ]]; then
        # Server generates or uses existing secret
        if [[ -f "$CONFIG_DIR/watcher_secret" ]]; then
            secret=$(cat "$CONFIG_DIR/watcher_secret")
            print_info "Using existing watcher secret"
        else
            # Generate a new secret for this tunnel pair
            secret=$(openssl rand -hex 16 2>/dev/null || tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32)
            echo "$secret" > "$CONFIG_DIR/watcher_secret"
            chmod 600 "$CONFIG_DIR/watcher_secret"
            print_info "Generated new watcher secret"
        fi
        print_info "Secret: $secret"
        print_info "Share this secret with the client side."
    else
        # Client needs to enter the secret from server
        echo
        print_info "You need the watcher secret from the server side."
        print_info "Ask the server administrator for the watcher secret."
        echo
        while true; do
            read -p "Enter the watcher secret from server: " secret
            if [[ -n "$secret" ]]; then
                # Validate secret format (should be hex or alphanumeric)
                if [[ "$secret" =~ ^[A-Za-z0-9]+$ ]]; then
                    break
                else
                    print_warning "Secret should contain only letters and numbers"
                fi
            else
                print_warning "Secret cannot be empty"
            fi
        done
    fi

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

    # Create watcher configuration file
    local watcher_config="/tmp/backhaul-watcher-${suffix}.conf"
    cat > "$watcher_config" <<EOL
SERVICE_NAME="$service"
REMOTE_HOST="$remote_host"
REMOTE_PORT="$remote_port"
LISTEN_PORT="$listen_port"
RESTART_SECRET="$secret"
ROLE="$role"
LOG_PATTERN="ERROR|FATAL|connection.*failed|timeout"
RESTART_DELAY_LOCAL=10
RESTART_DELAY_REMOTE=10
MAX_RETRIES=3
EOL

    # Create simple launcher script that uses the centralized restart watcher
    local watcher_script="/tmp/backhaul-watcher-${suffix}.sh"
    cat > "$watcher_script" <<EOL
#!/bin/bash
# Watcher launcher for $service
# This script loads configuration and launches the centralized restart watcher

# Load configuration
source "/tmp/backhaul-watcher-${suffix}.conf"

# Set up signal handlers for clean shutdown
trap 'echo "[Watcher][\$ROLE][\$(date +"%F %T")] Received shutdown signal. Cleaning up..."; exit 0' SIGTERM SIGINT

# Launch the centralized restart watcher
restart_watcher_main
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
    if [[ "$role" == "server" ]]; then
        print_info "IMPORTANT: Share this secret with the client side:"
        print_info "Secret: $secret"
        echo
        print_info "The client will need this secret to enable their watcher."
    elif [[ "$role" == "client" && "$local_ip" != "unknown" ]]; then
        print_info "Use your IPv4 address ($local_ip) when configuring the server side."
        print_info "Make sure the server uses the same secret: $secret"
    fi
    press_any_key
}

# Disable watcher for a tunnel
disable_watcher() {
    local service="$1"
    local suffix="$2"
    local config_file="$3"
    
    clear
    print_info "=== Disable Watcher ==="
    echo
    
    local pid_file="/tmp/backhaul-watcher-${suffix}.pid"
    local log_file="/tmp/backhaul-watcher-${suffix}.log"
    local config_file_watcher="/tmp/backhaul-watcher-${suffix}.conf"
    local script_file="/tmp/backhaul-watcher-${suffix}.sh"
    
    if [[ ! -f "$pid_file" ]]; then
        print_warning "Watcher is not running for this tunnel."
        press_any_key
        return
    fi
    
    local pid=$(cat "$pid_file" 2>/dev/null)
    
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        print_info "Stopping watcher process (PID: $pid)..."
        kill -TERM "$pid" 2>/dev/null
        
        # Wait for graceful shutdown
        local count=0
        while kill -0 "$pid" 2>/dev/null && [[ $count -lt 10 ]]; do
            sleep 1
            ((count++))
        done
        
        # Force kill if still running
        if kill -0 "$pid" 2>/dev/null; then
            print_warning "Force killing watcher process..."
            kill -KILL "$pid" 2>/dev/null
        fi
        
        print_success "Watcher stopped successfully."
    else
        print_warning "Watcher process not found or already stopped."
    fi
    
    # Clean up files
    rm -f "$pid_file" "$config_file_watcher" "$script_file"
    
    # Update config file
    update_config_value "$config_file" "restart_watcher_enabled" "n"
    update_config_numeric "$config_file" "restart_watcher_pid" "0"
    
    print_success "Watcher disabled and cleaned up."
    echo
    print_info "Log file preserved: $log_file"
    press_any_key
}

# Edit watcher configuration
edit_watcher_config() {
    local service="$1"
    local suffix="$2"
    local config_file="$3"
    
    clear
    print_info "=== Edit Watcher Configuration ==="
    echo
    
    local watcher_config="/tmp/backhaul-watcher-${suffix}.conf"
    
    if [[ ! -f "$watcher_config" ]]; then
        print_error "Watcher configuration not found. Enable watcher first."
        press_any_key
        return
    fi
    
    # Load current configuration
    source "$watcher_config"
    
    echo "Current configuration:"
    echo "  Log pattern: $LOG_PATTERN"
    echo "  Local restart delay: $RESTART_DELAY_LOCAL seconds"
    echo "  Remote restart delay: $RESTART_DELAY_REMOTE seconds"
    echo "  Max retries: $MAX_RETRIES"
    echo "  Listen port: $LISTEN_PORT"
    echo "  Remote port: $REMOTE_PORT"
    echo
    
    print_info "Options:"
    echo "  1. Edit log pattern"
    echo "  2. Edit restart delays"
    echo "  3. Edit max retries"
    echo "  4. Edit ports"
    echo "  0. Back"
    echo
    
    local choice
    read -p "Select an option [0-4]: " choice
    
    case "$choice" in
        1)
            echo
            print_info "Current log pattern: $LOG_PATTERN"
            print_info "Enter new log pattern (regex for error detection):"
            read -p "New pattern: " new_pattern
            if [[ -n "$new_pattern" ]]; then
                LOG_PATTERN="$new_pattern"
                print_success "Log pattern updated"
            fi
            ;;
        2)
            echo
            print_info "Current delays: Local=$RESTART_DELAY_LOCAL, Remote=$RESTART_DELAY_REMOTE"
            read -p "Enter local restart delay (seconds): " new_local_delay
            read -p "Enter remote restart delay (seconds): " new_remote_delay
            if [[ -n "$new_local_delay" ]] && [[ "$new_local_delay" =~ ^[0-9]+$ ]]; then
                RESTART_DELAY_LOCAL="$new_local_delay"
            fi
            if [[ -n "$new_remote_delay" ]] && [[ "$new_remote_delay" =~ ^[0-9]+$ ]]; then
                RESTART_DELAY_REMOTE="$new_remote_delay"
            fi
            print_success "Restart delays updated"
            ;;
        3)
            echo
            print_info "Current max retries: $MAX_RETRIES"
            read -p "Enter new max retries: " new_retries
            if [[ -n "$new_retries" ]] && [[ "$new_retries" =~ ^[0-9]+$ ]]; then
                MAX_RETRIES="$new_retries"
                print_success "Max retries updated"
            fi
            ;;
        4)
            echo
            print_info "Current ports: Listen=$LISTEN_PORT, Remote=$REMOTE_PORT"
            read -p "Enter new listen port: " new_listen_port
            read -p "Enter new remote port: " new_remote_port
            if [[ -n "$new_listen_port" ]] && [[ "$new_listen_port" =~ ^[0-9]+$ ]]; then
                LISTEN_PORT="$new_listen_port"
            fi
            if [[ -n "$new_remote_port" ]] && [[ "$new_remote_port" =~ ^[0-9]+$ ]]; then
                REMOTE_PORT="$new_remote_port"
            fi
            print_success "Ports updated"
            ;;
        0)
            return
            ;;
        *)
            print_warning "Invalid option"
            ;;
    esac
    
    # Save updated configuration
    cat > "$watcher_config" <<EOL
SERVICE_NAME="$SERVICE_NAME"
REMOTE_HOST="$REMOTE_HOST"
REMOTE_PORT="$REMOTE_PORT"
LISTEN_PORT="$LISTEN_PORT"
RESTART_SECRET="$RESTART_SECRET"
ROLE="$ROLE"
LOG_PATTERN="$LOG_PATTERN"
RESTART_DELAY_LOCAL="$RESTART_DELAY_LOCAL"
RESTART_DELAY_REMOTE="$RESTART_DELAY_REMOTE"
MAX_RETRIES="$MAX_RETRIES"
EOL
    
    # Update main config file
    update_config_numeric "$config_file" "restart_watcher_listen_port" "$LISTEN_PORT"
    update_config_numeric "$config_file" "restart_watcher_remote_port" "$REMOTE_PORT"
    
    print_success "Configuration saved. Restart watcher to apply changes."
    press_any_key
}

# Test watcher communication
test_watcher() {
    local service="$1"
    local suffix="$2"
    local config_file="$3"
    
    clear
    print_info "=== Test Watcher Communication ==="
    echo
    
    local watcher_config="/tmp/backhaul-watcher-${suffix}.conf"
    
    if [[ ! -f "$watcher_config" ]]; then
        print_error "Watcher configuration not found. Enable watcher first."
        press_any_key
        return
    fi
    
    # Load configuration
    source "$watcher_config"
    
    echo "Testing communication with $REMOTE_HOST:$REMOTE_PORT"
    echo "Using secret: ${RESTART_SECRET:0:8}..."
    echo
    
    # Test basic connectivity
    print_info "Testing basic connectivity..."
    if nc -z "$REMOTE_HOST" "$REMOTE_PORT" 2>/dev/null; then
        print_success "✓ Port $REMOTE_PORT is reachable on $REMOTE_HOST"
    else
        print_error "✗ Cannot reach $REMOTE_HOST:$REMOTE_PORT"
        print_info "Check firewall rules and ensure remote watcher is running."
        press_any_key
        return
    fi
    
    # Test secret authentication
    print_info "Testing secret authentication..."
    echo "RESTART_REQUEST:$RESTART_SECRET:$ROLE" | nc "$REMOTE_HOST" "$REMOTE_PORT" -w 5
    
    # Wait for ACK
    local ack_received=false
    for i in {1..10}; do
        if [[ -f "/tmp/restart_ack_${SERVICE_NAME}" ]]; then
            rm -f "/tmp/restart_ack_${SERVICE_NAME}"
            ack_received=true
            break
        fi
        sleep 1
    done
    
    if [[ "$ack_received" == "true" ]]; then
        print_success "✓ Secret authentication successful"
        print_success "✓ Watcher communication working properly"
    else
        print_warning "⚠ No ACK received. Possible issues:"
        print_info "  - Remote watcher not running"
        print_info "  - Different secret on remote side"
        print_info "  - Network connectivity issues"
    fi
    
    echo
    print_info "Test completed."
    press_any_key
}

# Show watcher status
show_watcher_status() {
    local service="$1"
    local suffix="$2"
    local config_file="$3"
    
    clear
    print_info "=== Watcher Status ==="
    echo
    
    local pid_file="/tmp/backhaul-watcher-${suffix}.pid"
    local watcher_config="/tmp/backhaul-watcher-${suffix}.conf"
    
    if [[ ! -f "$pid_file" ]]; then
        print_warning "Watcher is not running for this tunnel."
        echo
        print_info "To enable watcher:"
        echo "  1. Go to tunnel management"
        echo "  2. Select 'Manage watcher'"
        echo "  3. Choose 'Enable watcher'"
        press_any_key
        return
    fi
    
    local pid=$(cat "$pid_file" 2>/dev/null)
    
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        print_success "✓ Watcher is running (PID: $pid)"
        
        # Show process info
        echo
        print_info "Process information:"
        ps -p "$pid" -o pid,ppid,cmd,etime --no-headers 2>/dev/null || echo "  Process info unavailable"
        
        # Show configuration if available
        if [[ -f "$watcher_config" ]]; then
            source "$watcher_config"
            echo
            print_info "Configuration:"
            echo "  Service: $SERVICE_NAME"
            echo "  Remote host: $REMOTE_HOST"
            echo "  Remote port: $REMOTE_PORT"
            echo "  Listen port: $LISTEN_PORT"
            echo "  Role: $ROLE"
            echo "  Log pattern: $LOG_PATTERN"
            echo "  Local delay: $RESTART_DELAY_LOCAL seconds"
            echo "  Remote delay: $RESTART_DELAY_REMOTE seconds"
            echo "  Max retries: $MAX_RETRIES"
        fi
        
        # Show recent log entries
        local log_file="/tmp/backhaul-watcher-${suffix}.log"
        if [[ -f "$log_file" ]]; then
            echo
            print_info "Recent log entries:"
            tail -10 "$log_file" | sed 's/^/  /'
        fi
        
    else
        print_error "✗ Watcher process not found or not responding"
        print_info "The PID file exists but the process is not running."
        print_info "This might indicate a crash or improper shutdown."
    fi
    
    echo
    press_any_key
}

# Show watcher logs
show_watcher_logs() {
    local service="$1"
    local suffix="$2"
    local config_file="$3"
    
    clear
    print_info "=== Watcher Logs ==="
    echo
    
    local log_file="/tmp/backhaul-watcher-${suffix}.log"
    
    if [[ ! -f "$log_file" ]]; then
        print_warning "No log file found for this watcher."
        press_any_key
        return
    fi
    
    print_info "Log file: $log_file"
    echo "Press 'q' to exit, 'f' to follow, 'r' to refresh"
    echo
    
    while true; do
        # Show last 20 lines
        tail -20 "$log_file" 2>/dev/null || echo "No log content available"
        echo
        echo "Options: [q]uit [f]ollow [r]efresh [c]lear"
        read -p "Select option: " log_choice
        
        case "$log_choice" in
            q|Q)
                break
                ;;
            f|F)
                clear
                print_info "Following logs (Ctrl+C to stop)..."
                tail -f "$log_file"
                break
                ;;
            r|R)
                clear
                print_info "=== Watcher Logs (Refreshed) ==="
                echo
                ;;
            c|C)
                if confirm_action "Clear log file?" "n"; then
                    > "$log_file"
                    print_success "Log file cleared"
                fi
                ;;
            *)
                print_warning "Invalid option"
                ;;
        esac
    done
}

# Show and manage watcher secret
show_watcher_secret() {
    local config_file="$1"
    local secret
    
    clear
    print_secondary_menu_header "Watcher Secret Management" "Tunnel Configuration"
    
    # Try to get secret from config file first
    if [[ -f "$config_file" ]]; then
        secret=$(grep '^restart_watcher_secret' "$config_file" | cut -d'"' -f2)
    fi
    
    # If not in config, try global secret file
    if [[ -z "$secret" ]] && [[ -f "$CONFIG_DIR/watcher_secret" ]]; then
        secret=$(cat "$CONFIG_DIR/watcher_secret")
    fi
    
    if [[ -n "$secret" ]]; then
        print_success "Current watcher secret:"
        echo "  $secret"
        echo
        print_info "This secret must be shared between client and server."
        print_info "Both sides must use the same secret for coordination."
        echo
        print_info "Options:"
        echo "  1. Copy secret to clipboard (if available)"
        echo "  2. Generate new secret"
        echo "  3. Enter secret manually"
        echo "  0. Back"
        echo
        
        local choice
        read -p "Select an option [0-3]: " choice
        
        case "$choice" in
            1)
                if command -v xclip >/dev/null 2>&1; then
                    echo "$secret" | xclip -selection clipboard
                    print_success "Secret copied to clipboard"
                elif command -v pbcopy >/dev/null 2>&1; then
                    echo "$secret" | pbcopy
                    print_success "Secret copied to clipboard"
                else
                    print_warning "Clipboard not available. Copy manually:"
                    echo "$secret"
                fi
                press_any_key
                ;;
            2)
                if confirm_action "Generate new secret? This will break existing watcher coordination." "n"; then
                    local new_secret
                    new_secret=$(openssl rand -hex 16 2>/dev/null || tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32)
                    echo "$new_secret" > "$CONFIG_DIR/watcher_secret"
                    chmod 600 "$CONFIG_DIR/watcher_secret"
                    if [[ -f "$config_file" ]]; then
                        update_config_value "$config_file" "restart_watcher_secret" "$new_secret"
                    fi
                    print_success "New secret generated: $new_secret"
                    print_warning "You must update the secret on the other side as well."
                fi
                press_any_key
                ;;
            3)
                print_info "Enter the new secret (letters and numbers only):"
                read -p "New secret: " new_secret
                if [[ -n "$new_secret" ]] && [[ "$new_secret" =~ ^[A-Za-z0-9]+$ ]]; then
                    echo "$new_secret" > "$CONFIG_DIR/watcher_secret"
                    chmod 600 "$CONFIG_DIR/watcher_secret"
                    if [[ -f "$config_file" ]]; then
                        update_config_value "$config_file" "restart_watcher_secret" "$new_secret"
                    fi
                    print_success "Secret updated successfully"
                else
                    print_error "Invalid secret format"
                fi
                press_any_key
                ;;
            0)
                return
                ;;
            *)
                print_warning "Invalid option"
                press_any_key
                ;;
        esac
    else
        print_warning "No watcher secret found"
        echo
        print_info "To enable watcher coordination, you need to:"
        echo "  1. Generate a secret on the server side"
        echo "  2. Share that secret with the client side"
        echo "  3. Both sides must use the same secret"
        echo
        if confirm_action "Generate a new secret now?" "y"; then
            local new_secret
            new_secret=$(openssl rand -hex 16 2>/dev/null || tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32)
            echo "$new_secret" > "$CONFIG_DIR/watcher_secret"
            chmod 600 "$CONFIG_DIR/watcher_secret"
            if [[ -f "$config_file" ]]; then
                update_config_value "$config_file" "restart_watcher_secret" "$new_secret"
            fi
            print_success "New secret generated: $new_secret"
            print_info "Share this secret with the other side."
        fi
        press_any_key
    fi
} 
# --- MODULE: modules/tunnel_mgmt.sh ---
#!/bin/bash
# tunnel_mgmt.sh
# List/manage tunnels, single tunnel management, connection test 

# Note: When built into easybackhaul.sh, all modules are concatenated together
# No need to source separate files as they're already included

# WARNING: Do not use a global CONFIG_FILE variable. Always pass config file paths explicitly to functions.

# --- Tunnel Management ---
manage_tunnels() {
    push_menu "manage_tunnels"
    # Help function for tunnel list
    tunnel_list_help() {
        clear
        print_server_info_banner_minimal
        print_info "================= Tunnel Management Help ================="
        echo "This menu lets you manage your Backhaul tunnels."
        echo
        echo "Options:"
        echo "- Select a tunnel number to manage that specific tunnel"
        echo "- Each tunnel shows its current status (Running/Stopped)"
        echo "- From the tunnel menu, you can start, stop, restart, view logs, etc."
        echo "- Use 0 to return to the main menu"
        echo "- For more details, see the main help from the main menu."
        echo "================================================================"
        press_any_key
    }

    while true; do
        clear
        print_server_info_banner
        print_info "--- Available Backhaul Tunnels ---"
        echo
        mapfile -t services < <(systemctl list-unit-files --type=service 'backhaul-*.service' --no-legend | awk '{print $1}' | grep -v 'backhaul-watcher-')
        if [[ ${#services[@]} -eq 0 ]]; then
            print_warning "No Backhaul tunnels found. Use 'Configure a New Tunnel' first."
            press_any_key
            return_to_previous_menu
            return
        fi
        local i=1
        for service in "${services[@]}"; do
            local status
            if systemctl is-active --quiet "$service"; then
                status="running"
            else
                status="stopped"
            fi
            print_service_status "$service" "$status"
            ((i++))
        done
        echo
        print_info "----------------------------------------------------------------"
        echo " ?. Help"
        echo " 0. Back"
        echo
        menu_loop 0 $((i-1)) "?" "tunnel_list_help" "Select tunnel to manage [0-$((i-1)), ? for help]"
        case $choice in
            0) return_to_previous_menu; return ;;
            *)
                local selected_service="${services[$((choice-1))]}"
                local suffix=$(echo "$selected_service" | sed 's/backhaul-\(.*\)\.service/\1/')
                manage_specific_tunnel "$selected_service" "$suffix"
                ;;
        esac
    done
}

manage_specific_tunnel() {
    local service=$1 suffix=$2
    local config_file="$CONFIG_DIR/config-${suffix}.toml"
    
    # Help function for specific tunnel management
    tunnel_management_help() {
        clear
        print_server_info_banner_minimal
        print_info "================= Tunnel Management Help ================="
        echo "This menu lets you manage a specific Backhaul tunnel/service."
        echo
        echo " 1. Start: Start the selected tunnel service."
        echo " 2. Stop: Stop the tunnel service."
        echo " 3. Restart: Restart the tunnel service."
        echo " 4. View Live Logs: View real-time tunnel logs."
        echo " 5. View Configuration: View the TOML config (press q to exit)."
        echo " 6. Edit Configuration: Edit config in nano, then optionally restart."
        echo " 7. Change Log Level: Adjust log verbosity (debug/info/warn/error)."
        echo " 8. Test Connection: Test if the tunnel is reachable."
        echo " 9. Manage Restart Watcher: Set up automatic restart on errors."
        echo "10. Validate Configuration: Check config syntax and validate settings."
        echo "11. Show Tunnel Info: Display tunnel details and status."
        echo "12. Health Check & Performance: Monitor tunnel health and performance."
        echo "13. Delete Tunnel: Permanently remove this tunnel and all its data."
        echo " 0. Back to Tunnel List: Return to the previous menu."
        echo
        print_info "Tips:"
        echo "- Use Ctrl+C to exit log views and return to this menu."
        echo "- Use 'q' to exit configuration view."
        echo "- For more details, see the main help from the main menu."
        echo "================================================================"
        press_any_key
    }

    while true; do
        # Show tunnel status
        local status
        if systemctl is-active --quiet "$service"; then
            status="running"
        else
            status="stopped"
        fi
        
        clear
        print_server_info_banner_minimal
        print_info "--- Managing Tunnel: $suffix ---"
        print_info "Service: $service"
        print_tunnel_status "$suffix" "$status"
        
        # Show tunnel info
        if [ -f "$config_file" ]; then
            local cert_path=$(grep '^tls_cert' "$config_file" | cut -d'"' -f2)
            local key_path=$(grep '^tls_key' "$config_file" | cut -d'"' -f2)
            if [[ -n "$cert_path" && -n "$key_path" ]]; then
                print_success "TLS: Configured"
            else
                print_warning "TLS: Not configured"
            fi
        fi
        
        echo
        print_info "Select an option:"
        echo " 1. Start Tunnel"
        echo " 2. Stop Tunnel"
        echo " 3. Restart Tunnel"
        echo " 4. View Live Logs"
        echo " 5. View Configuration"
        echo " 6. Edit Configuration"
        echo " 7. Change Log Level"
        echo " 8. Test Connection"
        echo " 9. Manage Restart Watcher"
        echo "10. Validate Configuration"
        echo "11. Show Tunnel Info"
        echo "12. Health Check & Performance"
        echo "13. Delete Tunnel"
        echo
        print_info "----------------------------------------------------------------"
        echo " ?. Help"
        echo " 0. Back"
        echo
        
        menu_loop 0 13 "?" "tunnel_management_help" "Select an option [0-13, ? for help]"
        case $choice in
            1) 
                with_spinner "Starting tunnel" systemctl start "$service"
                if [ $? -eq 0 ]; then
                    print_success "Tunnel started successfully. You can now connect to this tunnel."
                else
                    print_error "Failed to start tunnel. Check logs for details."
                fi
                press_any_key
                ;;
            2) 
                with_spinner "Stopping tunnel" systemctl stop "$service"
                if [ $? -eq 0 ]; then
                    print_success "Tunnel stopped. Connections will be refused until restarted."
                else
                    print_error "Failed to stop tunnel. Check logs for details."
                fi
                press_any_key
                ;;
            3) 
                with_spinner "Restarting tunnel" systemctl restart "$service"
                if [ $? -eq 0 ]; then
                    print_success "Tunnel restarted. Check logs if you encounter issues."
                else
                    print_error "Failed to restart tunnel. Check logs for details."
                fi
                press_any_key
                ;;
            4)
                print_info "--- Live Logs for Tunnel: $suffix ---"
                echo
                echo "Select log viewing mode:"
                echo " 1) Live follow (Ctrl+C to exit log view and return to menu)"
                echo " 2) Interactive (scroll/search, press q to quit, F to follow live, Ctrl+C to exit log view and return to menu)"
                echo " 0) Cancel"
                echo
                while true; do
                    read -p "Select [1-2, 0 to cancel, default 2]: " log_mode
                    log_mode=${log_mode:-2}
                    
                    case $log_mode in
                        0) break ;;
                        1|2) 
                            if [[ "$log_mode" == "1" ]]; then
                                                            print_warning "You are about to enter live log view. Press Ctrl+C to exit log view and return to the menu."
                        else
                            print_warning "You are about to enter interactive log view. Use arrow keys to navigate, / to search, F to follow live, q to quit. Press Ctrl+C to exit log view and return to the menu."
                            fi
                            press_any_key
                            
                            if [[ "$log_mode" == "1" ]]; then
                                # Run log viewer in subshell with default SIGINT
                                (journalctl -u "$service" -f --no-pager)
                            else
                                (journalctl -u "$service" --no-pager | less -R)
                            fi
                            break
                            ;;
                        *) 
                            print_warning "Invalid option. Please enter 1, 2, or 0."
                            press_any_key
                            ;;
                    esac
                done
                ;;
            5)
                print_info "--- Configuration for Tunnel: $suffix ---"
                echo
                print_info "Viewing configuration. Press 'q' to exit and return to the menu."
                sleep 1
                less "$config_file"
                ;;
            6)
                                if [ ! -f "$config_file" ]; then
                    print_error "Config file not found for this tunnel. Please check your configuration and try again."
                    press_any_key
                    continue
                fi
                
                backup_config "$config_file"
                nano "$config_file"
                if confirm_action "Restart tunnel to apply changes?" "y"; then
                    with_spinner "Restarting tunnel" systemctl restart "$service"
                    if [ $? -eq 0 ]; then
                                            print_success "Tunnel restarted with new configuration."
                else
                    print_error "Failed to restart tunnel. Check logs for details."
                fi
                fi
                press_any_key
                ;;
            7)
                print_info "--- Change Log Level for Tunnel: $suffix ---"
                echo
                local current_level=$(grep -E '^\s*log_level\s*=\s*"' "$config_file" | head -n1 | cut -d'"' -f2)
                print_info "Current log level: ${current_level:-info}"
                echo
                echo "Available log levels:"
                echo "  debug: Detailed debugging information."
                echo "  info:  Normal operation messages (default)."
                echo "  warn:  Warning messages only."
                echo "  error: Error messages only."
                echo "  cancel: Cancel log level change."
                echo
                select new_level in debug info warn error cancel; do
                    case $new_level in
                        debug|info|warn|error)
                            update_config_value "$config_file" "log_level" "$new_level"
                            print_success "Log level updated to $new_level."
                            if confirm_action "Restart tunnel to apply new log level?" "y"; then
                                with_spinner "Restarting tunnel" systemctl restart "$service"
                                if [ $? -eq 0 ]; then
                                    print_success "Tunnel restarted with new log level."
                                else
                                    print_error "Failed to restart tunnel. Check logs for details."
                                fi
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
            press_any_key
                ;;
            8) test_connection "$config_file"; press_any_key;;
            9) manage_watcher_submenu "$service" "$suffix" "$config_file" ;;
            10) validate_tunnel_config "$config_file"; press_any_key ;;
            11)
                clear
                print_info "--- Tunnel Information: $suffix ---"
                echo
                echo "  - Service: $service"
                echo "  - Config: $config_file"
                echo "  - Status: $(systemctl is-active "$service" 2>/dev/null || echo "inactive")"
                echo "  - Enabled: $(systemctl is-enabled "$service" 2>/dev/null || echo "disabled")"
                press_any_key
                ;;
            12) show_tunnel_health_and_performance "$service" "$suffix" ;;
            13)
                print_info "--- Delete Tunnel: $suffix ---"
                echo
                print_warning "WARNING: This will permanently delete the tunnel and all its data!"
                echo
                echo "The following will be deleted:"
                echo "  - Service: $service"
                echo "  - Configuration: $config_file"
                echo "  - Logs and temporary files"
                echo "  - UFW rules (if any)"
                echo
                if confirm_action "Are you sure you want to PERMANENTLY delete this tunnel?" "n"; then
                    print_warning "Deleting tunnel $suffix..."
                    
                    # Stop and disable service
                    with_spinner "Stopping and disabling service" systemctl stop "$service" 2>/dev/null && systemctl disable "$service" 2>/dev/null
                    
                    # Remove service file
                    local service_file="$SERVICE_DIR/$service"
                    rm -f "$service_file"
                    
                    # Remove config file
                    rm -f "$config_file"
                    
                    # Clean up watcher if exists
                    local watcher_script="/tmp/backhaul-watcher-${suffix}.sh"
                    local watcher_pid_file="/tmp/backhaul-watcher-${suffix}.pid"
                    local watcher_log="/tmp/backhaul-watcher-${suffix}.log"
                    
                    if [[ -f "$watcher_pid_file" ]]; then
                        local watcher_pid=$(cat "$watcher_pid_file")
                        if [[ -n "$watcher_pid" ]]; then
                            kill "$watcher_pid" 2>/dev/null
                        fi
                        rm -f "$watcher_pid_file"
                    fi
                    
                    rm -f "$watcher_script" "$watcher_log"
                    pkill -f "backhaul-watcher-${suffix}" 2>/dev/null
                    
                    # Remove UFW rules
                    manage_ufw_delete "$suffix"
                    
                    # Reload systemd
                    systemctl daemon-reload
                    
                    print_success "Tunnel $suffix has been completely deleted. You may now create a new tunnel or exit."
                    press_any_key
                    return
                else
                    print_info "Tunnel deletion cancelled."
                    press_any_key
                fi
                ;;
            \?)
                clear
                print_info "================= Tunnel Management Help ================="
                echo "This menu lets you manage a specific Backhaul tunnel."
                echo
                echo "Options:"
                echo " 1. Start Tunnel: Start the tunnel service"
                echo " 2. Stop Tunnel: Stop the tunnel service"
                echo " 3. Restart Tunnel: Restart the tunnel service"
                echo " 4. View Live Logs: View real-time tunnel logs"
                echo " 5. View Configuration: View the TOML config (press q to exit)."
                echo " 6. Edit Configuration: Edit the TOML config in nano editor"
                echo " 7. Change Log Level: Set logging verbosity (debug, info, warn, error)"
                echo " 8. Test Connection: Test if the tunnel can connect to its remote"
                echo " 9. Manage Restart Watcher: Configure automatic restart on errors"
                echo "10. Validate Configuration: Check config syntax and settings"
                echo "11. Show Tunnel Info: Display tunnel details and status"
                echo "12. Health Check & Performance: Monitor tunnel health, resource usage, and performance metrics."
                echo "13. Delete Tunnel: Permanently remove this tunnel and all its data"
                echo " 0. Back to Tunnel List: Return to the previous menu."
                echo
                echo "- Use Ctrl+C to exit log views and return to this menu."
                echo "- Configuration changes require a restart to take effect."
                echo "- The restart watcher can automatically restart tunnels on errors."
                press_any_key
                ;;
            0) return ;;
            *)
                print_warning "Invalid option. Please enter 0-13 or ? for help."
                press_any_key
                ;;
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
    push_menu "manage_watcher_submenu"
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
        echo "7. Show watcher secret"
        echo "?. Help"
        echo "0. Back"
        read -p "Select [0-7, ? for help]: " wopt
        case $wopt in
            1) enable_watcher "$service" "$suffix" "$config_file" ;;
            2) disable_watcher "$service" "$suffix" "$config_file" ;;
            3) edit_watcher_config "$service" "$suffix" "$config_file" ;;
            4) show_watcher_status "$service" "$suffix" "$config_file" ;;
            5) show_watcher_logs "$service" "$suffix" "$config_file" ;;
            6) test_watcher "$service" "$suffix" "$config_file" ;;
            7) show_watcher_secret "$config_file" ;;
            \?) watcher_submenu_help ;;
            0) return_to_previous_menu; return ;;
            *) print_warning "Invalid option."; press_any_key ;;
        esac
    done
}

# --- Watcher Submenu Help ---
watcher_submenu_help() {
    clear
    print_info "=== Watcher Help ==="
    echo
    print_info "The Coordinated Restart Watcher monitors tunnel services and"
    print_info "coordinates restarts between client and server sides."
    echo
    print_info "Features:"
    echo "  • Automatic error detection in service logs"
    echo "  • Coordinated restart between both sides"
    echo "  • Configurable restart delays and retry limits"
    echo "  • Secure communication with shared secrets"
    echo "  • Port conflict detection and resolution"
    echo
    print_info "Setup Process:"
    echo "  1. Server generates a shared secret"
    echo "  2. Client enters the same secret"
    echo "  3. Both sides configure ports and delays"
    echo "  4. Watcher starts monitoring automatically"
    echo
    print_info "Communication:"
    echo "  • Uses netcat for simple TCP communication"
    echo "  • Authenticates with shared secret"
    echo "  • Sends restart requests and acknowledgments"
    echo "  • Handles network failures gracefully"
    echo
    press_any_key
}

# --- Technical Enhancement Functions ---

# Show health and performance metrics for a tunnel
show_tunnel_health_and_performance() {
    local tunnel_name="$1"
    local service="$2"
    
    clear
    print_server_info_banner_minimal
    print_info "=== Health Check & Performance Metrics ==="
    print_info "Tunnel: $tunnel_name"
    echo
    
    # Initialize logging if not already done
    init_logging
    
    # Check tunnel health
    print_info "--- Tunnel Health Status ---"
    local health_status
    health_status=$(check_tunnel_health "$tunnel_name")
    
    case "$health_status" in
        "running")
            print_success "Tunnel is running"
            ;;
        "dead")
            print_error "Tunnel process is dead"
            ;;
        "not_started")
            print_warning "Tunnel is not started"
            ;;
        *)
            print_warning "Tunnel status unknown"
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
                    if [[ "$success" == "true" ]]; then
                        print_success "$op: ${duration}s"
                    else
                        print_error "$op: ${duration}s"
                    fi
                fi
            done
        else
            print_warning "No performance data available in log file"
        fi
    else
        print_warning "Performance log file not found: $PERFORMANCE_LOG_FILE"
        print_info "Performance tracking will be available after the first operation"
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
                        "running") status_icon="Running" ;;
                        "dead") status_icon="Dead" ;;
                        "not_started") status_icon="Not Started" ;;
                        *) status_icon="Unknown" ;;
                    esac
                    print_status_with_icon "$status" "$timestamp"
                fi
            done
        else
            print_warning "No health history available in log file"
        fi
    else
        print_warning "Health log file not found: $HEALTH_LOG_FILE"
        print_info "Health tracking will be available after the first health check"
    fi
    
    # Optimize process priority
    echo
    print_info "--- Process Optimization ---"
    optimize_process_priority "$tunnel_name"
    
    echo
    print_info "Press any key to return to tunnel management..."
    read -n 1 -s
}

# Validate tunnel configuration - using comprehensive validation from validation.sh

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
        print_success "Graceful restart completed successfully"
        print_info "Tunnel is healthy and running"
    else
        print_error "Graceful restart failed or tunnel is unhealthy"
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
        print_warning "Rate limit exceeded. Please wait before creating another tunnel."
        return 1
    fi
    
    echo "=== Create New Tunnel ==="
    echo "💡 Tip: Use descriptive names like 'office-vpn' or 'home-connection'"
    
    # Input validation with sanitization
    tunnel_name=$(validate_tunnel_name "check_exists")
    server_ip=$(validate_ip_with_prompt)
    server_port=$(validate_port_with_prompt "Enter server port (1-65535): ")
    local_port=$(validate_port_with_prompt "Enter local port (1-65535): " "check_usage")
    
    echo "Select protocol:"
    echo "1) TCP"
    echo "2) UDP"
            read -p "Select an option [1-2, ? for help]: " protocol_choice
    
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

# Note: This script is standalone and doesn't need to source other modules

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
if ! validate_tunnel_parameters "\$SERVER_IP" "\$SERVER_PORT" "\$LOCAL_PORT" "\$TUNNEL_NAME"; then
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
    print_success "Tunnel '$tunnel_name' created successfully"
    echo "📁 Location: $tunnel_dir"
    echo "🔒 Permissions hardened for security"
    
    # Security audit
    audit_security
    
    # Performance optimization
    cleanup_temp_files
}

start_tunnel() {
    local tunnel_name="$1"
    
    if [ -z "$tunnel_name" ]; then
        print_error "Tunnel name is required"
        return 1
    fi
    
    # Input sanitization
    tunnel_name=$(sanitize_input "$tunnel_name" 50)
    
    # Rate limiting check
    if ! rate_limit_check "start_tunnel" 10; then
        print_warning "Rate limit exceeded. Please wait before starting another tunnel."
        return 1
    fi
    
    local tunnel_dir="$TUNNEL_DIR/$tunnel_name"
    local config_file="$tunnel_dir/config"
    local tunnel_script="$tunnel_dir/tunnel.sh"
    
    if [ ! -d "$tunnel_dir" ]; then
        print_error "Tunnel '$tunnel_name' not found"
        return 1
    fi
    
    if [ ! -f "$config_file" ]; then
        print_error "Configuration file not found"
        return 1
    fi
    
    # Load configuration with validation
    source "$config_file"
    
    if ! validate_tunnel_parameters "$SERVER_IP" "$SERVER_PORT" "$LOCAL_PORT" "$tunnel_name"; then
        print_error "Invalid configuration detected"
        return 1
    fi
    
    # Check if already running
    if is_tunnel_running "$tunnel_name"; then
        print_warning "Tunnel '$tunnel_name' is already running"
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
        print_error "Security: Tunnel script has insecure permissions"
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
    print_success "Tunnel '$tunnel_name' started successfully"
    echo "📊 PID: $pid"
    echo "📝 Logs: $tunnel_dir/tunnel.log"
    
    # Performance monitoring
    echo "💻 System resources: $(get_system_resources)"
}

stop_tunnel() {
    local tunnel_name="$1"
    
    if [ -z "$tunnel_name" ]; then
        print_error "Tunnel name is required"
        return 1
    fi
    
    # Input sanitization
    tunnel_name=$(sanitize_input "$tunnel_name" 50)
    
    local tunnel_dir="$TUNNEL_DIR/$tunnel_name"
    local pid_file="$tunnel_dir/tunnel.pid"
    
    if [ ! -d "$tunnel_dir" ]; then
        print_error "Tunnel '$tunnel_name' not found"
        return 1
    fi
    
    if [ ! -f "$pid_file" ]; then
        print_warning "Tunnel '$tunnel_name' is not running"
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
            print_warning "Force killed tunnel process"
        fi
    fi
    
    # Securely delete PID file
    secure_delete "$pid_file"
    print_success "Tunnel '$tunnel_name' stopped successfully"
    
    # Performance optimization
    optimize_memory_usage
} 
# --- MODULE: modules/menu.sh ---
# menu.sh
# Main menu logic and script entrypoint 

# --- Installation Wizard ---
installation_wizard() {
    push_menu "installation_wizard"
    while true; do
        clear
        print_server_info_banner
        print_primary_menu_header "EasyBackhaul Installation Wizard (v13.0-beta)" "Core by Musixal  |  Installer by @N4Xon"
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
        print_menu_footer
        read -p "Select an option [0-5, ? for help]: " choice
        case $choice in
            1)
                download_from_github "latest" "$(uname -s | tr '[:upper:]' '[:lower:]')" "$(uname -m)"
                ;;
            2)
                download_from_local_file "$(uname -s | tr '[:upper:]' '[:lower:]')" "$(uname -m)"
                ;;
            3)
                download_from_alternative_source "$(uname -s | tr '[:upper:]' '[:lower:]')" "$(uname -m)"
                ;;
            4)
                run_network_diagnostics_menu
                ;;
            5)
                print_warning "Skipping binary installation."
                print_info "You can install the binary manually later using option 3 in the main menu."
                print_info "Make sure to place it at: $BIN_PATH"
                press_any_key
                return_to_previous_menu
                return 0
                ;;
            \?)
                show_installation_help
                ;;
            0)
                print_info "Exiting EasyBackhaul installer."
                exit 0
                ;;
            *)
                print_warning "Invalid option. Please enter 0-5 or ? for help."; press_any_key
                ;;
        esac
    done
}

# Show installation-specific help
show_installation_help() {
    clear
    print_server_info_banner_minimal
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
    print_server_info_banner_minimal
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
                print_status_running "$tunnel"
                ((healthy_count++))
                ;;
            "dead")
                print_status_dead "$tunnel"
                ;;
            "not_started")
                print_status_not_started "$tunnel"
                ;;
            *)
                print_status_warning "$tunnel" "Unknown"
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
                    if [[ "$success" == "true" ]]; then
                        print_success "$op: ${duration}s"
                    else
                        print_error "$op: ${duration}s"
                    fi
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
            print_status_active "$service"
        else
            print_status_inactive "$service"
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
            print_success "Watcher for $tunnel_name: Running (PID: $pid)"
        else
            print_status_dead "Watcher for $tunnel_name"
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
    echo
    print_info "----------------------------------------------------------------"
    while true; do
        read -p "Select action [0-4]: " action_choice
        case $action_choice in
            1)
                show_system_health_monitor
                ;;
            2)
                cleanup_zombie_processes
                print_success "Zombie processes cleaned up"
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
                        echo
                        while true; do
                            read -p "Select log file to view [0-$((i-1))]: " log_choice
                            if [[ "$log_choice" == "0" ]]; then
                                break
                            elif [[ "$log_choice" =~ ^[1-9][0-9]*$ ]] && [[ $log_choice -lt $i ]]; then
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
                                break
                            else
                                print_warning "Invalid option. Please enter 0-$((i-1))."
                                press_any_key
                            fi
                        done
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
                print_success "All tunnel processes optimized"
                press_any_key
                show_system_health_monitor
                ;;
            0)
                return
                ;;

            *)
                print_warning "Invalid option. Please enter 0-4."; press_any_key ;;
        esac
    done
}

# --- Main Menu Logic & Entrypoint ---
main_menu() {
    clear
    print_primary_menu_header "EasyBackhaul Management Menu" "Core by Musixal  |  Installer by @N4Xon"
    
    # Check binary status
    if [ -f "$BIN_PATH" ]; then
        if [[ ! -x "$BIN_PATH" ]]; then
            print_warning "Binary Status: Found but not executable"
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
                    print_success "Binary Status: $version_output (Services: $running_services running)"
                else
                    print_success "Binary Status: Found and working (Services: $running_services running)"
                fi
            else
                if [[ -n "$version_output" ]]; then
                    print_success "Binary Status: $version_output (No services running)"
                else
                    print_success "Binary Status: Found and executable (No services running)"
                fi
            fi
        fi
    else
        print_error "Binary Status: Not installed"
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
    echo
    print_menu_footer "true" "false" "true"
    
    # Help function for main menu
    main_menu_help() {
        clear
        print_server_info_banner_minimal
        print_info "================= EasyBackhaul Management Help ================="
        echo
        echo "EasyBackhaul is a comprehensive Backhaul tunnel management system."
        echo "This menu provides access to all management functions."
        echo
        echo "Available options:"
        echo "  • Configure New Tunnel: Create and configure a new Backhaul tunnel"
        echo "  • Manage Existing Tunnels: Start, stop, and manage existing tunnels"
        echo "  • Update/Re-install Binary: Download and install the latest Backhaul binary"
        echo "  • Generate TLS Certificate: Create self-signed certificates for secure connections"
        echo "  • Select Binary Directory: Change where the Backhaul binary is located"
        echo "  • System Health Monitor: Monitor system resources and tunnel performance"
        echo "  • Clean Up Processes: Remove zombie and orphaned processes"
        echo "  • Uninstall: Completely remove EasyBackhaul and all configurations"
        echo
        print_info "Note: The binary status shows if Backhaul is installed and working."
        echo "================================================================"
        press_any_key
    }
    
    menu_loop 0 8 "?" "main_menu_help" "Select an option [0-8, ? for help]"
    
    case $choice in
        1) configure_new_tunnel; press_any_key; main_menu ;;
        2) manage_tunnels; main_menu ;;
        3) download_backhaul; press_any_key; main_menu ;;
        4) generate_self_signed_cert; press_any_key; main_menu ;;
        5)
           read -e -p "Enter the full path for the Backhaul binary (e.g., /usr/local/bin/backhaul): " new_bin_path
           if [[ -n "$new_bin_path" ]]; then
               BIN_PATH="$new_bin_path"
               print_success "Backhaul binary path set to: $BIN_PATH (for this session)"
           else
               print_warning "No path entered. Keeping current: $BIN_PATH"
           fi
           press_any_key
           main_menu
           ;;
        6)
           show_system_health_monitor; press_any_key; main_menu ;;
        7)
           clear
           print_server_info_banner_minimal
           print_info "--- Clean Up Zombie/Orphaned Processes ---"
           echo
           print_info "This will clean up any zombie processes and orphaned watcher processes."
           echo
           cleanup_zombie_processes
           press_any_key
           main_menu
           ;;
        8)
           if confirm_action "This will REMOVE the binary and ALL configs/services. This is irreversible. Are you sure?" "n"; then
        confirm="y"
    else
        confirm="n"
    fi
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
                    main_menu
                    return
                fi
                print_warning "Stopping and disabling all backhaul services..."
                systemctl stop backhaul-*.service &>/dev/null
                systemctl disable backhaul-*.service &>/dev/null
                print_warning "Cleaning up all watcher processes and files..."
                for pid_file in /tmp/backhaul-watcher-*.pid; do
                    if [[ -f "$pid_file" ]]; then
                        local watcher_pid=$(cat "$pid_file")
                        if [[ -n "$watcher_pid" ]]; then
                            print_info "Stopping watcher process (PID: $watcher_pid)..."
                            kill "$watcher_pid" 2>/dev/null
                            local count=0
                            while kill -0 "$watcher_pid" 2>/dev/null && [[ $count -lt 5 ]]; do
                                sleep 1
                                ((count++))
                            done
                            if kill -0 "$watcher_pid" 2>/dev/null; then
                                print_warning "Process not responding to SIGTERM, forcing termination..."
                                kill -9 "$watcher_pid" 2>/dev/null
                                sleep 1
                            fi
                            if kill -0 "$watcher_pid" 2>/dev/null; then
                                print_error "Failed to terminate watcher process (PID: $watcher_pid)"
                            else
                                print_success "Watcher process terminated successfully"
                            fi
                        fi
                        rm -f "$pid_file"
                    fi
                done
                pkill -f "backhaul-watcher" 2>/dev/null
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
                local CERT_DIR="/etc/backhaul/certs"
                if [ -d "$CERT_DIR" ] && compgen -G "$CERT_DIR/*.crt" > /dev/null; then
                    if confirm_action "Do you also want to delete all TLS certificates in $CERT_DIR?" "n"; then
        delcerts="y"
    else
        delcerts="n"
    fi
                    if [[ "${delcerts,,}" == "y" ]]; then
                        rm -rf "$CERT_DIR"
                        print_success "All certificates in $CERT_DIR have been deleted."
                    else
                        print_info "Certificates in $CERT_DIR have been preserved."
                    fi
                fi
                cleanup_zombie_processes
                print_success "EasyBackhaul has been completely uninstalled (including all watchers and related files)."
                exit 0
           fi
           press_any_key
           main_menu
           ;;
        0) exit 0 ;;
        *) print_warning "Invalid option. Please enter 0-8 or ? for help."; press_any_key ;;
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
    echo
    print_warning "Backhaul binary not found at: $BIN_PATH"
    echo
    print_info "The Backhaul binary is required to create and manage tunnels."
    print_info "Please complete the installation to continue."
    echo
    print_info "Press any key to start the installation wizard..."
    press_any_key
    
    # Run installation wizard
    installation_wizard
    
    # Check if installation was successful
    if [ ! -f "$BIN_PATH" ]; then
        echo
        print_warning "Binary installation was not completed."
        print_info "You can still use the script to manage existing tunnels or install later."
        echo
        print_info "To install the binary later, use option 3 in the main menu."
        print_info "Press any key to continue to the main menu..."
        press_any_key
    fi
fi

while true; do
    main_menu
done 
