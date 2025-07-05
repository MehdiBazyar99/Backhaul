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
# Enhanced error handling with logging and recovery
handle_error() {
    local error_msg="$1"
    local return_code="${2:-1}"
    local operation="${3:-unknown}"
    local tunnel_name="${4:-}"
    local retry_count="${5:-0}"
    
    log_error "Error in $operation: $error_msg (attempt $((retry_count + 1)))"
    print_error "$error_msg"
    
    # Check for resource exhaustion
    if check_resource_exhaustion; then
        log_warn "Resource exhaustion detected during $operation"
        optimize_memory_usage
        cleanup_temp_files
    fi
    
    # Check for network connectivity issues
    if [[ "$error_msg" =~ (connection|network|timeout|unreachable) ]]; then
        log_warn "Network-related error detected"
        test_network_connectivity
    fi
    
    # Attempt recovery if enabled and retry count is within limits
    if [[ "$ERROR_RECOVERY_ENABLED" == "true" && $retry_count -lt 3 ]]; then
        local recovery_result
        recovery_result=$(attempt_error_recovery "$operation" "$error_msg" "$tunnel_name" "$retry_count")
        if [[ $? -eq 0 ]]; then
            log_success "Error recovery successful, retrying operation"
            return 0
        fi
    fi
    
    # Log final failure
    if [[ $retry_count -ge 3 ]]; then
        log_error "Operation failed after $retry_count retry attempts"
    fi
    
    return "$return_code"
}

# Enhanced error recovery attempts with retry logic
attempt_error_recovery() {
    local operation="$1"
    local error_msg="$2"
    local tunnel_name="$3"
    local retry_count="${4:-0}"
    
    log_info "Attempting error recovery for operation: $operation (attempt $((retry_count + 1)))"
    
    case "$operation" in
        "tunnel_start"|"tunnel_restart")
            log_info "Attempting tunnel recovery..."
            cleanup_zombie_processes
            
            # Try to restart the specific tunnel
            if [[ -n "$tunnel_name" ]]; then
                local service_name="backhaul-$tunnel_name"
                if systemctl list-unit-files | grep -q "$service_name"; then
                    log_info "Attempting to restart service: $service_name"
                    
                    # Stop service first
                    systemctl stop "$service_name" 2>/dev/null
                    sleep 2
                    
                    # Start service
                    systemctl start "$service_name" 2>/dev/null
                    sleep 3
                    
                    # Check if restart was successful
                    if systemctl is-active --quiet "$service_name" 2>/dev/null; then
                        log_success "Tunnel recovery successful"
                        return 0
                    else
                        log_error "Tunnel recovery failed"
                        
                        # Try alternative recovery methods
                        attempt_alternative_tunnel_recovery "$tunnel_name"
                    fi
                fi
            fi
            ;;
        "config_validation"|"config_error")
            log_info "Attempting config recovery..."
            if [[ -n "$tunnel_name" ]]; then
                if restore_config_backup "$tunnel_name"; then
                    log_success "Configuration recovery successful"
                    return 0
                fi
            fi
            ;;
        "systemd_service"|"service_error")
            log_info "Attempting systemd service recovery..."
            systemctl daemon-reload 2>/dev/null
            sleep 1
            
            # Try to reset failed services
            systemctl reset-failed 2>/dev/null
            
            if [[ -n "$tunnel_name" ]]; then
                local service_name="backhaul-$tunnel_name"
                systemctl reset-failed "$service_name" 2>/dev/null
            fi
            ;;
        "ufw_rules"|"firewall_error")
            log_info "Attempting UFW rules recovery..."
            ufw reload 2>/dev/null
            sleep 2
            
            # Check UFW status
            if ufw status | grep -q "Status: active"; then
                log_success "UFW recovery successful"
                return 0
            fi
            ;;
        "network_error"|"connectivity_error")
            log_info "Attempting network recovery..."
            
            # Check network interfaces
            if ! ip link show | grep -q "UP"; then
                log_warn "No network interfaces are up"
                return 1
            fi
            
            # Test basic connectivity
            if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
                log_success "Network connectivity restored"
                return 0
            fi
            ;;
        "permission_error"|"access_denied")
            log_info "Attempting permission recovery..."
            
            # Check if running as root
            if [[ $(id -u) -ne 0 ]]; then
                log_error "Permission error: script must be run as root"
                return 1
            fi
            
            # Fix common permission issues
            chmod 755 "$CONFIG_DIR" 2>/dev/null
            chmod 600 "$CONFIG_DIR"/*.conf 2>/dev/null
            ;;
        *)
            log_info "No specific recovery for operation: $operation"
            ;;
    esac
    
    return 1
}

# Alternative tunnel recovery methods
attempt_alternative_tunnel_recovery() {
    local tunnel_name="$1"
    local tunnel_dir="$TUNNEL_DIR/$tunnel_name"
    
    log_info "Attempting alternative recovery methods for tunnel: $tunnel_name"
    
    # Method 1: Kill any existing processes
    pkill -f "backhaul.*$tunnel_name" 2>/dev/null
    sleep 2
    
    # Method 2: Clean up PID files
    rm -f "$tunnel_dir"/*.pid 2>/dev/null
    
    # Method 3: Try manual start
    if [[ -f "$tunnel_dir/tunnel.sh" ]]; then
        log_info "Attempting manual tunnel start"
        nohup "$tunnel_dir/tunnel.sh" > "$tunnel_dir/tunnel.log" 2>&1 &
        sleep 3
        
        if is_tunnel_running "$tunnel_name"; then
            log_success "Manual tunnel recovery successful"
            return 0
        fi
    fi
    
    return 1
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
    print_warning "❌ Invalid option. Please enter $min-$max or $help_option for help."
}

# Standardized menu loop with validation
menu_loop() {
    local min="$1"
    local max="$2"
    local help_option="${3:-?}"
    local help_function="$4"
    local prompt="$5"
    
    while true; do
        read -p "$prompt: " choice
        validate_menu_choice "$choice" "$min" "$max" "$help_option"
        local result=$?
        
        case $result in
            0) return 0 ;;  # Valid choice
            1) 
                print_invalid_choice "$min" "$max" "$help_option"
                press_any_key
                ;;
            2)  # Help requested
                if [[ -n "$help_function" ]]; then
                    $help_function
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

# Standardized submenu header
print_submenu_header() {
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

# Standardized menu footer
print_menu_footer() {
    echo " ?. Help"
    echo " 0. Back"
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
print_main_menu_header() {
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

print_submenu_header_unified() {
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

print_menu_footer_unified() {
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

# === SYSTEM OPERATIONS ===
# Enhanced system resource management
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

# === NETWORK OPERATIONS ===
# Enhanced network connectivity testing
test_network_connectivity() {
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
        echo -e " $service_name (\e[32m✓ Running\e[0m)"
    else
        echo -e " $service_name (\e[31m✗ Stopped\e[0m)"
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