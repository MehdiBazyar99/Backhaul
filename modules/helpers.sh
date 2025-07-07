# modules/helpers.sh
# Unified utility, print, logging, validation, and menu functions for EasyBackhaul

# --- Color Codes & Icons (Constants) ---
COLOR_BLUE="\e[34m"
COLOR_GREEN="\e[32m"
COLOR_YELLOW="\e[33m"
COLOR_RED="\e[31m"
COLOR_RESET="\e[0m"

ICON_INFO="ℹ"
ICON_SUCCESS="✓"
ICON_WARNING="⚠"
ICON_ERROR="✗"

# --- Basic Print Functions ---
print_info() { echo -e "${COLOR_BLUE}${ICON_INFO} $1${COLOR_RESET}"; }
print_success() { echo -e "${COLOR_GREEN}${ICON_SUCCESS} $1${COLOR_RESET}"; }
print_warning() { echo -e "${COLOR_YELLOW}${ICON_WARNING} $1${COLOR_RESET}"; }
print_error() { echo -e "${COLOR_RED}${ICON_ERROR} $1${COLOR_RESET}"; }
press_any_key() { read -n 1 -s -r -p "Press any key to continue..."; echo; }

# --- Unified Logging System ---
# LOG_LEVEL, LOG_DIR, LOG_MAX_FILES, LOG_FORMAT should be set in globals.sh

# Initialize the logging system (directories, main log file)
init_logging() {
    # Ensure LOG_DIR is set, fallback to a default if necessary (should be defined in globals.sh)
    local current_log_dir="${LOG_DIR:-/var/log/easybackhaul}"
    mkdir -p "$current_log_dir"
    chmod 750 "$current_log_dir"
    
    local main_log_file="$current_log_dir/easybackhaul.log"
    touch "$main_log_file"
    chmod 640 "$main_log_file"

    # Specific log files if they are different from main_log_file
    if [[ -n "${HEALTH_LOG_FILE:-}" && "$HEALTH_LOG_FILE" != "$main_log_file" ]]; then
        touch "$HEALTH_LOG_FILE"
        chmod 640 "$HEALTH_LOG_FILE"
    fi
    if [[ -n "${PERFORMANCE_LOG_FILE:-}" && "$PERFORMANCE_LOG_FILE" != "$main_log_file" ]]; then
        touch "$PERFORMANCE_LOG_FILE"
        chmod 640 "$PERFORMANCE_LOG_FILE"
    fi
    
    if command -v logrotate &>/dev/null; then
        setup_log_rotation
    fi
}

# Setup log rotation for easybackhaul logs
setup_log_rotation() {
    local current_log_dir="${LOG_DIR:-/tmp/easybackhaul_logs}" # Using /tmp for sandbox
    local logrotate_conf_target="/etc/logrotate.d/easybackhaul"
    local logrotate_conf_sandbox="/tmp/easybackhaul_logrotate_conf_test.conf" # Write to /tmp for sandbox
    local max_files_to_rotate="${LOG_MAX_FILES:-5}"

    print_info "Logrotate: Simulating creation of $logrotate_conf_target by writing to $logrotate_conf_sandbox for testing."
    # In a real deployment, this would be: cat > "$logrotate_conf_target" << EOF
    # For sandbox/testing, we write to /tmp to avoid permission errors.
    cat > "$logrotate_conf_sandbox" << EOF
${current_log_dir}/*.log {
    daily
    missingok
    rotate ${max_files_to_rotate}
    compress
    delaycompress
    notifempty
    create 0640 root adm
    postrotate
        # No action needed for script logs generally
    endscript
}
EOF
    chmod 644 "$logrotate_conf_sandbox" # Target the sandbox path
    log_message "DEBUG" "Logrotate (sandbox) configuration created/updated at $logrotate_conf_sandbox."
    # In a real deployment, this would be: log_message "DEBUG" "Logrotate configuration created/updated at $logrotate_conf_target."
    # This function is called by init_logging, so log_message should be available after init_logging completes.
}

# Unified logging function
log_message() {
    local level="$1"
    local message="$2"

    local current_log_dir="${LOG_DIR:-/var/log/easybackhaul}"
    local log_file_to_use="${LOG_FILE_OVERRIDE:-$current_log_dir/easybackhaul.log}"
    local current_log_level="${LOG_LEVEL:-INFO}"
    local current_log_format="${LOG_FORMAT:-text}"
    local timestamp

    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    case "$current_log_level" in
        "DEBUG") ;;
        "INFO") [[ "$level" == "DEBUG" ]] && return ;;
        "WARN") [[ "$level" == "DEBUG" || "$level" == "INFO" ]] && return ;;
        "ERROR") [[ "$level" != "ERROR" && "$level" != "CRITICAL" ]] && return ;;
        "CRITICAL") [[ "$level" != "CRITICAL" ]] && return ;;
        *) [[ "$level" == "DEBUG" ]] && return ;;
    esac
    
    local log_entry
    if [[ "$current_log_format" == "json" ]]; then
        # Basic JSON escaping for the message
        local escaped_message=$(echo "$message" | sed 's/"/\\"/g' | sed 's/\\/\\\\/g')
        log_entry="{\"timestamp\":\"$timestamp\",\"level\":\"$level\",\"message\":\"$escaped_message\"}"
    else
        log_entry="[$timestamp] [$level] $message"
    fi

    echo "$log_entry" >> "$log_file_to_use"
}

# Logging convenience functions
log_debug() { log_message "DEBUG" "$1"; }
log_info()  { log_message "INFO" "$1"; }
log_warn()  { log_message "WARN" "$1"; }
log_error() { log_message "ERROR" "$1"; }
log_success_msg() { log_message "INFO" "SUCCESS: $1"; }

# --- Unified Error Handling & Exiting ---
handle_error() {
    local error_type="$1"
    local message="$2"
    local exit_code="${3:-1}"

    local upper_error_type
    upper_error_type=$(echo "$error_type" | tr '[:lower:]' '[:upper:]')

    case "$upper_error_type" in
        "CRITICAL")
            print_error "CRITICAL: $message"
            log_message "CRITICAL" "$message"
            exit "$exit_code"
            ;;
        "ERROR")
            print_error "ERROR: $message"
            log_message "ERROR" "$message"
            ;;
        "WARNING")
            print_warning "WARNING: $message"
            log_message "WARN" "$message"
            ;;
        "INFO")
            print_info "INFO: $message"
            log_message "INFO" "$message"
            ;;
        *)
            print_error "ERROR (Unknown Type $error_type): $message"
            log_message "ERROR" "(Unknown Type $error_type) $message"
            ;;
    esac
}

handle_critical_error() {
    handle_error "CRITICAL" "$1" "${2:-1}"
}

handle_success() {
    local message="$1"
    print_success "$message"
    log_success_msg "$message"
}

# --- Input Validation Utilities ---
sanitize_input() {
    local input="$1"
    local max_length="${2:-255}" # Increased default max_length
    
    # Remove dangerous characters and limit length.
    # Added @ . : / - _ to allow common characters in paths, IPs, etc.
    # Still restrictive, consider carefully if this is too aggressive.
    echo "$input" | sed "s/[^a-zA-Z0-9@.:/\-_ ]/_/g" | head -c "$max_length"
}

validate_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        local IFS='.'
        read -ra octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if ! [[ "$octet" =~ ^[0-9]+$ ]] || (( octet < 0 || octet > 255 )); then
                return 1 # Invalid octet
            fi
        done
        return 0 # Valid IP
    fi
    return 1 # Does not match IP pattern
}

validate_port() {
    local port="$1"
    if [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )); then
        return 0 # Valid port
    fi
    return 1 # Invalid port
}

validate_tunnel_name_format() {
    local name="$1"
    if [[ "$name" =~ ^[a-zA-Z0-9_-]+$ ]] && [[ ${#name} -ge 1 ]] && [[ ${#name} -le 50 ]]; then
        return 0 # Valid tunnel name
    fi
    # handle_error "WARNING" "Tunnel name '$name' is invalid. Must be 1-50 chars, letters, numbers, hyphens, underscores."
    # Caller should handle the error message for more context.
    return 1
}

# --- Network Utilities ---
check_port_availability() {
    local port_to_check="$1"
    
    if ! validate_port "$port_to_check"; then
        log_message "ERROR" "Invalid port '$port_to_check' for availability check."
        return 1
    fi
    
    # Try ss first (more modern)
    if command -v ss &>/dev/null; then
        if ss -tuln | grep -q ":${port_to_check}[[:space:]]"; then # Added [[:space:]] to avoid matching substrings like 8080 for 80
            return 1 # Port in use
        fi
    # Fallback to netstat
    elif command -v netstat &>/dev/null; then
        if netstat -tuln | grep -q ":${port_to_check}[[:space:]]"; then
            return 1 # Port in use
        fi
    # Fallback to lsof (can be slower)
    elif command -v lsof &>/dev/null; then
        if lsof -i ":$port_to_check" -sTCP:LISTEN -sUDP:LISTEN -P -n -- 2>/dev/null | grep -q LISTEN; then # More specific lsof
            return 1 # Port in use
        fi
    else
        log_message "WARN" "No suitable tool (ss, netstat, lsof) found to check port availability."
        return 2 # Cannot determine
    fi
    
    return 0 # Port available
}

check_nc_compatibility() {
    # Test for OpenBSD netcat compatibility with timeout to prevent hanging
    local nc_test_result=""
    
    if command -v timeout &>/dev/null; then
        nc_test_result=$(timeout 3s bash -c 'echo | nc -l -p 0 -w 1 2>&1' 2>/dev/null || echo "timeout_or_error")
    else
        # Fallback without timeout command - riskier
        ( nc -l -p 0 -w 1 >/dev/null 2>&1 & )
        local nc_pid=$!
        sleep 3
        if kill -0 $nc_pid 2>/dev/null; then
            kill -9 $nc_pid 2>/dev/null
            nc_test_result="timeout_or_error"
        else
            # This path is tricky; if nc fails very fast due to incompatibility, it might seem like success.
            # A more robust check here is difficult without 'timeout'.
            # We'll assume if it exited quickly without error output, it might be okay, or it failed too fast to capture output.
            # The subsequent grep will try to catch known error patterns.
            nc_test_result="success_or_immediate_fail"
        fi
    fi
    
    if [[ "$nc_test_result" == "timeout_or_error" ]] || \
       echo "$nc_test_result" | grep -qiE 'usage|invalid|unknown option|must be used with|Ncat: Could not resolve hostname'; then
        log_message "WARN" "Netcat (nc) may not support '-l -p -w 1' or test timed out/errored. Restart watcher and some features might not work reliably."
        print_warning "Netcat (nc) may not be fully compatible. Restart watcher might be unreliable."
        print_info "Consider installing 'netcat-openbsd' (Debian/Ubuntu) or 'nmap-ncat' (CentOS/RHEL/Fedora)."
        if command -v ncat &>/dev/null; then
            print_info "Found 'ncat' (from nmap) - this is usually a good alternative if 'nc' is problematic."
        fi
        NC_COMPATIBLE="false" # Global hint for other parts of the script
        return 1
    fi
    log_message "DEBUG" "Netcat compatibility check passed."
    NC_COMPATIBLE="true" # Global hint
    return 0
}

ensure_netcat_installed() {
    if ! command -v nc &>/dev/null; then
        print_warning "Netcat (nc) is not installed. Attempting to install..."
        if command -v apt-get &>/dev/null; then
            run_with_spinner "Installing netcat-openbsd..." apt-get update -y && apt-get install -y netcat-openbsd || \
                handle_critical_error "Failed to install netcat-openbsd. Please install it manually."
        elif command -v yum &>/dev/null; then
            run_with_spinner "Installing nmap-ncat..." yum install -y nmap-ncat || \
                handle_critical_error "Failed to install nmap-ncat. Please install it manually."
        elif command -v dnf &>/dev/null; then
            run_with_spinner "Installing nmap-ncat..." dnf install -y nmap-ncat || \
                handle_critical_error "Failed to install nmap-ncat. Please install it manually."
        else
            handle_critical_error "Unsupported package manager. Please install netcat (preferably OpenBSD or Nmap version) manually."
        fi
        
        if ! command -v nc &>/dev/null; then # Re-check
             handle_critical_error "Netcat installation appears to have failed. Please install it manually."
        fi
        print_success "Netcat installed successfully."
    fi
    check_nc_compatibility # Always check compatibility after ensuring it's installed
}

check_basic_connectivity() {
    local test_hosts=("8.8.8.8" "1.1.1.1" "github.com")
    local success_count=0

    print_info "Testing basic network connectivity..."

    for host_to_test in "${test_hosts[@]}"; do
        if ping -c 1 -W 2 "$host_to_test" >/dev/null 2>&1; then
            log_message "DEBUG" "Successfully pinged $host_to_test."
            ((success_count++))
        else
            log_message "WARN" "Failed to ping $host_to_test."
        fi
    done
    
    if (( success_count > 0 )); then
        print_success "Network connectivity: OK ($success_count/${#test_hosts[@]} hosts reachable)"
        return 0
    else
        print_error "Network connectivity: FAILED (no test hosts reachable)"
        return 1
    fi
}

# --- System Resource Utilities ---
get_system_resources_summary() {
    local cpu_usage mem_usage disk_usage
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}' | cut -d. -f1)
    mem_usage=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100.0}')
    disk_usage=$(df -P / | awk 'NR==2 {print $5}' | sed 's/%//') # Added -P for POSIX output
    
    echo "CPU: ${cpu_usage}% | Memory: ${mem_usage}% | Disk: ${disk_usage}%"
}

display_system_resources() {
    print_info "--- System Resources ---"
    local cpu_usage mem_usage disk_usage
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}' | cut -d. -f1)
    mem_usage=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100.0}')
    disk_usage=$(df -P / | awk 'NR==2 {print $5}' | sed 's/%//')
    
    echo "  CPU Usage: ${cpu_usage}%"
    echo "  Memory Usage: ${mem_usage}%"
    echo "  Root Disk Usage: ${disk_usage}%"
    
    if (( cpu_usage > 85 )); then print_warning "  High CPU usage detected!"; fi
    if (( mem_usage > 85 )); then print_warning "  High memory usage detected!"; fi
    if (( disk_usage > 90 )); then print_warning "  High disk usage detected!"; fi
}

# --- Performance Tracking Utilities ---
with_performance_tracking() {
    local operation_description="$1"
    shift
    local command_to_run=("$@")

    local start_time end_time duration_secs
    start_time=$(date +%s%N)
    
    "${command_to_run[@]}"
    local exit_code=$?
    
    end_time=$(date +%s%N)
    local duration_nanos=$((end_time - start_time))
    duration_secs=$(awk "BEGIN {printf \"%.3f\", $duration_nanos / 1000000000}")

    local success_status="false"
    if [[ $exit_code -eq 0 ]]; then
        success_status="true"
    fi

    if [[ -n "$PERFORMANCE_LOG_FILE" ]]; then
        local perf_log_entry
        if [[ "${LOG_FORMAT:-text}" == "json" ]]; then
            perf_log_entry="{\"timestamp\":\"$(date '+%Y-%m-%d %H:%M:%S')\",\"operation\":\"$operation_description\",\"duration_seconds\":$duration_secs,\"success\":$success_status,\"exit_code\":$exit_code}"
        else
            perf_log_entry="[$(date '+%Y-%m-%d %H:%M:%S')] [PERF] Operation: \"$operation_description\", Duration: ${duration_secs}s, Success: $success_status, ExitCode: $exit_code"
        fi
        echo "$perf_log_entry" >> "$PERFORMANCE_LOG_FILE"
    fi
    
    if (( $(echo "$duration_secs > 30" | bc -l 2>/dev/null || echo 0) )); then
        log_message "WARN" "Slow operation: \"$operation_description\" took ${duration_secs}s."
    fi
    
    return $exit_code
}

# --- File and Configuration Utilities ---
ensure_dir() {
    local dir_path="$1"
    local permissions="${2:-750}"
    if [[ ! -d "$dir_path" ]]; then
        mkdir -p "$dir_path" || { handle_critical_error "Failed to create directory: $dir_path"; return 1; }
    fi
    chmod "$permissions" "$dir_path" || { handle_critical_error "Failed to set permissions on directory: $dir_path"; return 1; }
}

secure_delete() {
    local path_to_delete="$1"
    if [[ ! -e "$path_to_delete" ]]; then
        log_message "DEBUG" "Secure delete: Path not found '$path_to_delete'."
        return 0
    fi

    if [[ "${TEMP_FILE_SECURE_DELETE:-false}" == "true" ]] && command -v shred &>/dev/null && [[ -f "$path_to_delete" ]]; then
        shred -u -n 1 "$path_to_delete" 2>/dev/null || rm -f "$path_to_delete" # shred once
        log_message "DEBUG" "Securely deleted file: $path_to_delete"
    elif [[ -d "$path_to_delete" ]]; then
        rm -rf "$path_to_delete"
        log_message "DEBUG" "Recursively deleted directory: $path_to_delete"
    else
        rm -f "$path_to_delete"
        log_message "DEBUG" "Deleted file: $path_to_delete"
    fi
}

set_secure_file_permissions() {
    local file_path="$1"
    local permissions="${2:-600}"
    if [[ -f "$file_path" ]]; then
        chmod "$permissions" "$file_path" || log_message "WARN" "Failed to set permissions $permissions on $file_path"
        if [[ "$(id -u)" -eq 0 ]]; then
            chown root:root "$file_path" 2>/dev/null || true
        fi
    else
        log_message "WARN" "Set secure permissions: File not found '$file_path'."
    fi
}

update_toml_value() {
    local config_file="$1"
    local key="$2"
    local value="$3"
    local data_type="${4:-string}"

    if [[ ! -f "$config_file" ]]; then
        log_message "ERROR" "Config file not found for update: $config_file"
        return 1
    fi

    if ! acquire_file_lock "$config_file"; then
        handle_error "WARNING" "Could not update $config_file due to lock timeout."
        return 1
    fi
    # Ensure lock is released even on error within this function
    trap 'release_file_lock "$config_file"; trap - EXIT HUP INT QUIT TERM' EXIT HUP INT QUIT TERM


    if [[ "${CONFIG_BACKUP_ON_CHANGE:-true}" == "true" ]]; then
        local backup_base_dir="${BACKUP_DIR:-/etc/easybackhaul/backup}"
        ensure_dir "$backup_base_dir" "700"
        local backup_file="$backup_base_dir/$(basename "$config_file").$(date +%Y%m%d-%H%M%S).bak"
        cp "$config_file" "$backup_file" 2>/dev/null && \
            log_message "DEBUG" "Config backup created: $backup_file" || \
            log_message "WARN" "Failed to create config backup for $config_file"
    fi
    
    local temp_file
    temp_file=$(mktemp)
    
    local updated=false
    # Regex to match key, allowing for spaces and comments after value
    # Handles: key = "value", key="value", key = value, key=value #comment
    local key_regex="^[[:space:]]*${key}[[:space:]]*=[[:space:]]*"

    while IFS= read -r line || [[ -n "$line" ]]; do
        if echo "$line" | grep -qE "$key_regex"; then
            local comment_part=""
            if echo "$line" | grep -q "#"; then
                comment_part=" #"$(echo "$line" | sed 's/.*#//')
            fi
            case "$data_type" in
                "numeric") echo "${key} = ${value}${comment_part}" >> "$temp_file" ;;
                "boolean") echo "${key} = ${value}${comment_part}" >> "$temp_file" ;;
                "string"|*) echo "${key} = \"${value}\"${comment_part}" >> "$temp_file" ;;
            esac
            updated=true
        else
            echo "$line" >> "$temp_file"
        fi
    done < "$config_file"

    if ! $updated; then
        case "$data_type" in
            "numeric") echo "${key} = ${value}" >> "$temp_file" ;;
            "boolean") echo "${key} = ${value}" >> "$temp_file" ;;
            "string"|*) echo "${key} = \"${value}\"" >> "$temp_file" ;;
        esac
    fi
    
    if mv "$temp_file" "$config_file"; then
        set_secure_file_permissions "$config_file" "600"
        log_message "INFO" "Updated key '$key' in $config_file."
        release_file_lock "$config_file"
        trap - EXIT HUP INT QUIT TERM
        return 0
    else
        log_message "ERROR" "Failed to move temp file to $config_file."
        rm -f "$temp_file" # Clean up temp file on failure
        release_file_lock "$config_file"
        trap - EXIT HUP INT QUIT TERM
        return 1
    fi
}

backup_configuration_path() {
    local path_to_backup="$1"
    local backup_desc="${2:-configuration}"

    if [[ ! -e "$path_to_backup" ]]; then
        log_message "WARN" "Backup source not found: $path_to_backup"
        return 1
    fi

    local backup_base_dir="${BACKUP_DIR:-/etc/easybackhaul/backup}"
    ensure_dir "$backup_base_dir" "700"
    
    local backup_filename
    backup_filename="$(basename "$path_to_backup")-$(date +%Y%m%d-%H%M%S).bak"
    local backup_target_path="$backup_base_dir/$backup_filename"

    if [[ -d "$path_to_backup" ]]; then
        backup_target_path+=".tar.gz"
        if tar -czf "$backup_target_path" -C "$(dirname "$path_to_backup")" "$(basename "$path_to_backup")"; then
            log_message "INFO" "$backup_desc backup created: $backup_target_path"
            set_secure_file_permissions "$backup_target_path" "600"
            return 0
        else
            log_message "ERROR" "Failed to create directory backup for $path_to_backup"
            return 1
        fi
    elif [[ -f "$path_to_backup" ]]; then
        if cp "$path_to_backup" "$backup_target_path"; then
            log_message "INFO" "$backup_desc backup created: $backup_target_path"
            set_secure_file_permissions "$backup_target_path" "600"
            return 0
        else
            log_message "ERROR" "Failed to create file backup for $path_to_backup"
            return 1
        fi
    fi
}

acquire_file_lock() {
    local file_to_lock="$1"
    local lock_file_path="${file_to_lock}.lock"
    local timeout_seconds="${2:-10}"
    local current_pid=$$
    
    local attempt_start_time
    attempt_start_time=$(date +%s)

    while true; do
        if (set -o noclobber; echo "$current_pid" > "$lock_file_path") 2>/dev/null; then
            return 0
        fi

        if [[ -f "$lock_file_path" ]]; then
            local lock_owner_pid
            lock_owner_pid=$(cat "$lock_file_path" 2>/dev/null)
            if [[ -n "$lock_owner_pid" ]] && ! ps -p "$lock_owner_pid" > /dev/null 2>&1; then
                log_message "WARN" "Stale lock file found for '$file_to_lock' (PID $lock_owner_pid). Removing."
                rm -f "$lock_file_path"
                continue
            fi
        fi
        
        local current_time
        current_time=$(date +%s)
        if (( (current_time - attempt_start_time) >= timeout_seconds )); then
            log_message "ERROR" "Timeout acquiring lock for '$file_to_lock' after ${timeout_seconds}s. Locked by PID: $(cat "$lock_file_path" 2>/dev/null || echo 'unknown')."
            return 1
        fi
        
        sleep 0.5
    done
}

release_file_lock() {
    local file_to_unlock="$1"
    local lock_file_path="${file_to_unlock}.lock"
    local current_pid=$$

    if [[ -f "$lock_file_path" ]]; then
        local lock_owner_pid
        lock_owner_pid=$(cat "$lock_file_path" 2>/dev/null)
        if [[ "$lock_owner_pid" == "$current_pid" ]] || [[ -z "$lock_owner_pid" ]]; then
            rm -f "$lock_file_path"
        else
            log_message "WARN" "Attempted to release lock for '$file_to_unlock' not owned by current process (Owner: $lock_owner_pid, Current: $current_pid)."
        fi
    fi
}

# --- User Interaction & Menu System ---
MENU_STACK=()
CURRENT_MENU_FUNCTION=""

_push_menu_stack() {
    local menu_function_name="$1"
    MENU_STACK+=("$menu_function_name")
    CURRENT_MENU_FUNCTION="$menu_function_name"
    log_message "DEBUG" "Pushed to menu stack: ${MENU_STACK[*]}. Current: $CURRENT_MENU_FUNCTION"
}

_pop_menu_stack() {
    if [[ ${#MENU_STACK[@]} -eq 0 ]]; then
        log_message "WARN" "Menu stack underflow attempt."
        CURRENT_MENU_FUNCTION=""
        return
    fi
    
    unset 'MENU_STACK[${#MENU_STACK[@]}-1]'
    if [[ ${#MENU_STACK[@]} -gt 0 ]]; then
        CURRENT_MENU_FUNCTION="${MENU_STACK[${#MENU_STACK[@]}-1]}"
    else
        CURRENT_MENU_FUNCTION=""
    fi
    log_message "DEBUG" "Popped from menu stack. Current: $CURRENT_MENU_FUNCTION. Stack: ${MENU_STACK[*]}"
}

navigate_to_menu() {
    local target_menu_function="$1"
    log_message "DEBUG" "Navigating from '$CURRENT_MENU_FUNCTION' to '$target_menu_function'"
    _push_menu_stack "$target_menu_function"
    # Calling function should 'return 0' to allow main loop to pick up new CURRENT_MENU_FUNCTION
}

return_from_menu() {
    log_message "DEBUG" "Requesting return from menu '$CURRENT_MENU_FUNCTION'"
    _pop_menu_stack
    # Calling function should 'return 0' to allow main loop to pick up new CURRENT_MENU_FUNCTION (previous one)
    # or to exit if stack becomes empty.
}

go_to_main_menu() {
    log_message "DEBUG" "Requesting jump to main menu from '$CURRENT_MENU_FUNCTION'"
    MENU_STACK=("main_menu_entry") # Assuming 'main_menu_entry' is the name of the main menu function
    CURRENT_MENU_FUNCTION="main_menu_entry"
    # Calling function should 'return 0'
}

request_script_exit() {
    log_message "INFO" "Script exit requested from '$CURRENT_MENU_FUNCTION'."
    MENU_STACK=()
    CURRENT_MENU_FUNCTION=""
    # Calling function should 'return 0', main loop will see empty CURRENT_MENU_FUNCTION and exit.
}

# Unified menu header printing
# Usage: print_menu_header "TYPE (primary/secondary)" "Title" ["Subtitle/Service Details" "Status (for secondary)"]
print_menu_header() {
    clear # Ensure screen is always cleared first
    local type="$1"
    local title="$2"
    local detail1="${3:-}"
    local detail2="${4:-}"

    # Use global SCRIPT_VERSION or fallback
    local version_string="${SCRIPT_VERSION:-v14.0-dev}"

    if [[ "$type" == "primary" ]]; then
        echo
        echo "      EasyBackhaul Management Menu ($version_string)"
        echo "================================================================="
        echo "  Core by Musixal  |  Installer by @N4Xon"
        echo "-----------------------------------------------------------------"
        if [[ -n "${SERVER_IP:-N/A}" && "${SERVER_IP:-N/A}" != "N/A" ]]; then
            echo "📍 Server: ${SERVER_IP} | 🌍 ${SERVER_COUNTRY:-N/A} | 🏢 ${SERVER_ISP:-N/A}"
        fi
        echo
        print_info "      $title"
        if [[ -n "$detail1" ]]; then # Subtitle for primary header
             print_info "================================================================"
             print_info "  $detail1"
        fi
        print_info "================================================================"
    else # secondary type
        if [[ -n "${SERVER_IP:-N/A}" && "${SERVER_IP:-N/A}" != "N/A" ]]; then
            echo "📍 ${SERVER_IP} | 🌍 ${SERVER_COUNTRY:-N/A}" # Minimal server info
        fi
        echo
        print_info "--- $title ---"
        if [[ -n "$detail1" ]]; then print_info "Context: $detail1"; fi # Context/Service for secondary
        if [[ -n "$detail2" ]]; then print_info "Status: $detail2"; fi   # Status for secondary
    fi
    # Standardized tip line, will be part of print_menu_footer now.
    # print_info "Tip: Press '?' for help, 'm' for Main Menu, 'x' to Exit."
    echo
}

# Helper function to prompt for a port with validation and optional availability check
# Usage: prompt_for_port "Description for port" "default_port" true port_variable_name
# Returns: 0 on success, 1 on failure/cancel (e.g., user enters 'c' if read supported it, or empty + no to retry)
prompt_for_port() {
    local desc="$1"
    local default_val="$2"
    local check_avail="$3" # true or false
    local -n port_ref=$4   # Nameref for the output variable

    local input_val
    while true; do
        read -r -p "Enter $desc (e.g., 443, 8080) [${default_val}]: " input_val
        input_val=${input_val:-$default_val}

        # Allow 'c' or 'cancel' to break out, though read doesn't have built-in cancel for this.
        # This is more a conceptual cancel for the user if they just hit enter on an empty prompt
        # or if we enhance read with a timeout or specific cancel key handling in future.
        # For now, an empty input (after default is applied or not) will be caught by validate_port.
        # A more robust cancel would require changes to how `read` is used or a different input loop.

        if ! validate_port "$input_val"; then
            print_warning "Invalid port number. Must be 1-65535."
            if ! prompt_yes_no "Try again?" "y"; then port_ref=""; return 1; fi
            continue
        fi

        if [[ "$check_avail" == "true" ]]; then
            if ! check_port_availability "$input_val"; then
                print_warning "Port $input_val is currently in use on this server."
                _get_port_process_info "$input_val" # Assumes _get_port_process_info is available if needed
                if ! prompt_yes_no "Use this port anyway (if the process is temporary or will be stopped)?" "n"; then
                    if ! prompt_yes_no "Try a different port?" "y"; then port_ref=""; return 1; fi
                    continue
                fi
            else
                print_success "Port $input_val is available."
            fi
        fi
        port_ref="$input_val"
        return 0
    done
}

# Helper function to prompt for an IP address with validation and optional ping
# Usage: prompt_for_ip "Description for IP" "default_ip_optional" true ip_variable_name
# Returns: 0 on success, 1 on failure/cancel
prompt_for_ip() {
    local desc="$1"
    local default_val="$2" # Can be empty
    local do_ping="$3"     # true or false
    local -n ip_ref=$4     # Nameref for the output variable

    local input_val
    while true; do
        local prompt_str="Enter $desc"
        if [[ -n "$default_val" ]]; then
            prompt_str+=" [${default_val}]"
        fi
        prompt_str+=": "
        read -r -p "$prompt_str" input_val
        input_val=${input_val:-$default_val}

        if [[ -z "$input_val" ]]; then # Handle case where default is empty and user enters nothing
            print_warning "IP address cannot be empty."
            if ! prompt_yes_no "Try again?" "y"; then ip_ref=""; return 1; fi
            continue
        fi

        if ! validate_ip "$input_val"; then
            print_warning "Invalid IP address format."
            if ! prompt_yes_no "Try again?" "y"; then ip_ref=""; return 1; fi
            continue
        fi

        if [[ "$do_ping" == "true" ]]; then
            if prompt_yes_no "Ping $input_val to check reachability?" "y"; then
                run_with_spinner "Pinging $input_val..." ping -c 2 -W 2 "$input_val"
                # We don't fail based on ping result, just inform user.
            fi
        fi
        ip_ref="$input_val"
        return 0
    done
}


# Unified menu footer printing
print_menu_footer() {
    echo "----------------------------------------------------------------"
    echo " [?] Help | [c] Cancel Op | [r] Return/Back | [m] Main Menu | [x] Exit Script"
}

prompt_yes_no() {
    local prompt_message="$1"
    local default_answer="${2:-n}"

    local yn_prompt
    if [[ "$default_answer" == "y" ]]; then
        yn_prompt="[Y/n]"
    else
        yn_prompt="[y/N]"
    fi

    while true; do
        read -r -p "$prompt_message $yn_prompt: " user_input
        user_input=$(echo "${user_input:-$default_answer}" | tr '[:upper:]' '[:lower:]')

        case "$user_input" in
            y|yes) return 0 ;;
            n|no) return 1 ;;
            *) print_warning "Invalid input. Please enter 'y' or 'n'." ;;
        esac
    done
}

MENU_CHOICE="" # Global variable to store the result of menu_loop

# Standardized menu loop.
# Usage: menu_loop "Prompt Message" "options_array_name" ["custom_help_function_name"]
#   options_array: ("1. Option A" "2. Option B") - These are the numbered options.
# Sets MENU_CHOICE to the selected number (as a string) or one of the navigation characters.
# Returns:
#   0: Valid NUMERIC choice from options_ref was made. MENU_CHOICE holds the number.
#   2: '?' (Help) was pressed. MENU_CHOICE holds '?'.
#   3: 'm' (Main Menu) was pressed. MENU_CHOICE holds 'm'.
#   4: 'x' (Exit Script) was pressed. MENU_CHOICE holds 'x'.
#   5: 'r' (Return/Back) was pressed. MENU_CHOICE holds 'r'.
#   6: 'c' (Cancel Operation) was pressed. MENU_CHOICE holds 'c'.
#   Any other non-zero return indicates an issue, though the loop should prevent this.
menu_loop() {
    local prompt_msg="$1"
    local -n options_ref=$2 # Array of menu options like "1. Do X"
    # Third argument is now custom_help_function_name, removed exit_option_details_ref
    local custom_help_function_name="${3:-}"

    local min_numeric_opt=1
    local max_numeric_opt=${#options_ref[@]}
    
    # Construct the choice part of the prompt string for NUMERIC options
    local prompt_numeric_choices_str=""
    if (( max_numeric_opt > 0 )); then
        if (( max_numeric_opt == 1 )); then
            prompt_numeric_choices_str="1"
        else
            prompt_numeric_choices_str="${min_numeric_opt}-${max_numeric_opt}"
        fi
    fi
    
    while true; do
        # Display options from the array
        for opt_str in "${options_ref[@]}"; do
            echo "  $opt_str"
        done

        # Display the standardized footer (which now contains all nav keys)
        print_menu_footer # No argument needed anymore

        # Build the prompt string
        local full_prompt_str="$prompt_msg"
        local available_choices_display=""
        if [[ -n "$prompt_numeric_choices_str" ]]; then
            available_choices_display="$prompt_numeric_choices_str, "
        fi
        # Add standardized navigation keys to the prompt display
        available_choices_display+="?, c, r, m, x" # Standard nav keys

        full_prompt_str+=" [${available_choices_display}]: "

        read -r -p "$full_prompt_str" raw_choice
        MENU_CHOICE=$(echo "$raw_choice" | tr '[:upper:]' '[:lower:]') # Normalize to lowercase

        case "$MENU_CHOICE" in
            '?')
                if [[ -n "$custom_help_function_name" ]] && type "$custom_help_function_name" &>/dev/null; then
                    "$custom_help_function_name"
                else
                    print_info "No specific help available for this menu."
                fi
                press_any_key # Always press_any_key after help
                return 2 # Help shown
                ;;
            'm') return 3 ;; # Request Main Menu
            'x') return 4 ;; # Request Exit Script (changed from 'e')
            'r') return 5 ;; # Request Return/Back
            'c') return 6 ;; # Request Cancel Operation
        esac

        # Check if choice is a number within the options range
        if [[ "$MENU_CHOICE" =~ ^[0-9]+$ ]]; then
            if (( max_numeric_opt == 0 )); then # No numbered options defined
                 print_warning "Invalid option: '$MENU_CHOICE'. No numeric options available. Use navigation keys."
            elif (( MENU_CHOICE >= min_numeric_opt && MENU_CHOICE <= max_numeric_opt )); then
                return 0 # Valid numeric option selected
            else
                 print_warning "Invalid numeric option: '$MENU_CHOICE'. Choose from ${prompt_numeric_choices_str} or navigation keys."
            fi
        else
            # Non-numeric input that wasn't a nav key (and not empty)
            if [[ -n "$MENU_CHOICE" ]]; then # Only print warning if input was not empty
                print_warning "Invalid option: '$MENU_CHOICE'. Please try again."
            fi
        fi

        # If input was empty or invalid, press_any_key only if it was not empty and invalid
        if [[ -n "$MENU_CHOICE" ]]; then
             press_any_key
        fi
        # Loop again to re-display menu and prompt
    done
}

# --- Process Management & Cleanup ---
cleanup_stale_processes_and_files() {
    log_message "INFO" "Running cleanup for stale processes and temporary files..."
    local cleaned_items=0

    local zombie_pids
    zombie_pids=$(ps aux | awk '$8=="Z" {print $2}')
    if [[ -n "$zombie_pids" ]]; then
        log_message "WARN" "Found zombie processes: $zombie_pids. Attempting to reap."
        if kill -CHLD 1 2>/dev/null; then
            sleep 1
            local remaining_zombies=$(ps aux | awk '$8=="Z" {print $2}' | wc -l)
            if (( remaining_zombies == 0 )); then
                log_message "INFO" "Zombie processes reaped."
            else
                log_message "WARN" "$remaining_zombies zombie processes may remain."
            fi
        else
             log_message "WARN" "Failed to send SIGCHLD to init. Zombie reaping might not be effective."
        fi
        ((cleaned_items++))
    fi

    if pgrep -f "backhaul-watcher-" > /dev/null; then
        log_message "INFO" "Found orphaned watcher processes by name pattern. Terminating..."
        run_with_spinner "Terminating orphaned watchers..." pkill -f "backhaul-watcher-"
        sleep 1 # Give pkill time
        pkill -9 -f "backhaul-watcher-" 2>/dev/null
        ((cleaned_items++))
    fi

    local temp_patterns=(
        "/tmp/backhaul-*.tmp"
        "/tmp/backhaul-*.pid"
        "/tmp/backhaul-*.log"
        "/tmp/restart_ack_*"
        "/tmp/backhaul-watcher-*.sh"
        "/tmp/backhaul-watcher-*.conf"
        "/tmp/easybackhaul_rate_limit_*.lock"
    )
    log_message "DEBUG" "Checking for stale temporary files..."
    for pattern in "${temp_patterns[@]}"; do
        # Delete files older than 1 day matching the pattern
        find /tmp -name "$(basename "$pattern")" -type f -mtime +1 -print -delete 2>/dev/null && ((cleaned_items++))

        if [[ "$pattern" == *".pid" ]]; then
            find /tmp -name "$(basename "$pattern")" -type f -print0 | while IFS= read -r -d $'\0' pid_file; do
                local pid_val
                pid_val=$(cat "$pid_file" 2>/dev/null)
                if [[ -n "$pid_val" ]] && ! ps -p "$pid_val" > /dev/null 2>&1; then
                    log_message "INFO" "Removing stale PID file $pid_file for dead process $pid_val."
                    rm -f "$pid_file" && ((cleaned_items++))
                fi
            done
        fi
    done
    
    if (( cleaned_items > 0 )); then
        log_message "INFO" "Cleanup completed. Addressed items related to $cleaned_items patterns/checks."
    else
        log_message "INFO" "No stale processes or files found needing immediate cleanup based on current checks."
    fi
}

cleanup_watcher_files() {
    local tunnel_suffix="$1"
    if [[ -z "$tunnel_suffix" ]]; then
        log_message "ERROR" "cleanup_watcher_files: Tunnel suffix is required."
        return 1
    fi

    log_message "INFO" "Cleaning up watcher files for tunnel: $tunnel_suffix"
    
    local watcher_script_path="/tmp/backhaul-watcher-${tunnel_suffix}.sh"
    local watcher_pid_file_path="/tmp/backhaul-watcher-${tunnel_suffix}.pid"
    local watcher_log_file_path="/tmp/backhaul-watcher-${tunnel_suffix}.log"
    local watcher_conf_file_path="/tmp/backhaul-watcher-${tunnel_suffix}.conf"
    # Assuming service name follows a pattern like backhaul-<suffix>.service
    local restart_ack_file_path="/tmp/restart_ack_backhaul-${tunnel_suffix}.service"

    if [[ -f "$watcher_pid_file_path" ]]; then
        local watcher_pid_val
        watcher_pid_val=$(cat "$watcher_pid_file_path" 2>/dev/null)
        if [[ -n "$watcher_pid_val" ]] && ps -p "$watcher_pid_val" > /dev/null 2>&1; then
            log_message "INFO" "Stopping watcher process PID $watcher_pid_val for tunnel $tunnel_suffix."
            kill "$watcher_pid_val" 2>/dev/null
            sleep 0.5
            kill -9 "$watcher_pid_val" 2>/dev/null
        fi
    fi
    
    rm -f "$watcher_script_path" "$watcher_pid_file_path" "$watcher_log_file_path" "$watcher_conf_file_path" "$restart_ack_file_path"
    
    # General pkill for the specific watcher script pattern, just in case
    pkill -f "backhaul-watcher-${tunnel_suffix}.sh" 2>/dev/null

    log_message "INFO" "Watcher files cleanup for tunnel '$tunnel_suffix' complete."
}

# --- Spinner Utility ---
run_with_spinner() {
    local description="$1"
    shift
    local command_to_run=("$@")
    local spin_chars="|/-\\"
    local log_file="/tmp/spinner_$(date +%s%N).log" # Unique log file for each spinner run
    
    echo -n "$description "
    # Redirect stdout and stderr of the command to the log file
    "${command_to_run[@]}" > "$log_file" 2>&1 &
    local pid=$!
    
    local i=0
    local original_trap_INT
    original_trap_INT=$(trap -p INT) # Save original INT trap

    # Local trap for Ctrl+C during spinner
    trap '_spinner_ctrl_c "$pid" "$log_file"; return 130' INT

    while ps -p $pid > /dev/null 2>&1; do
        printf "\b%s" "${spin_chars:i++%${#spin_chars}:1}"
        sleep 0.1
    done
    printf "\b" # Clear spinner char
    
    # Restore original INT trap
    eval "$original_trap_INT" 2>/dev/null || trap - INT

    wait $pid
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        print_success "Done."
        rm -f "$log_file"
    elif [[ $exit_code -eq 130 ]]; then # Interrupted by our trap
        # Message already printed by _spinner_ctrl_c
        :
    else
        print_error "Failed. (Exit code: $exit_code)"
        print_info "Details logged to: $log_file"
    fi
    return $exit_code
}

# Helper for run_with_spinner's Ctrl+C trap
_spinner_ctrl_c() {
    local child_pid="$1"
    local log_f="$2"
    printf "\b" # Clear spinner character
    print_warning "\nOperation interrupted by user (Ctrl+C)."
    log_message "WARN" "Spinner operation interrupted by user for PID $child_pid."
    # Attempt to kill the child process
    if [[ -n "$child_pid" ]] && ps -p "$child_pid" > /dev/null 2>&1; then
        kill "$child_pid" 2>/dev/null && sleep 0.2 && kill -9 "$child_pid" 2>/dev/null
    fi
    if [[ -f "$log_f" ]]; then
        print_info "Partial logs (if any) at: $log_f"
    fi
    # The main run_with_spinner function will return 130
}

# --- Miscellaneous Utilities ---
generate_random_secret() {
    local length="${1:-32}"
    if command -v openssl &>/dev/null; then
        openssl rand -hex $((length / 2))
    else
        tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "$length"
    fi
}

generate_self_signed_tls_cert() {
    local cert_common_name="${1:-${SERVER_IP:-localhost}}"
    local cert_dir="${CERT_DIR:-/etc/easybackhaul/certs}"
    ensure_dir "$cert_dir" "700"

    print_menu_header "secondary" "TLS Certificate Generation"
    
    if ! command -v openssl &>/dev/null; then
        handle_critical_error "OpenSSL is not installed. Please install it to generate certificates."
        press_any_key
        return 1
    fi

    local country_code state_name locality_name org_name final_cn
    read -r -p "Country (2 letter code, e.g., US) [US]: " country_code
    country_code=${country_code:-US}
    read -r -p "State or Province (e.g., California) [State]: " state_name
    state_name=${state_name:-State}
    read -r -p "Locality/City (e.g., San Francisco) [City]: " locality_name
    locality_name=${locality_name:-City}
    read -r -p "Organization Name (e.g., My Company) [MyOrg]: " org_name
    org_name=${org_name:-MyOrg}
    read -r -p "Common Name (domain or IP, e.g., $cert_common_name) [$cert_common_name]: " final_cn
    final_cn="${final_cn:-$cert_common_name}"

    local timestamp
    timestamp=$(date +%Y%m%d-%H%M%S)
    local key_path="$cert_dir/privkey-$timestamp.pem"
    local cert_path="$cert_dir/fullchain-$timestamp.pem"
    local subject_line="/C=$country_code/ST=$state_name/L=$locality_name/O=$org_name/CN=$final_cn"

    print_info "Generating private key: $key_path"
    if ! run_with_spinner "Generating private key..." openssl genpkey -algorithm RSA -out "$key_path" -pkeyopt rsa_keygen_bits:2048; then
        handle_error "ERROR" "OpenSSL private key generation failed. Check spinner log for details."
        press_any_key; return 1
    fi
    set_secure_file_permissions "$key_path" "600"

    print_info "Generating self-signed certificate: $cert_path"
    if ! run_with_spinner "Generating certificate..." openssl req -new -x509 -key "$key_path" -out "$cert_path" -days 365 -subj "$subject_line"; then
        handle_error "ERROR" "OpenSSL certificate generation failed. Check spinner log for details."
        rm -f "$key_path"
        press_any_key; return 1
    fi
    set_secure_file_permissions "$cert_path" "644"

    print_success "TLS Certificate and Key generated successfully!"
    echo "  Private Key: $key_path"
    echo "  Certificate: $cert_path"
    print_info "These paths can be used in your tunnel configurations for WSS/WSSMUX."
    press_any_key
    return 0
}

show_main_application_help() {
    print_menu_header "primary" "EasyBackhaul Help"

    echo "EasyBackhaul is a script to simplify the installation, configuration,"
    echo "and management of Backhaul tunnels."
    echo
    print_info "Core Features:"
    echo "  - Automated Backhaul binary download and installation."
    echo "  - Guided tunnel configuration wizard (server and client modes)."
    echo "  - Support for various transport protocols (TCP, UDP, WS, WSS, MUX variants)."
    echo "  - Systemd service management for tunnels."
    echo "  - UFW firewall rule management (optional)."
    echo "  - Restart watcher for improved tunnel reliability (optional)."
    echo "  - TLS certificate generation for secure protocols."
    echo "  - Health monitoring and performance logging."
    echo
    print_info "Main Menu Options Guide:"
    echo "  1. Configure New Tunnel: Step-by-step setup for new tunnels."
    echo "  2. Manage Existing Tunnels: Control (start/stop/restart), view logs,"
    echo "     edit configurations, and delete existing tunnels."
    echo "  3. Update/Re-install Binary: Get the latest Backhaul binary or reinstall."
    echo "  4. Generate TLS Certificate: Create self-signed certs for WSS/WSSMUX."
    echo "  5. Select Binary Directory: (Advanced) Change where the script looks for 'backhaul'."
    echo "  6. System Health Monitor: Overview of system resources and tunnel status."
    echo "  7. Clean Up Processes: Attempt to clean stale or zombie processes."
    echo "  8. Uninstall EasyBackhaul: Remove the script, binary, configs, and services."
    echo
    print_info "General Tips:"
    echo "  - Always ensure your server's firewall allows traffic on the ports Backhaul uses."
    echo "  - For client tunnels, the 'server' IP in the config is the public IP of your Backhaul server."
    echo "  - The 'auth_token' must match on both client and server sides of a tunnel."
    echo "  - Check logs regularly if you encounter issues."
    echo
    print_info "Resources:"
    echo "  - Backhaul Project: https://github.com/Musixal/Backhaul"
    echo "  - EasyBackhaul Installer Issues: https://github.com/N4Xon/EasyBackhaul" # Assuming this is the repo
    echo
    press_any_key
}

view_system_log() {
    local log_source_type="$1"
    local log_identifier="$2"
    local log_title="${3:-Log Viewer}"

    _view_log_help() { # Local helper function for this menu
        print_info "Log Viewer Help:"
        echo " - Interactive: Scrollable view (use arrows, 'q' to quit 'less')."
        echo " - Live follow: Real-time log updates (Ctrl+C to stop)."
        echo " - Last 100 lines: Quick look at recent activity."
        echo " - Search: Filter logs for a specific term (case-insensitive)."
        press_any_key
    }

    local local_menu_options=(
        "1. Interactive view (less)"
        "2. Live follow (tail -f / journalctl -f)"
        "3. View last 100 lines"
        "4. Search logs (grep -i)"
    )
    # Removed local_exit_options as menu_loop no longer uses numbered exit
    local user_choice
    local menu_return_code

    while true; do
        print_menu_header "secondary" "$log_title" "Source: $log_identifier"
        # Call menu_loop without the exit_option_details_array
        menu_loop "Select log view option" local_menu_options "_view_log_help"
        user_choice="$MENU_CHOICE"
        menu_return_code=$?

        case "$menu_return_code" in
            0) # Numeric choice
                case "$user_choice" in
                    "1")
                        if [[ "$log_source_type" == "journalctl" ]]; then
                            journalctl -u "$log_identifier" --no-pager | less
                        elif [[ -f "$log_identifier" ]]; then
                            less "$log_identifier"
                        else print_error "Log source not found: $log_identifier"; press_any_key; fi
                        ;;
                    "2")
                        print_info "Starting live log follow. Press Ctrl+C to stop."
                        # Add trap for Ctrl+C specific to this operation
                        trap 'print_info "Live log follow interrupted."; trap - INT; return_from_menu; return 130' INT
                        if [[ "$log_source_type" == "journalctl" ]]; then
                            journalctl -u "$log_identifier" -f
                        elif [[ -f "$log_identifier" ]]; then
                            tail -f "$log_identifier"
                        else print_error "Log source not found: $log_identifier"; fi
                        trap - INT # Clear trap
                        print_info "Live log follow stopped."
                        press_any_key
                        ;;
                    "3")
                        if [[ "$log_source_type" == "journalctl" ]]; then
                            journalctl -u "$log_identifier" --no-pager -n 100
                        elif [[ -f "$log_identifier" ]]; then
                            tail -n 100 "$log_identifier"
                        else print_error "Log source not found: $log_identifier"; fi
                        press_any_key
                        ;;
                    "4")
                        read -r -p "Enter search term: " search_term
                        if [[ -n "$search_term" ]]; then
                            print_info "Searching for '$search_term' (last 200 matching lines)..."
                            if [[ "$log_source_type" == "journalctl" ]]; then
                                journalctl -u "$log_identifier" --no-pager | grep -i "$search_term" | tail -n 200
                            elif [[ -f "$log_identifier" ]]; then
                                grep -i "$search_term" "$log_identifier" | tail -n 200
                            else print_error "Log source not found: $log_identifier"; fi
                            press_any_key
                        fi
                        ;;
                esac
                ;;
            2) # Help shown, menu_loop already handled press_any_key
                continue ;;
            3) go_to_main_menu; return ;;
            4) request_script_exit; return ;;
            5) return_from_menu; return ;; # 'r' Return/Back
            6) return_from_menu; return ;; # 'c' Cancel (acts like 'r' here)
            *) print_warning "Invalid option from log viewer menu_loop."; press_any_key ;;
        esac
    done
}

# --- Advanced Error Recovery & Retry ---
# Retry mechanism with exponential backoff
retry_operation() {
    local operation_desc="$1" # For logging
    local max_retries="${2:-3}"
    local base_delay_seconds="${3:-2}"
    local operation_function_name="$4"
    shift 4 # Remaining args are for the operation_function_name
    
    local retry_count=0
    local current_delay=$base_delay_seconds
    
    while (( retry_count < max_retries )); do
        log_message "INFO" "Attempting operation: '$operation_desc' (Attempt $((retry_count + 1))/$max_retries)"
        if "$operation_function_name" "$@"; then
            log_message "INFO" "Operation '$operation_desc' succeeded."
            return 0 # Success
        fi

        ((retry_count++))

        if (( retry_count < max_retries )); then
            log_message "WARN" "Operation '$operation_desc' failed. Retrying in $current_delay seconds..."
            sleep "$current_delay"
            current_delay=$((current_delay * 2)) # Exponential backoff
        fi
    done
    
    log_message "ERROR" "Operation '$operation_desc' failed after $max_retries attempts."
    return 1 # Failure
}

# Attempt to recover from common error scenarios
attempt_generic_error_recovery() {
    local failed_operation_desc="$1"
    local error_details="$2" # e.g., service name, file path
    local recovery_attempt_count="${3:-0}"

    log_message "INFO" "Attempting recovery for '$failed_operation_desc' (Details: $error_details, Attempt: $((recovery_attempt_count + 1)))"

    # Example recovery strategies (can be expanded)
    case "$failed_operation_desc" in
        "start_service")
            # Try cleaning up potential conflicting state then restart
            if [[ -n "$error_details" ]]; then # error_details is service name
                cleanup_watcher_files "$error_details" # Clean related watcher state
                log_message "INFO" "Ensuring service $error_details is stopped before retry..."
                systemctl stop "$error_details" 2>/dev/null
                sleep 2
                log_message "INFO" "Retrying start for service $error_details..."
                if systemctl start "$error_details"; then
                    log_message "INFO" "Service $error_details recovered and started."
                    return 0
                fi
            fi
            ;;
        "download_file")
            # Try checking connectivity, or suggest alternative if context allows
            log_message "INFO" "Checking basic connectivity before retrying download..."
            if check_basic_connectivity; then
                log_message "INFO" "Connectivity seems OK. The issue might be with the specific download source for '$error_details'."
                # Specific retry for download might be handled by the download function itself
            else
                log_message "ERROR" "Basic connectivity check failed. Cannot retry download now."
            fi
            ;;
        "update_config")
            # Try restoring from the most recent backup if available
            if [[ -n "$error_details" ]]; then # error_details is tunnel name or config path
                local config_to_restore="$CONFIG_DIR/config-${error_details}.toml" # Assuming tunnel name
                if [[ ! -f "$config_to_restore" ]]; then config_to_restore="$error_details"; fi # Assuming full path

                local backup_file_path
                backup_file_path=$(find "$BACKUP_DIR" -name "$(basename "$config_to_restore").*.bak" -type f | sort -r | head -n 1)

                if [[ -f "$backup_file_path" ]]; then
                    log_message "INFO" "Attempting to restore '$config_to_restore' from backup: $backup_file_path"
                    if cp "$backup_file_path" "$config_to_restore"; then
                        set_secure_file_permissions "$config_to_restore"
                        log_message "INFO" "Config '$config_to_restore' restored from backup. Service may need restart."
                        return 0
                    else
                        log_message "ERROR" "Failed to restore '$config_to_restore' from backup '$backup_file_path'."
                    fi
                else
                    log_message "WARN" "No backup found to restore for '$config_to_restore'."
                fi
            fi
            ;;
        *)
            log_message "WARN" "No specific recovery strategy for '$failed_operation_desc'. Generic wait and retry might be applicable elsewhere."
            # Generic recovery: just wait a bit, usually handled by retry_operation
            sleep $((recovery_attempt_count + 2)) # Wait a bit longer for generic cases
            return 0 # Signify that a generic attempt (like waiting) was made
            ;;
    esac
    
    log_message "ERROR" "Recovery attempt for '$failed_operation_desc' failed."
    return 1
}

# --- Prerequisite Checks ---
# (Moved from prereqs.sh)
# Checks for essential command-line tool dependencies and attempts to install them.
check_dependencies() {
    log_message "INFO" "Checking for required dependencies..."
    # Define core dependencies and their typical package names
    # This map helps manage cases where cmd name != package name (like ss -> iproute2)
    declare -A deps_map=(
        ["curl"]="curl"
        ["wget"]="wget"
        ["tar"]="tar"
        ["jq"]="jq"
        ["nc"]="netcat-openbsd" # Preferred nc, nmap-ncat is fallback
        ["ss"]="iproute2"
        ["systemctl"]="systemd" # Though systemctl itself isn't a package, 'systemd' is.
        ["journalctl"]="systemd-journal-remote" # Often part of systemd itself or a sub-package
        ["logrotate"]="logrotate"
        ["openssl"]="openssl"
        ["ping"]="iputils-ping" # For Debian/Ubuntu; 'iputils' on CentOS/RHEL
    )
    # Packages that might provide 'nc' if netcat-openbsd fails or isn't primary
    declare -A nc_fallback_pkgs=(
        ["nmap-ncat"]="nmap-ncat" # For yum/dnf
        ["netcat-traditional"]="netcat-traditional" # Another option on Debian
    )

    local missing_cmds=()
    local packages_to_install=()

    for cmd in "${!deps_map[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            log_message "WARN" "Dependency '$cmd' not found."
            missing_cmds+=("$cmd")
            # Add the primary package name for this command
            packages_to_install+=("${deps_map[$cmd]}")
        fi
    done

    if [[ ${#missing_cmds[@]} -gt 0 ]]; then
        print_warning "The following dependencies are missing or not in PATH: ${missing_cmds[*]}."
        # Deduplicate packages_to_install before proceeding
        local unique_packages_to_install=($(printf "%s\n" "${packages_to_install[@]}" | sort -u | tr '\n' ' '))

        print_info "Attempting to install packages: ${unique_packages_to_install[*]}"

        if command -v apt-get &>/dev/null; then
            run_with_spinner "Updating package lists (apt)..." sudo apt-get update -y
            # Attempt to install primary packages
            if ! run_with_spinner "Installing dependencies (apt)..." sudo apt-get install -y --no-install-recommends "${unique_packages_to_install[@]}"; then
                handle_error "ERROR" "Some dependencies failed to install via apt. Please try manually."
                # Try nc fallbacks if nc was missing and netcat-openbsd failed
                if [[ " ${missing_cmds[*]} " =~ " nc " ]] && ! command -v nc &>/dev/null; then
                    log_message "INFO" "Attempting nc fallback installation (apt)..."
                    sudo apt-get install -y --no-install-recommends "${nc_fallback_pkgs[nmap-ncat]}" || \
                    sudo apt-get install -y --no-install-recommends "${nc_fallback_pkgs[netcat-traditional]}"
                fi
            fi
        elif command -v yum &>/dev/null; then
            # Adjust package names for yum if necessary (e.g. netcat-openbsd -> nc or nmap-ncat)
            local yum_packages=()
            for pkg in "${unique_packages_to_install[@]}"; do
                if [[ "$pkg" == "netcat-openbsd" ]]; then yum_packages+=("nmap-ncat"); else yum_packages+=("$pkg"); fi
            done
            if ! run_with_spinner "Installing dependencies (yum)..." sudo yum install -y "${yum_packages[@]}"; then
                 handle_error "ERROR" "Some dependencies failed to install via yum. Please try manually."
            fi
        elif command -v dnf &>/dev/null; then
            local dnf_packages=()
            for pkg in "${unique_packages_to_install[@]}"; do
                if [[ "$pkg" == "netcat-openbsd" ]]; then dnf_packages+=("nmap-ncat"); else dnf_packages+=("$pkg"); fi
            done
            if ! run_with_spinner "Installing dependencies (dnf)..." sudo dnf install -y "${dnf_packages[@]}"; then
                 handle_error "ERROR" "Some dependencies failed to install via dnf. Please try manually."
            fi
        else
            handle_error "CRITICAL" "Unsupported package manager. Please install the missing dependencies manually: ${missing_cmds[*]}"
            return 1
        fi

        # Re-check after install attempt
        local still_missing_cmds=()
        for cmd in "${missing_cmds[@]}"; do # Only re-check originally missing commands
            if ! command -v "$cmd" &>/dev/null; then
                still_missing_cmds+=("$cmd")
            fi
        done
        if [[ ${#still_missing_cmds[@]} -gt 0 ]]; then
             handle_error "CRITICAL" "Failed to install the following critical dependencies: ${still_missing_cmds[*]}. Please install them manually and re-run the script."
             return 1
        fi
        handle_success "All attempted dependency installations complete."
    else
        log_message "INFO" "All essential dependencies found."
    fi
    return 0
}


# Final 'true' to ensure the script is valid if sourced.
true