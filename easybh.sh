#!/bin/bash
echo 'DEBUG: SCRIPT EXECUTION STARTED' >&2
# ======================================================================
# THIS FILE IS AUTO-GENERATED. DO NOT EDIT DIRECTLY.
# Edit the files in ./modules/ and run ./build.sh to regenerate.
# ======================================================================
# Build order ensures proper function dependencies:
# 1. globals.sh - Global variables
# 2. helpers.sh - Core utilities, validation, dependency checks
# 3. backhaul_core.sh - Binary installation
# 4. config.sh - Configuration wizard
# 5. validation.sh - Config validation
# 6. ufw.sh - Firewall management
# 7. systemd.sh - Service management
# 8. cron.sh - Cron job management
# 9. restart_watcher.sh - Restart watcher
# 10. tunnel_mgmt.sh - Tunnel operations
# 11. menu.sh - Main interface, root check, initial calls
# ======================================================================
# --- MODULE: modules/globals.sh ---
# globals.sh
# Contains global variables, constants, and paths for EasyBackhaul

# --- Global Variables ---
# All global variables use UPPER_SNAKE_CASE for consistency
# Using /tmp for paths to ensure writability in restricted environments/sandboxes
CONFIG_DIR="/tmp/easybackhaul_config"
BACKUP_DIR="/tmp/easybackhaul_backups"
BIN_PATH="/tmp/easybackhaul_bin/easybackhaul_binary" # Renamed to avoid conflict
SERVICE_DIR="/tmp/easybackhaul_services" # Dummy for testing, real systemd is /etc/systemd/system
LOG_DIR="/tmp/easybackhaul_logs"

CRON_COMMENT_TAG="EasyBackhaul" # Standardized comment tag

# Generate a random secret for restart watcher if not already set
# This secret is a global default; per-tunnel secrets can also be used.
GLOBAL_WATCHER_SECRET_FILE="${CONFIG_DIR}/watcher_master.secret"

# Helper function scoped to this file for early CONFIG_DIR creation if needed.
# This is because helpers.sh (with ensure_dir) isn't sourced yet.
_globals_ensure_config_dir_for_secret() {
    if [[ ! -d "$CONFIG_DIR" ]]; then
        mkdir -p "$CONFIG_DIR"
        if [[ $? -ne 0 ]]; then
            echo "ERROR: [_globals_ensure_config_dir_for_secret] Failed to create CONFIG_DIR: $CONFIG_DIR. Please check permissions." >&2
            return 1
        else
            chmod 700 "$CONFIG_DIR" # Set restrictive permissions
            return 0
        fi
    fi
    return 0 # Dir already exists
}

RESTART_WATCHER_SECRET_VALUE="" # Temporary variable to hold the secret value

# 1. Check if RESTART_WATCHER_SECRET is already set (e.g., by environment variable)
if [[ -n "$RESTART_WATCHER_SECRET" ]]; then
    RESTART_WATCHER_SECRET_VALUE="$RESTART_WATCHER_SECRET"
else
    # 2. If not set by env, try to read from the global secret file
    # Ensure config directory exists before trying to read from it.
    if _globals_ensure_config_dir_for_secret; then
        if [[ -f "$GLOBAL_WATCHER_SECRET_FILE" ]]; then
            RESTART_WATCHER_SECRET_VALUE=$(cat "$GLOBAL_WATCHER_SECRET_FILE" 2>/dev/null)
        fi
    fi
fi

# 3. If still no secret (neither from env nor file), generate, save, and set it.
if [[ -z "$RESTART_WATCHER_SECRET_VALUE" ]]; then
    if _globals_ensure_config_dir_for_secret; then # Ensure dir exists before writing
        # Use direct command as helpers.sh (where generate_random_secret is) isn't sourced yet.
        GENERATED_SECRET_FALLBACK=$(openssl rand -hex 32 2>/dev/null || tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 64)
        if [[ -n "$GENERATED_SECRET_FALLBACK" ]]; then
            echo "$GENERATED_SECRET_FALLBACK" > "$GLOBAL_WATCHER_SECRET_FILE"
            if [[ $? -eq 0 ]]; then # Check if write was successful
                chmod 600 "$GLOBAL_WATCHER_SECRET_FILE"
                RESTART_WATCHER_SECRET_VALUE="$GENERATED_SECRET_FALLBACK"
            else
                # Failed to write to file, don't use the generated secret if it couldn't be persisted.
                echo "ERROR: [_globals_ensure_config_dir_for_secret] Failed to write to $GLOBAL_WATCHER_SECRET_FILE. Watcher secret not set." >&2
                RESTART_WATCHER_SECRET_VALUE="" # Ensure it remains empty
            fi
        else
            echo "WARNING: [_globals_ensure_config_dir_for_secret] Failed to generate random string for RESTART_WATCHER_SECRET." >&2
        fi
    else
         echo "WARNING: [_globals_ensure_config_dir_for_secret] CONFIG_DIR '$CONFIG_DIR' not usable. Cannot generate/store global watcher secret." >&2
    fi
fi
RESTART_WATCHER_SECRET="$RESTART_WATCHER_SECRET_VALUE" # Assign to the final global var
unset RESTART_WATCHER_SECRET_VALUE GENERATED_SECRET_FALLBACK # Clean up temp vars
# The helper function _globals_ensure_config_dir_for_secret remains defined.

# --- Enhanced Logging System ---
# LOG_DIR is already defined above
LOG_LEVEL="INFO"  # DEBUG, INFO, WARN, ERROR, CRITICAL
LOG_MAX_FILES=5     # For logrotate
LOG_FORMAT="text"   # json, text (default to text for easier human reading)

# --- Health Monitoring ---
# Specific log files for health and performance, distinct from the main operational log.
HEALTH_LOG_FILE="${LOG_DIR}/easybackhaul_health.log"
PERFORMANCE_LOG_FILE="${LOG_DIR}/easybackhaul_performance.log"

# --- Performance Settings ---
MAX_CONCURRENT_OPERATIONS=4 # Default for concurrent operations like health checks

# --- Advanced Error Recovery ---
MAX_RESTART_ATTEMPTS=3    # For services/watchers
RESTART_COOLDOWN=10       # Seconds, for services/watchers

# --- Resource Management ---
PROCESS_PRIORITY=0  # Default 'nice' value for backhaul processes (0 is normal)

# --- Configuration Validation ---
CONFIG_BACKUP_ON_CHANGE=true # Automatic backup of TOML configs on change

# --- Security Enhancements ---
FILE_PERMISSIONS_STRICT=true    # Enforce 600/700 permissions where appropriate
TEMP_FILE_SECURE_DELETE=false   # Default to false; shredding can be slow. User can enable.

# --- Watcher Defaults (can be overridden in tunnel TOML or watcher.conf) ---
WATCHER_DEFAULT_LOG_PATTERN="ERROR|FATAL|connection.*failed|timeout|reset by peer|broken pipe"
WATCHER_DEFAULT_DELAY_LOCAL=10
WATCHER_DEFAULT_DELAY_REMOTE=15 # Slightly longer for remote to react
WATCHER_DEFAULT_MAX_RETRIES=3
WATCHER_SERVER_LISTEN_PORT=45679 # Default listen port for server-side watcher
WATCHER_CLIENT_LISTEN_PORT=45680 # Default listen port for client-side watcher
# Note: When a server watcher communicates, its REMOTE_PORT will be WATCHER_CLIENT_LISTEN_PORT.
# When a client watcher communicates, its REMOTE_PORT will be WATCHER_SERVER_LISTEN_PORT.

true # Ensure the script can be sourced without error if it's the last one.

# --- MODULE: modules/helpers.sh ---
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

# Unified menu footer printing
# Param $1: The primary numbered exit option for the current menu (e.g., "0. Back to Main Menu")
print_menu_footer() {
    local numbered_exit_option="$1" # e.g., "0. Back to Previous"

    echo "----------------------------------------------------------------"
    if [[ -n "$numbered_exit_option" ]]; then
        echo " $numbered_exit_option"
    fi
    echo " [?] Help  |  [r] Return/Back  |  [m] Main Menu  |  [e] Exit Script"
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
# Usage: menu_loop "Prompt Message" "options_array_name" "default_exit_option_details_array_name" ["custom_help_function_name"]
#   options_array: ("1. Option A" "2. Option B")
#   default_exit_option_details_array: ("0" "Back to Previous Menu") -> Number and Text for the default exit.
# Sets MENU_CHOICE to the selected number/char.
# Returns:
#   0: Valid numeric choice from options_ref OR the default_exit_num_char was chosen.
#   2: '?' (Help) was pressed.
#   3: 'm' (Main Menu) was pressed.
#   4: 'e' (Exit Script) was pressed.
#   5: 'r' (Return/Back) was pressed.
#   1: Other error / invalid (should ideally be caught before this).
menu_loop() {
    local prompt_msg="$1"
    local -n options_ref=$2          # Array of menu options like "1. Do X"
    local -n exit_option_details_ref=$3 # Array like ("0" "Back to Main")
    local custom_help_function_name="${4:-}"

    local min_numeric_opt=1
    local max_numeric_opt=${#options_ref[@]}
    
    local default_exit_key="${exit_option_details_ref[0]}" # e.g., "0"
    local default_exit_text="${exit_option_details_ref[1]}" # e.g., "Back to Main Menu"

    # Construct the choice part of the prompt string
    local prompt_choices_str=""
    if (( max_numeric_opt > 0 )); then
        prompt_choices_str="${min_numeric_opt}-${max_numeric_opt}, "
    fi
    prompt_choices_str+="${default_exit_key}"
    
    while true; do
        # Display options from the array
        for opt_str in "${options_ref[@]}"; do
            echo "  $opt_str"
        done
        # Display the footer with the specific default exit option and universal nav keys
        print_menu_footer "${default_exit_key}. ${default_exit_text}"
        
        read -r -p "$prompt_msg [${prompt_choices_str}, ?, r, m, e]: " raw_choice
        MENU_CHOICE=$(echo "$raw_choice" | tr '[:upper:]' '[:lower:]') # Normalize to lowercase

        case "$MENU_CHOICE" in
            '?')
                if [[ -n "$custom_help_function_name" ]] && type "$custom_help_function_name" &>/dev/null; then
                    "$custom_help_function_name"
                else
                    print_info "No specific help available for this menu."
                    press_any_key
                fi
                return 2 # Help shown, caller should re-loop/re-render
                ;;
            'm') return 3 ;; # Request Main Menu
            'e') return 4 ;; # Request Exit Script
            'r') return 5 ;; # Request Return/Back
        esac

        # Check if choice is the default exit key (e.g., "0")
        if [[ "$MENU_CHOICE" == "$default_exit_key" ]]; then
            return 0 # Valid default exit chosen
        fi

        # Check if choice is a number within the options range
        if [[ "$MENU_CHOICE" =~ ^[0-9]+$ ]] && \
           (( MENU_CHOICE >= min_numeric_opt && MENU_CHOICE <= max_numeric_opt )); then
            return 0 # Valid numeric option selected
        fi

        print_warning "Invalid option. Please try again."
        press_any_key
        # Loop again to re-display menu and prompt (after print_menu_header in calling function)
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
    while ps -p $pid > /dev/null 2>&1; do
        printf "\b%s" "${spin_chars:i++%${#spin_chars}:1}"
        sleep 0.1
    done
    printf "\b"
    
    wait $pid
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        print_success "Done."
        rm -f "$log_file" # Clean up successful log
    else
        print_error "Failed. (Exit code: $exit_code)"
        print_info "Details logged to: $log_file"
        # Do not delete log_file on error so user can inspect it
    fi
    return $exit_code
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
    local local_exit_options=("0. Back")
    local user_choice
    local menu_return_code

    while true; do
        print_menu_header "secondary" "$log_title" "Source: $log_identifier"
        menu_loop "Select log view option" local_menu_options local_exit_options "_view_log_help"
        user_choice="$MENU_CHOICE"
        menu_return_code=$?

        if [[ "$menu_return_code" -eq 3 ]]; then go_to_main_menu; return; fi
        if [[ "$menu_return_code" -eq 4 ]]; then request_script_exit; return; fi
        # menu_return_code 2 (help shown) is handled by menu_loop continuing.

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
                if [[ "$log_source_type" == "journalctl" ]]; then
                    journalctl -u "$log_identifier" -f
                elif [[ -f "$log_identifier" ]]; then
                    tail -f "$log_identifier"
                else print_error "Log source not found: $log_identifier"; fi
                print_info "Live log follow stopped." # This will show after Ctrl+C
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
            "0")
                return_from_menu; return ;;
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
# --- MODULE: modules/backhaul_core.sh ---
# modules/backhaul_core.sh
# Download, install, and update Backhaul binary; get server info 

# Global variables for server info - to be populated by get_server_info
SERVER_IP="N/A"
SERVER_COUNTRY="N/A"
SERVER_ISP="N/A"

# Fetches server's public IP and geo-information.
# Populates SERVER_IP, SERVER_COUNTRY, SERVER_ISP global variables.
get_server_info() {
    log_message "INFO" "Attempting to fetch server IP and geo-information..."
    SERVER_IP="N/A"
    SERVER_COUNTRY="N/A"
    SERVER_ISP="N/A"

    local services_to_try=(
        "http://ip-api.com/json/?fields=query,country,isp"
        "https://ipapi.co/json/"
        "https://ipinfo.io/json"
    )
    local response_json

    for service_url in "${services_to_try[@]}"; do
        log_message "DEBUG" "Trying IP service: $service_url"
        
        # Use run_with_spinner for curl command with timeout
        # Create a temporary file to capture curl output
        local temp_output_file
        temp_output_file=$(mktemp)

        # Using a subshell to capture output for response_json
        if response_json=$(timeout 10s curl -s --connect-timeout 3 --max-time 8 "$service_url" 2>"$temp_output_file"); then
            if [[ -n "$response_json" ]] && echo "$response_json" | jq -e . >/dev/null 2>&1; then
                # Attempt to parse common fields
                local ip country isp
                ip=$(echo "$response_json" | jq -r '.ip // .query // "N/A"')
                country=$(echo "$response_json" | jq -r '.country // .country_name // "N/A"')
                isp=$(echo "$response_json" | jq -r '.isp // .org // "N/A"')

                if [[ "$ip" != "N/A" && "$ip" != "null" ]]; then
                    SERVER_IP="$ip"
                    SERVER_COUNTRY="$country"
                    SERVER_ISP="$isp"
                    log_message "INFO" "Server info fetched from $service_url: IP=$SERVER_IP, Country=$SERVER_COUNTRY, ISP=$SERVER_ISP"
                    rm -f "$temp_output_file"
                    return 0
                else
                    log_message "WARN" "Successfully fetched from $service_url, but IP address was null or N/A."
                fi
            else
                log_message "WARN" "Invalid or empty JSON response from $service_url. Error: $(cat "$temp_output_file")"
            fi
        else
            log_message "WARN" "Failed to fetch from $service_url. Error: $(cat "$temp_output_file")"
        fi
        rm -f "$temp_output_file"
    done

    log_message "WARN" "All external IP services failed. Attempting fallback using icanhazip.com..."
    local fallback_ip
    if fallback_ip=$(curl -s --connect-timeout 3 --max-time 5 https://icanhazip.com 2>/dev/null | tr -d '\n\r'); then
         if [[ -n "$fallback_ip" ]] && validate_ip "$fallback_ip"; then # Use helper
            SERVER_IP="$fallback_ip"
            # SERVER_COUNTRY and SERVER_ISP will remain N/A
            log_message "INFO" "Fallback successful. Server IP detected as: $SERVER_IP (Country/ISP unknown)."
            return 0
        else
            log_message "WARN" "Fallback icanhazip.com returned invalid IP: $fallback_ip"
        fi
    else
        log_message "ERROR" "Could not fetch server IP from any source."
    fi
    
    # If still N/A, log it.
    if [[ "$SERVER_IP" == "N/A" ]]; then
        log_message "ERROR" "Unable to determine server IP address."
    fi
    return 1
}

# Verifies the Backhaul binary installation and version.
# Uses global BIN_PATH.
verify_binary_installation() {
    log_message "INFO" "Verifying Backhaul binary at: $BIN_PATH"
    if [[ ! -f "$BIN_PATH" ]]; then
        handle_error "ERROR" "Binary not found at expected location: $BIN_PATH"
        return 1
    fi
    
    if [[ ! -x "$BIN_PATH" ]]; then
        handle_error "WARNING" "Binary at $BIN_PATH is not executable. Attempting to fix..."
        chmod +x "$BIN_PATH"
        if [[ ! -x "$BIN_PATH" ]]; then
            handle_error "ERROR" "Failed to make binary $BIN_PATH executable."
            return 1
        fi
        log_message "INFO" "Binary permissions fixed for $BIN_PATH."
    fi
    
    local version_output=""
    # Try -v first, then --version
    if version_output=$("$BIN_PATH" -v 2>&1 | head -n1); then
        : # Command succeeded, version_output captured
    elif version_output=$("$BIN_PATH" --version 2>&1 | head -n1); then
        : # Command succeeded, version_output captured
    else
        handle_error "WARNING" "Binary exists at $BIN_PATH but version check command failed. It might be incompatible or corrupted."
        return 1
    fi

    if [[ -z "$version_output" ]] || echo "$version_output" | grep -qiE "command not found|no such file|error"; then
        handle_error "WARNING" "Binary at $BIN_PATH version output seems invalid: $version_output"
        return 1
    fi

    handle_success "Backhaul binary verification successful. Version: $version_output"
    return 0
}

# Installs the downloaded Backhaul binary.
# Assumes binary is at /tmp/backhaul.tar.gz
# Uses global BIN_PATH.
install_downloaded_binary() {
    local archive_path="/tmp/backhaul.tar.gz"
    local target_bin_dir
    target_bin_dir=$(dirname "$BIN_PATH")
    local target_bin_name
    target_bin_name=$(basename "$BIN_PATH")

    log_message "INFO" "Starting installation of Backhaul binary from $archive_path to $BIN_PATH"

    if [[ ! -f "$archive_path" ]]; then
        handle_error "ERROR" "Downloaded archive $archive_path not found."
        return 1
    fi

    if ! tar -tzf "$archive_path" >/dev/null 2>&1; then
        handle_error "ERROR" "File $archive_path is not a valid tar.gz archive."
        secure_delete "$archive_path"
        return 1
    fi

    local temp_extract_dir
    temp_extract_dir=$(mktemp -d /tmp/backhaul_extract_XXXXXX)
    
    log_message "INFO" "Extracting $archive_path to $temp_extract_dir..."
    if ! tar -xzf "$archive_path" -C "$temp_extract_dir"; then
        handle_error "ERROR" "Extraction of $archive_path failed."
        rm -rf "$temp_extract_dir"
        secure_delete "$archive_path"
        return 1
    fi

    # Find the binary - could be 'backhaul' or 'backhaul_os_arch/backhaul' etc.
    local found_binary_path
    found_binary_path=$(find "$temp_extract_dir" -type f \( -name "backhaul" -o -name "$target_bin_name" \) -executable 2>/dev/null | head -n1)
    
    if [[ -z "$found_binary_path" ]]; then
        # If not executable, try finding by name only
        found_binary_path=$(find "$temp_extract_dir" -type f \( -name "backhaul" -o -name "$target_bin_name" \) 2>/dev/null | head -n1)
        if [[ -z "$found_binary_path" ]]; then
            handle_error "ERROR" "Could not find 'backhaul' binary within the extracted archive."
            rm -rf "$temp_extract_dir"
            secure_delete "$archive_path"
            return 1
        fi
        log_message "WARN" "Found binary '$found_binary_path' but it was not marked executable initially."
    fi

    log_message "INFO" "Found binary at '$found_binary_path'. Moving to $BIN_PATH."
    
    ensure_dir "$target_bin_dir" "755" # Ensure target directory exists
    
    if ! mv "$found_binary_path" "$BIN_PATH"; then
        handle_error "ERROR" "Failed to move binary from $found_binary_path to $BIN_PATH."
        rm -rf "$temp_extract_dir"
        secure_delete "$archive_path"
        return 1
    fi

    chmod +x "$BIN_PATH"
    set_secure_file_permissions "$BIN_PATH" "755" # Executable for owner, readable for others

    rm -rf "$temp_extract_dir"
    secure_delete "$archive_path"
    
    log_message "INFO" "Backhaul binary extracted and placed at $BIN_PATH."

    if verify_binary_installation; then
        handle_success "Backhaul binary installation completed and verified!"
        print_info "Summary: 📁 $BIN_PATH | 🔒 $(stat -c %a "$BIN_PATH") | 📊 $(du -h "$BIN_PATH" | cut -f1)"
    else
        handle_error "WARNING" "Binary installed to $BIN_PATH, but verification failed. It may be incompatible."
    fi
    return 0
}


# --- Download Backhaul Binary Workflow ---
_download_menu_help() {
    print_info "Backhaul Installation Help:"
    echo " - GitHub Download: Attempts to fetch the latest release directly."
    echo " - Local File: Install from a .tar.gz you've already downloaded."
    echo " - Alt. Source: Provide a custom URL for the .tar.gz binary archive."
    echo " - Network Diagnostics: Test connectivity if downloads fail."
    echo " - Skip: Continue without installing (you can install later)."
    press_any_key
}

download_backhaul_binary_workflow() {
    print_menu_header "primary" "Backhaul Binary Installation"
    
    log_message "INFO" "Identifying system architecture..."
    local system_os system_arch detected_arch_suffix
    system_os=$(uname -s | tr '[:upper:]' '[:lower:]')
    system_arch=$(uname -m)

    case "$system_arch" in
        x86_64) detected_arch_suffix="amd64" ;;
        aarch64) detected_arch_suffix="arm64" ;;
        armv7l) detected_arch_suffix="armv7" ;; # Common for RPi
        *) 
            handle_error "CRITICAL" "Unsupported architecture: $system_arch. Cannot automatically download."
            press_any_key
            return 1
            ;;
    esac
    print_success "Detected System: $system_os / $detected_arch_suffix (raw: $system_arch)"
    echo

    local menu_options=(
        "1. Automatic GitHub Download (Recommended)"
        "2. Install from Local File"
        "3. Install from Alternative URL"
        "4. Run Network Diagnostics"
        "5. Skip Installation (Advanced)"
    )
    local current_exit_details=("0" "Cancel Installation") # Array: [key, text]
    local user_choice menu_rc

    while true; do
        print_menu_header "primary" "Backhaul Binary Installation" "Choose Installation Method"
        # Pass arrays by name
        menu_loop "Select option" menu_options current_exit_details "_download_menu_help"
        user_choice="$MENU_CHOICE" # menu_loop sets MENU_CHOICE
        menu_rc=$?                # menu_loop returns status code
        
        # Handle universal navigation keys based on menu_rc
        case "$menu_rc" in
            3) go_to_main_menu; return 0 ;; # m -> main menu
            4) request_script_exit; return 0 ;; # e -> exit script
            5) # r -> return/back (for this top-level workflow, it's like cancelling)
               print_info "Installation cancelled via 'r' key."
               return 1 ;;
            2) continue ;; # ? -> help was shown, re-loop current menu
        esac

        # Handle numeric choices and the specific default exit ("0")
        case "$user_choice" in
            "1") # GitHub Download
                _download_from_github "$system_os" "$detected_arch_suffix" # This function will return 0 on success, 1 on failure
                # If successful, download_backhaul_binary_workflow should also return 0
                # If _download_from_github was successful (which means install_downloaded_binary was successful),
                # we can assume the workflow is complete.
                if [[ $? -eq 0 ]]; then return 0; fi
                # If it failed, the error message is handled in _download_from_github or install_downloaded_binary
                # Loop will continue to re-prompt installation method.
                ;;
            "2") # Local File
                _download_from_local_file "$system_os" "$detected_arch_suffix"
                if [[ $? -eq 0 ]]; then return 0; fi
                ;;
            "3") # Alternative URL
                _download_from_alternative_source "$system_os" "$detected_arch_suffix"
                if [[ $? -eq 0 ]]; then return 0; fi
                ;;
            "4") # Network Diagnostics
                # run_network_diagnostics_menu is a self-contained menu loop.
                # It will handle its own navigation and return when the user exits it.
                # We need to ensure it's called correctly.
                # If run_network_diagnostics_menu itself needs to trigger main menu or exit script, it should use the nav helpers.
                # For now, assume it returns to this loop.
                if type run_network_diagnostics_menu &>/dev/null; then
                    navigate_to_menu "run_network_diagnostics_menu"
                    return 0 # Let main loop call it
                else
                    handle_error "ERROR" "Network diagnostics function not available."
                fi
                ;;
            "5") # Skip
                print_warning "Skipping binary installation."
                print_info "You can install the binary later using the main menu."
                print_info "Ensure it's placed at: $BIN_PATH"
                press_any_key
                return 0 # Successfully skipped
                ;;
            "0") # Cancel Installation (Matches current_exit_details[0])
                print_info "Installation cancelled."
                return 1 # Signify cancellation/failure
                ;;
            *) 
                print_warning "Invalid option selected in download workflow."
                ;;
        esac
        # If an option failed and didn't return, loop back to show menu again
        press_any_key
    done
}

# Helper function for installation menu choice
# download_installation_choice() { # No longer needed due to direct MENU_CHOICE usage
#     local choice="$1"
#     download_choice="$choice"
# }

# Helper function for fallback menu choice
# download_fallback_choice() { # No longer needed if _download_from_github doesn't have its own sub-menu loop for this
#     local choice="$1"
#     fallback_choice="$choice"
# }

_download_from_github() {
    local os="$1"
    local arch_suffix="$2"
    local latest_version=""

    log_message "INFO" "Fetching latest Backhaul version from GitHub API..."
    local api_response
    api_response=$(curl -s --connect-timeout 10 "https://api.github.com/repos/Musixal/Backhaul/releases/latest")

    if [[ -n "$api_response" ]] && echo "$api_response" | jq -e .tag_name >/dev/null 2>&1; then
        latest_version=$(echo "$api_response" | jq -r .tag_name)
        if [[ -z "$latest_version" || "$latest_version" == "null" ]]; then
            log_message "WARN" "Could not parse tag_name from GitHub API response. Will try a common fallback."
            latest_version="v0.6.6" # Fallback, consider making this more dynamic or removing
        else
            log_message "INFO" "Latest version from GitHub: $latest_version"
        fi
    else
        handle_error "WARNING" "Failed to fetch latest version from GitHub API. Check connectivity or API rate limits."
        log_message "WARN" "Using fallback version v0.6.6 due to API fetch failure."
        latest_version="v0.6.6"
    fi

    local download_url="https://github.com/Musixal/Backhaul/releases/download/${latest_version}/backhaul_${os}_${arch_suffix}.tar.gz"
    print_info "Attempting to download Backhaul ${latest_version} for ${os}/${arch_suffix}..."
    echo "URL: $download_url"

    if run_with_spinner "Downloading from GitHub..." \
        wget --progress=dot:giga -O /tmp/backhaul.tar.gz "$download_url"; then
        if install_downloaded_binary; then # install_downloaded_binary returns 0 on success
            return 0 # Overall success
        else
            handle_error "ERROR" "Binary installation failed after download."
            return 1 # Installation part failed
        fi
    else
        handle_error "ERROR" "Download from GitHub failed. URL: $download_url"
        return 1
    fi
}

_download_from_local_file() {
    local os="$1" # For informational purposes
    local arch_suffix="$2" # For informational purposes
    
    print_menu_header "secondary" "Local File Installation" \
        "Install Backhaul from a pre-downloaded file."
    
    print_info "Provide the full path to your local Backhaul .tar.gz archive."
    print_info "(e.g., /path/to/your/backhaul_${os}_${arch_suffix}.tar.gz)"
    
    local local_file_path
    while true; do
        read -e -r -p "Enter path to local .tar.gz file (or '0' to cancel): " local_file_path
        if [[ "$local_file_path" == "0" ]]; then print_info "Cancelled."; return 1; fi
        if [[ -z "$local_file_path" ]]; then
            if prompt_yes_no "Path cannot be empty. Cancel local file installation?" "y"; then return 1; fi
            continue
        fi
        if [[ ! -f "$local_file_path" ]]; then
            if prompt_yes_no "File not found: '$local_file_path'. Try again?" "y"; then continue; else return 1; fi
        fi
        # Relaxed check for .tar.gz, install_downloaded_binary will verify archive integrity.
        # if [[ "$local_file_path" != *.tar.gz ]]; then
        #     if prompt_yes_no "File does not end with .tar.gz. Proceed anyway?" "n"; then break; else continue; fi
        # fi
        break
    done

    log_message "INFO" "Copying local file '$local_file_path' to /tmp/backhaul.tar.gz"
    if cp "$local_file_path" /tmp/backhaul.tar.gz; then
        if install_downloaded_binary; then return 0; else return 1; fi
    else
        handle_error "ERROR" "Failed to copy local file '$local_file_path' to temporary location."
        return 1
    fi
}

_download_from_alternative_source() {
    local os="$1" # For informational purposes
    local arch_suffix="$2" # For informational purposes

    print_menu_header "secondary" "Alternative Download Source" \
        "Install Backhaul from a custom URL."
    
    print_info "Provide the full URL to the Backhaul .tar.gz archive."
    print_info "(e.g., https://your-mirror.com/backhaul_${os}_${arch_suffix}.tar.gz)"

    local alt_url
    while true; do
        read -e -r -p "Enter alternative download URL (or '0' to cancel): " alt_url
        if [[ "$alt_url" == "0" ]]; then print_info "Cancelled."; return 1; fi
        if [[ -z "$alt_url" ]]; then
            if prompt_yes_no "URL cannot be empty. Cancel alternative source installation?" "y"; then return 1; fi
            continue
        fi
        if [[ ! "$alt_url" =~ ^https?:// ]]; then # Basic URL check
            if prompt_yes_no "URL does not look valid. Try again?" "y"; then continue; else return 1; fi
        fi
        break
    done

    if run_with_spinner "Downloading from $alt_url..." \
        wget --progress=dot:giga -O /tmp/backhaul.tar.gz "$alt_url"; then
        if install_downloaded_binary; then return 0; else return 1; fi
    else
        handle_error "ERROR" "Download from alternative source '$alt_url' failed."
        return 1
    fi
}

# Network diagnostics menu (moved from menu.sh potentially, or refined)
run_network_diagnostics_menu() {
    _network_diag_help() {
        print_info "Network Diagnostics Help:"
        echo " This tests connectivity to common internet services and GitHub."
        echo " Failures can indicate network configuration issues on your VPS,"
        echo " DNS problems, or regional blocks."
        press_any_key
    }

    local diag_menu_options=("1. Run All Network Tests")
    local diag_exit_details=("0" "Back to Installation Options") # Array: [key, text]
    local user_choice diag_rc

    while true; do
        print_menu_header "secondary" "Network Connectivity Diagnostics"
        menu_loop "Select option" diag_menu_options diag_exit_details "_network_diag_help"
        user_choice="$MENU_CHOICE"
        diag_rc=$?

        case "$diag_rc" in
            3) go_to_main_menu; return ;; # m -> main menu
            4) request_script_exit; return ;; # e -> exit script
            5) return_from_menu; return ;; # r -> return/back
            2) continue ;; # ? -> help was shown
        esac

        case "$user_choice" in
            "1")
                print_info "--- Testing General Internet Connectivity ---"
                check_basic_connectivity # Uses a few common hosts like 8.8.8.8, google.com
                echo
                print_info "--- Testing GitHub Connectivity ---"
                local github_hosts=("github.com" "api.github.com" "objects.githubusercontent.com")
                local gh_success_count=0
                for gh_host in "${github_hosts[@]}"; do
                    if run_with_spinner "Pinging $gh_host..." ping -c 1 -W 2 "$gh_host"; then
                        ((gh_success_count++))
                    fi
                done
                 if (( gh_success_count == ${#github_hosts[@]} )); then
                    print_success "All GitHub hosts pingable."
                elif (( gh_success_count > 0 )); then
                    print_warning "Some GitHub hosts not pingable. Downloads might be affected."
                else
                    print_error "Cannot ping any GitHub hosts. Downloads from GitHub will likely fail."
                fi
                press_any_key
                ;;
            "0") # Default exit for this menu
                return_from_menu; return ;; # Return to previous menu (download_backhaul_binary_workflow)
            *) print_warning "Invalid option in network diagnostics."; press_any_key;;
        esac
    done
}


true # Ensure script is valid
                handle_error "ERROR" "GitHub download and installation failed."
                # If it fails, loop back to offer other options
                ;;
            "2") # Local File
                _download_from_local_file "$system_os" "$detected_arch_suffix" && return 0 || \
                handle_error "ERROR" "Local file installation failed."
                ;;
            "3") # Alternative URL
                _download_from_alternative_source "$system_os" "$detected_arch_suffix" && return 0 || \
                handle_error "ERROR" "Alternative URL installation failed."
                ;;
            "4") # Network Diagnostics
                run_network_diagnostics_menu # This function is self-contained with its own menu loop
                # After diagnostics, the user is returned here to re-choose.
                ;;
            "5") # Skip
                print_warning "Skipping binary installation."
                print_info "You can install the binary later using the main menu."
                print_info "Ensure it's placed at: $BIN_PATH"
                press_any_key
                return 0 # Successfully skipped
                ;;
            "0") # Cancel
                print_info "Installation cancelled."
                return 1 # Signify cancellation/failure
                ;;
            *) # Should be handled by menu_loop, but as a fallback
                print_warning "Invalid option selected."
                press_any_key
                ;;
        esac
        # If an option failed and didn't return, loop back to show menu again
        press_any_key
    done
}

_download_from_github() {
    local os="$1"
    local arch_suffix="$2"
    local latest_version=""

    log_message "INFO" "Fetching latest Backhaul version from GitHub API..."
    local api_response
    api_response=$(curl -s --connect-timeout 10 "https://api.github.com/repos/Musixal/Backhaul/releases/latest")

    if [[ -n "$api_response" ]] && echo "$api_response" | jq -e .tag_name >/dev/null 2>&1; then
        latest_version=$(echo "$api_response" | jq -r .tag_name)
        if [[ -z "$latest_version" || "$latest_version" == "null" ]]; then
            log_message "WARN" "Could not parse tag_name from GitHub API response. Will try a common fallback."
            latest_version="v0.6.6" # Fallback, consider making this more dynamic or removing
        else
            log_message "INFO" "Latest version from GitHub: $latest_version"
        fi
    else
        handle_error "WARNING" "Failed to fetch latest version from GitHub API. Check connectivity or API rate limits."
        # Could offer to input version manually or use a fixed known good version. For now, using fallback.
        log_message "WARN" "Using fallback version v0.6.6 due to API fetch failure."
        latest_version="v0.6.6"
    fi

    local download_url="https://github.com/Musixal/Backhaul/releases/download/${latest_version}/backhaul_${os}_${arch_suffix}.tar.gz"
    print_info "Attempting to download Backhaul ${latest_version} for ${os}/${arch_suffix}..."
    echo "URL: $download_url"

    if run_with_spinner "Downloading from GitHub..." \
        wget --progress=dot:giga -O /tmp/backhaul.tar.gz "$download_url"; then
        install_downloaded_binary
        return $? # Return status of install_downloaded_binary
    else
        handle_error "ERROR" "Download from GitHub failed. URL: $download_url"
        return 1
    fi
}

_download_from_local_file() {
    local os="$1" # For informational purposes
    local arch_suffix="$2" # For informational purposes
    
    print_menu_header "secondary" "Local File Installation" \
        "Install Backhaul from a pre-downloaded file."
    
    print_info "Provide the full path to your local Backhaul .tar.gz archive."
    print_info "(e.g., /path/to/your/backhaul_${os}_${arch_suffix}.tar.gz)"

    local local_file_path
    while true; do
        read -e -r -p "Enter path to local .tar.gz file: " local_file_path
        if [[ -z "$local_file_path" ]]; then
            if prompt_yes_no "Path cannot be empty. Cancel local file installation?" "y"; then return 1; fi
            continue
        fi
        if [[ ! -f "$local_file_path" ]]; then
            if prompt_yes_no "File not found: '$local_file_path'. Try again?" "y"; then continue; else return 1; fi
        fi
        if [[ "$local_file_path" != *.tar.gz ]]; then
            if prompt_yes_no "File does not end with .tar.gz. Proceed anyway?" "n"; then break; else continue; fi
        fi
        break
    done

    log_message "INFO" "Copying local file '$local_file_path' to /tmp/backhaul.tar.gz"
    if cp "$local_file_path" /tmp/backhaul.tar.gz; then
        install_downloaded_binary
        return $?
    else
        handle_error "ERROR" "Failed to copy local file '$local_file_path' to temporary location."
        return 1
    fi
}

_download_from_alternative_source() {
    local os="$1" # For informational purposes
    local arch_suffix="$2" # For informational purposes

    print_menu_header "secondary" "Alternative Download Source" \
        "Install Backhaul from a custom URL."
    
    print_info "Provide the full URL to the Backhaul .tar.gz archive."
    print_info "(e.g., https://your-mirror.com/backhaul_${os}_${arch_suffix}.tar.gz)"

    local alt_url
    while true; do
        read -e -r -p "Enter alternative download URL: " alt_url
        if [[ -z "$alt_url" ]]; then
            if prompt_yes_no "URL cannot be empty. Cancel alternative source installation?" "y"; then return 1; fi
            continue
        fi
        if [[ ! "$alt_url" =~ ^https?:// ]]; then # Basic URL check
            if prompt_yes_no "URL does not look valid. Try again?" "y"; then continue; else return 1; fi
        fi
        break
    done

    if run_with_spinner "Downloading from $alt_url..." \
        wget --progress=dot:giga -O /tmp/backhaul.tar.gz "$alt_url"; then
        install_downloaded_binary
        return $?
    else
        handle_error "ERROR" "Download from alternative source '$alt_url' failed."
        return 1
    fi
}

# Network diagnostics menu (moved from menu.sh potentially, or refined)
run_network_diagnostics_menu() {
    _network_diag_help() {
        print_info "Network Diagnostics Help:"
        echo " This tests connectivity to common internet services and GitHub."
        echo " Failures can indicate network configuration issues on your VPS,"
        echo " DNS problems, or regional blocks."
        press_any_key
    }

    local diag_menu_options=("1. Run All Network Tests")
    local diag_exit_options=("0. Back to Installation Options")
    local user_choice diag_rc

    while true; do
        print_menu_header "secondary" "Network Connectivity Diagnostics"
        menu_loop "Select option" diag_menu_options diag_exit_options "_network_diag_help"
        user_choice="$MENU_CHOICE"
        diag_rc=$?

        # Handle global nav from menu_loop if needed, though this is a sub-menu
        if [[ "$diag_rc" -eq 3 ]]; then go_to_main_menu; return; fi
        if [[ "$diag_rc" -eq 4 ]]; then request_script_exit; return; fi
        if [[ "$diag_rc" -eq 2 ]]; then continue; fi

        case "$user_choice" in
            "1")
                print_info "--- Testing General Internet Connectivity ---"
                check_basic_connectivity # Uses a few common hosts like 8.8.8.8, google.com
                echo
                print_info "--- Testing GitHub Connectivity ---"
                local github_hosts=("github.com" "api.github.com" "objects.githubusercontent.com")
                local gh_success_count=0
                for gh_host in "${github_hosts[@]}"; do
                    if run_with_spinner "Pinging $gh_host..." ping -c 1 -W 2 "$gh_host"; then
                        ((gh_success_count++))
                    fi
                done
                 if (( gh_success_count == ${#github_hosts[@]} )); then
                    print_success "All GitHub hosts pingable."
                elif (( gh_success_count > 0 )); then
                    print_warning "Some GitHub hosts not pingable. Downloads might be affected."
                else
                    print_error "Cannot ping any GitHub hosts. Downloads from GitHub will likely fail."
                fi
                press_any_key
                ;;
            "0")
                return # Return to previous menu (download_backhaul_binary_workflow)
                ;;
        esac
    done
}


true # Ensure script is valid
# --- MODULE: modules/config.sh ---
# modules/config.sh
# Tunnel configuration wizard and related TOML file management.

# WARNING: Do not use a global CONFIG_FILE variable. All configurations are per-tunnel TOML files.

# --- Helper: Get process information for a port ---
# This is kept here as it's specific to the config wizard's port checking UX
_get_port_process_info() {
    local port_to_check="$1"
    log_message "DEBUG" "Checking process for port $port_to_check"
    
    if command -v ss &>/dev/null; then
        # Using ss for more detailed info, including user if possible
        ss -lntupe "sport = :$port_to_check" 2>/dev/null | awk 'NR>1 {print "  - Process (ss): " $0}' && return 0
    fi
    if command -v netstat &>/dev/null; then
        netstat -tlnp 2>/dev/null | grep ":${port_to_check}[[:space:]]" | awk '{print "  - Process (netstat): " $0}' && return 0
    fi
    if command -v lsof &>/dev/null; then # More resource intensive
        lsof -i ":$port_to_check" -sTCP:LISTEN -P -n -- 2>/dev/null | awk 'NR>1 {print "  - Process (lsof): " $0}' && return 0
    fi
    print_info "  Port $port_to_check is in use, but detailed process info unavailable with current tools."
    return 1
}


# --- Sub-functions for configure_tunnel wizard ---

_prompt_setup_type_and_mode() {
    local -n setup_type_choice_ref=$1 # Output: 1 for Quick, 2 for Advanced
    local -n tunnel_mode_ref=$2       # Output: "server" or "client"

    print_menu_header "secondary" "Tunnel Setup Type" "Step 1 of 5: Setup Type"
    local setup_options=("1. Quick Setup (Recommended)" "2. Advanced Setup")
    local setup_exit_details=("0" "Back to Main Menu") # Array: [key, text]
    _setup_type_help() {
        print_info "Setup Type Help:"
        echo " - Quick Setup: Uses sensible defaults for most common scenarios."
        echo " - Advanced Setup: Allows manual configuration of all parameters."
        press_any_key
    }
    menu_loop "Select setup type" setup_options setup_exit_details "_setup_type_help"
    local menu_rc=$?
    case "$menu_rc" in
        3) go_to_main_menu; return 0 ;; # m -> main menu
        4) request_script_exit; return 0 ;; # e -> exit script
        5) return_from_menu; return 0 ;; # r -> return/back (to previous menu, likely main menu here)
        2) _prompt_setup_type_and_mode setup_type_choice_ref tunnel_mode_ref; return $? ;; # ? -> help shown, re-call current function
        0) # Numeric choice or default exit "0"
           if [[ "$MENU_CHOICE" == "0" ]]; then return_from_menu; return 0; fi # Explicit "0" handled as back
           : # No-op if MENU_CHOICE was numeric and not "0"
           ;;
        *) handle_error "ERROR" "Unhandled menu_loop code $menu_rc in _prompt_setup_type_and_mode"; return 1;;
    esac
    # If we reach here, menu_rc was 0 and MENU_CHOICE is a valid numeric option
    setup_type_choice_ref="$MENU_CHOICE"

    # --- Mode (Server/Client) ---
    print_menu_header "secondary" "Tunnel Mode" "Step 2 of 5: Select Mode"
    local default_mode_val="2" # Default to client if not Iran
    local detected_loc_info=""
    if [[ -n "$SERVER_COUNTRY" && "$SERVER_COUNTRY" != "N/A" ]]; then
        if [[ "$SERVER_COUNTRY" == "IR" ]]; then
            default_mode_val="1"
            detected_loc_info="Detected server location: Iran (Suggesting Server Mode)"
        else
            detected_loc_info="Detected server location: $SERVER_COUNTRY (Suggesting Client Mode)"
        fi
        print_info "$detected_loc_info"
    else
        print_info "Server location unknown. Please choose mode carefully."
    fi

    local mode_options=("1. Server (Listens for connections - typically on Iran VPS)" "2. Client (Connects to a server - typically on Foreign VPS)")
    _mode_help() {
        print_info "Tunnel Mode Help:"
        echo " - Server Mode: This machine will act as the entry point for users."
        echo "                It listens for incoming connections from Backhaul clients."
        echo " - Client Mode: This machine will connect out to a Backhaul server."
        echo "                It forwards traffic from a local port to the remote server."
        press_any_key
    }
    # setup_exit_details is ("0" "Back to Main Menu")
    menu_loop "Select tunnel mode (Default: $default_mode_val)" mode_options setup_exit_details "_mode_help"
    menu_rc=$?
    case "$menu_rc" in
        3) go_to_main_menu; return 0 ;;
        4) request_script_exit; return 0 ;;
        5) _prompt_setup_type_and_mode setup_type_choice_ref tunnel_mode_ref; return $? ;; # 'r' goes back to previous step (setup type)
        2) # Help shown, re-call current step/function
            # This recursive call needs careful thought or a loop structure within _prompt_setup_type_and_mode
            # For now, let the outer configure_tunnel loop handle it by returning a specific code if needed,
            # or simply re-prompt by continuing the while loop within this function if it had one.
            # Given the current structure, making it re-call itself for this step:
            _prompt_setup_type_and_mode setup_type_choice_ref tunnel_mode_ref; return $? ;;
        0) # Numeric choice or default exit "0"
           if [[ "$MENU_CHOICE" == "0" ]]; then return_from_menu; return 0; fi # Explicit "0" handled as back to main menu
           : # No-op if MENU_CHOICE was numeric and not "0"
           ;;
        *) handle_error "ERROR" "Unhandled menu_loop code $menu_rc in tunnel mode selection"; return 1;;
    esac

    if [[ "$MENU_CHOICE" == "1" ]]; then
        tunnel_mode_ref="server"
    elif [[ "$MENU_CHOICE" == "2" ]]; then
        tunnel_mode_ref="client"
    else
        handle_error "ERROR" "Invalid mode choice '$MENU_CHOICE' from menu_loop." # Should not happen if menu_loop is correct
        return 1
    fi
    return 0
}

_prompt_transport_protocol() {
    local setup_type_choice=$1   # 1 for Quick, 2 for Advanced
    local -n transport_ref=$2    # Output: selected transport string (e.g., "tcp")

    print_menu_header "secondary" "Transport Protocol" "Step 3 of 5: Select Protocol"
    
    local transport_options_arr=(
        "tcp (Standard, reliable)"
        "ws (WebSocket, good for CDNs/firewalls)"
        "wss (Secure WebSocket, encrypted)"
        "tcpmux (Multiplexed TCP)"
        "wsmux (Multiplexed WebSocket)"
        "wssmux (Multiplexed Secure WebSocket)"
        "udp (For UDP-based applications)"
    )
    local all_transport_choices=()
    for i in "${!transport_options_arr[@]}"; do
        all_transport_choices+=("$(($i + 1)). ${transport_options_arr[$i]}")
    done

    local quick_transport_choices=(
        "1. ${transport_options_arr[0]}" # tcp
        "2. ${transport_options_arr[1]}" # ws
        "3. ${transport_options_arr[2]}" # wss
        "4. Show all options"
    )
    local current_exit_details=("0" "Back to Main Menu") # Array: [key, text]

    _transport_help() {
        print_info "Transport Protocol Help:"
        echo " - tcp: Standard, fast, and reliable."
        echo " - ws: WebSocket, useful for proxying through CDNs like Cloudflare."
        echo " - wss: Secure WebSocket (TLS/SSL encrypted), also good for CDNs."
        echo " - *mux: Multiplexed versions allow multiple streams over one connection."
        echo " - udp: For applications requiring UDP (e.g., some games, VoIP)."
        press_any_key
    }

    if [[ "$setup_type_choice" -eq 1 ]]; then # Quick setup
        menu_loop "Select transport (Default: 1 for TCP)" quick_transport_choices current_exit_details "_transport_help"
        local menu_rc=$?
        case "$menu_rc" in
            3) go_to_main_menu; return 0 ;; 4) request_script_exit; return 0 ;;
            5) _prompt_setup_type_and_mode setup_type_choice_ref tunnel_mode_ref; return $? ;; # 'r' to go back to mode selection
            2) _prompt_transport_protocol "$setup_type_choice" transport_ref; return $? ;; # '?' to re-call
            0) if [[ "$MENU_CHOICE" == "0" ]]; then return_from_menu; return 0; fi
               : # No-op for other numeric choices handled by menu_rc=0
               ;;
            *) handle_error "ERROR" "Unhandled menu_loop code $menu_rc in quick transport selection"; return 1;;
        esac
        
        case "$MENU_CHOICE" in
            "1") : ; transport_ref="tcp" ;;
            "2") : ; transport_ref="ws" ;;
            "3") : ; transport_ref="wss" ;;
            "4") # Show all options
                : ; # Added colon for case "4"
                print_menu_header "secondary" "All Transport Protocols" "Step 3 of 5 (Detail)"
                menu_loop "Select transport (Default: 1 for TCP)" all_transport_choices current_exit_details "_transport_help"
                menu_rc=$?
                case "$menu_rc" in
                    3) : ; go_to_main_menu; return 0 ;;
                    4) : ; request_script_exit; return 0 ;;
                    5) : ; _prompt_transport_protocol "$setup_type_choice" transport_ref; return $? ;; # 'r' to go back to quick transport options
                    2) # Re-call this specific sub-part (all options)
                        : ; # Added colon
                        # This needs a slight restructure or a loop to show all options again.
                        # For now, this will re-call the parent _prompt_transport_protocol.
                        _prompt_transport_protocol "$setup_type_choice" transport_ref; return $? ;;
                    0) if [[ "$MENU_CHOICE" == "0" ]]; then return_from_menu; return 0; fi
                       : # No-op
                       ;;
                    *) : ; handle_error "ERROR" "Unhandled menu_loop code $menu_rc in all transport selection"; return 1;;
                esac

                if [[ "$MENU_CHOICE" -ge 1 && "$MENU_CHOICE" -le ${#transport_options_arr[@]} ]]; then
                    transport_ref=$(echo "${transport_options_arr[$(($MENU_CHOICE-1))]}" | awk '{print $1}')
                else
                    handle_error "ERROR" "Invalid transport selection from all options."; return 1;
                fi
                ;;
            *) handle_error "ERROR" "Invalid quick transport choice: $MENU_CHOICE."; return 1 ;;
        esac
    else # Advanced setup
        menu_loop "Select transport protocol" all_transport_choices current_exit_details "_transport_help"
        local menu_rc=$?
        case "$menu_rc" in
            3) go_to_main_menu; return 0 ;; 4) request_script_exit; return 0 ;;
            5) _prompt_setup_type_and_mode setup_type_choice_ref tunnel_mode_ref; return $? ;; # 'r' to go back to mode selection
            2) _prompt_transport_protocol "$setup_type_choice" transport_ref; return $? ;; # '?' to re-call
            0) if [[ "$MENU_CHOICE" == "0" ]]; then return_from_menu; return 0; fi
               : # No-op
               ;;
            *) handle_error "ERROR" "Unhandled menu_loop code $menu_rc in advanced transport selection"; return 1;;
        esac

        if [[ "$MENU_CHOICE" -ge 1 && "$MENU_CHOICE" -le ${#transport_options_arr[@]} ]]; then
            transport_ref=$(echo "${transport_options_arr[$(($MENU_CHOICE-1))]}" | awk '{print $1}')
        else
            handle_error "ERROR" "Invalid advanced transport selection: $MENU_CHOICE."; return 1;
        fi
    fi
    log_message "INFO" "Selected transport: $transport_ref"
    return 0
}

_prompt_basic_config_params() {
    local tunnel_mode="$1"      # "server" or "client"
    local -n listen_port_ref=$2 # Output for server mode
    local -n remote_ip_ref=$3   # Output for client mode
    local -n remote_port_ref=$4 # Output for client mode
    local -n local_fwd_port_ref=$5 # Output for client mode (local port to forward from)
    local -n auth_token_ref=$6  # Output: auth token

    print_menu_header "secondary" "Basic Configuration" "Step 4 of 5"

    if [[ "$tunnel_mode" == "server" ]]; then
        print_info "Server Mode: Configure listening port."
        local default_listen_port=443
        # Ensure SERVER_IP is available for port conflict check context if needed
        if [[ -z "$SERVER_IP" || "$SERVER_IP" == "N/A" ]]; then get_server_info; fi

        while true; do
            read -r -p "Enter port for Backhaul server to listen on (e.g., 443, 8080) [${default_listen_port}]: " listen_port_val
            listen_port_val=${listen_port_val:-$default_listen_port}
            if ! validate_port "$listen_port_val"; then
                print_warning "Invalid port number. Must be 1-65535."
            elif ! check_port_availability "$listen_port_val"; then
                print_warning "Port $listen_port_val is currently in use on this server."
                _get_port_process_info "$listen_port_val" # Show what's using it
                if ! prompt_yes_no "Use this port anyway (if the process is temporary or will be stopped)?" "n"; then
                    continue # Ask for port again
                fi
                listen_port_ref="$listen_port_val"
                break
            else
                listen_port_ref="$listen_port_val"
                print_success "Port $listen_port_ref is available."
                break
            fi
        done
    else # client mode
        print_info "Client Mode: Configure remote server details and local forwarding port."
        while true; do
            read -r -p "Enter the public IP address of the Backhaul SERVER: " remote_ip_val
            if validate_ip "$remote_ip_val"; then
                if prompt_yes_no "Ping $remote_ip_val to check reachability?" "y"; then
                    run_with_spinner "Pinging $remote_ip_val..." ping -c 2 -W 2 "$remote_ip_val"
                fi
                remote_ip_ref="$remote_ip_val"
                break
            else
                print_warning "Invalid IP address format."
            fi
        done
        
        local default_remote_port=443
        while true; do
            read -r -p "Enter the port the Backhaul SERVER is listening on [${default_remote_port}]: " remote_port_val
            remote_port_val=${remote_port_val:-$default_remote_port}
            if validate_port "$remote_port_val"; then
                remote_port_ref="$remote_port_val"
                break
            else
                print_warning "Invalid port number."
            fi
        done

        local default_local_fwd_port=1080 # Common for SOCKS or local proxy
        print_info "Enter the local port this client will listen on to forward traffic."
        while true; do
            read -r -p "Local forwarding port on THIS machine (e.g., 1080, 8000) [${default_local_fwd_port}]: " local_fwd_port_val
            local_fwd_port_val=${local_fwd_port_val:-$default_local_fwd_port}
            if ! validate_port "$local_fwd_port_val"; then
                print_warning "Invalid port number."
            elif ! check_port_availability "$local_fwd_port_val"; then
                print_warning "Port $local_fwd_port_val is currently in use on this machine."
                _get_port_process_info "$local_fwd_port_val"
                 if ! prompt_yes_no "Use this port anyway?" "n"; then
                    continue
                fi
                local_fwd_port_ref="$local_fwd_port_val"
                break
            else
                local_fwd_port_ref="$local_fwd_port_val"
                print_success "Local forwarding port $local_fwd_port_ref is available."
                break
            fi
        done
    fi

    # Auth Token
    local default_auth_token="EasyBackhaulSecretToken" # More descriptive default
    print_info "Set an authentication token (must match on both server and client)."
    while true; do
        read -r -s -p "Enter auth token (min 8 chars) [${default_auth_token}]: " auth_token_val
        echo # Newline after secret input
        auth_token_val=${auth_token_val:-$default_auth_token}
        if [[ "${#auth_token_val}" -lt 8 ]]; then
            print_warning "Token too short. Please use at least 8 characters for security."
        else
            auth_token_ref="$auth_token_val"
            break
        fi
    done
    return 0
}

_prompt_tls_config() {
    local transport="$1"
    local -n tls_cert_path_ref=$2
    local -n tls_key_path_ref=$3

    if [[ ! "$transport" =~ ^(wss|wssmux)$ ]]; then
        return 0 # No TLS needed
    fi

    print_menu_header "secondary" "TLS Certificate Configuration" "Secure Protocols (WSS/WSSMUX)"
    print_info "Secure protocols (WSS/WSSMUX) require a TLS certificate and private key."

    local cert_dir_global="${CERT_DIR:-/etc/easybackhaul/certs}" # From globals.sh
    ensure_dir "$cert_dir_global" "700"
    
    mapfile -t existing_certs < <(find "$cert_dir_global" -maxdepth 1 -name '*.pem' -o -name '*.crt' 2>/dev/null | sort)
    
    local tls_options=()
    local cert_map=() # Associative array to map choice number to path

    if [[ ${#existing_certs[@]} -gt 0 ]]; then
        print_info "Existing certificates/keys found in $cert_dir_global:"
        local count=1
        for cert_file in "${existing_certs[@]}"; do
            # Heuristic to find matching key: replace .crt/.pem with .key
            local potential_key_file="${cert_file%.*}.key"
            if [[ ! -f "$potential_key_file" ]]; then potential_key_file="${cert_file%.*}.pem"; fi # Some might use .pem for keys too

            if [[ -f "$potential_key_file" ]]; then
                 tls_options+=("$count. Use: $(basename "$cert_file") + $(basename "$potential_key_file")")
                 cert_map[$count]="$cert_file;$potential_key_file" # Store pair
                 ((count++))
            else
                print_warning "Certificate $(basename "$cert_file") found without a clearly matching .key file, skipping."
            fi
        done
    fi
    tls_options+=("$((${#cert_map[@]} + 1)). Generate New Self-Signed Certificate")
    local generate_new_opt_num=$((${#cert_map[@]} + 1))
    
    local current_exit_details=("0" "Skip TLS (Not Recommended for WSS/WSSMUX)") # Array: [key, text]
    _tls_help() {
        print_info "TLS Configuration Help:"
        echo " - Select an existing certificate/key pair if available."
        echo " - Choose 'Generate New' to create a self-signed certificate."
        echo " - Skipping TLS for WSS/WSSMUX will likely cause connection failures."
        echo " - Certificate paths are stored in the tunnel's TOML config file."
        press_any_key
    }

    menu_loop "Select TLS certificate option" tls_options current_exit_details "_tls_help"
    local menu_rc=$?
    local user_choice="$MENU_CHOICE" # Capture choice before potential navigation

    case "$menu_rc" in
        3) go_to_main_menu; return 0 ;; 4) request_script_exit; return 0 ;;
        5) _prompt_basic_config_params "$tunnel_mode" server_listen_port client_remote_ip client_remote_port client_local_fwd_port common_auth_token; return $? ;; # 'r' to go back to basic params
        2) _prompt_tls_config "$transport" tls_cert_path_ref tls_key_path_ref; return $? ;; # '?' to re-call
        0) # Numeric choice or default exit "0"
           # Proceed to specific choice handling below
           : # No-op, allow execution to continue after the case statement
           ;;
        *) handle_error "ERROR" "Unhandled menu_loop code $menu_rc in TLS config"; return 1;;
    esac

    if [[ "$user_choice" == "0" ]]; then # Default exit for this menu (Skip TLS)
        print_warning "Skipping TLS configuration. WSS/WSSMUX will likely not work without it."
        tls_cert_path_ref=""
        tls_key_path_ref=""
        return 0
    elif (( MENU_CHOICE == generate_new_opt_num )); then
        if generate_self_signed_tls_cert; then # Uses its own internal prompts
            # Need to find the newest cert/key pair generated
            local new_cert=$(find "$cert_dir_global" -name '*.pem' -o -name '*.crt' -print0 | xargs -0 stat -c "%Y %n" | sort -nr | head -n1 | awk '{print $2}')
            local new_key="${new_cert%.*}.key" # Assuming .key based on generate_self_signed_tls_cert
             if [[ ! -f "$new_key" ]]; then new_key="${new_cert%.*}.pem"; fi


            if [[ -f "$new_cert" && -f "$new_key" ]]; then
                tls_cert_path_ref="$new_cert"
                tls_key_path_ref="$new_key"
                print_success "Using newly generated cert: $tls_cert_path_ref and key: $tls_key_path_ref"
            else
                handle_error "ERROR" "Failed to identify newly generated certificate/key pair."
                return 1
            fi
        else
            handle_error "ERROR" "Self-signed certificate generation failed."
            return 1
        fi
    elif [[ -n "${cert_map[$MENU_CHOICE]}" ]]; then
        IFS=';' read -r tls_cert_path_ref tls_key_path_ref <<< "${cert_map[$MENU_CHOICE]}"
        print_success "Using selected cert: $tls_cert_path_ref and key: $tls_key_path_ref"
    else
        handle_error "ERROR" "Invalid TLS certificate selection."
        return 1
    fi
    return 0
}

# --- Main Configuration Wizard ---
configure_tunnel() {
    # Initialize local variables to store configuration parameters
    local setup_is_advanced=false # Default to quick setup
    local tunnel_mode=""          # "server" or "client"
    local transport_protocol=""

    local server_listen_port=""   # For server mode
    local client_remote_ip=""     # For client mode
    local client_remote_port=""   # For client mode
    local client_local_fwd_port="" # For client mode
    local common_auth_token=""

    local cfg_tls_cert_path=""
    local cfg_tls_key_path=""

    # Advanced parameters with defaults
    local cfg_log_level="info"
    local cfg_sniffer="false"
    local cfg_sniffer_log="/var/log/easybackhaul/$(date +%s%N)-sniffer.json" # Default, needs tunnel name later
    local cfg_web_port=0
    local cfg_nodelay="true" # Common for TCP-based
    local cfg_keepalive_period=75
    # Server specific advanced
    local cfg_heartbeat=40
    local cfg_channel_size=2048
    local cfg_accept_udp="false" # Only for TCP server
    # Client specific advanced
    local cfg_connection_pool=8
    local cfg_aggressive_pool="false"
    local cfg_retry_interval=3
    local cfg_dial_timeout=10
    # MUX specific advanced
    local cfg_mux_con=8
    local cfg_mux_version=1 # Default to SMUX v1 usually
    local cfg_mux_framesize=32768
    local cfg_mux_receivebuffer=4194304 # Renamed from recieve to receive
    local cfg_mux_streambuffer=65536

    # --- Step 1 & 2: Setup Type (Quick/Advanced) and Mode (Server/Client) ---
    local setup_choice_val
    if ! _prompt_setup_type_and_mode setup_choice_val tunnel_mode; then
        # Handles navigation/exit signals from menu_loop
        if [[ "$CURRENT_MENU_FUNCTION" == "main_menu" || -z "$CURRENT_MENU_FUNCTION" ]]; then return_from_menu; fi
        return # Propagate exit/back to main menu loop
    fi
    [[ "$setup_choice_val" -eq 2 ]] && setup_is_advanced=true
    log_message "INFO" "Setup type: $(if $setup_is_advanced; then echo "Advanced"; else echo "Quick"; fi), Mode: $tunnel_mode"

    # --- Step 3: Transport Protocol ---
    if ! _prompt_transport_protocol "$setup_choice_val" transport_protocol; then
        if [[ "$CURRENT_MENU_FUNCTION" == "main_menu" || -z "$CURRENT_MENU_FUNCTION" ]]; then return_from_menu; fi
        return
    fi

    # --- Step 4: Basic Configuration (Ports, IP, Token) ---
    if ! _prompt_basic_config_params "$tunnel_mode" \
        server_listen_port client_remote_ip client_remote_port client_local_fwd_port \
        common_auth_token; then
        if [[ "$CURRENT_MENU_FUNCTION" == "main_menu" || -z "$CURRENT_MENU_FUNCTION" ]]; then return_from_menu; fi
        return
    fi

    # --- Step 5 (Conditional): Advanced Configuration ---
    if $setup_is_advanced; then
        # This would call a new sub-function: _prompt_advanced_parameters
        # For now, we'll just note that it would happen here.
        # _prompt_advanced_parameters "$tunnel_mode" "$transport_protocol" cfg_log_level ... (all cfg_* vars by ref)
        print_info "Advanced parameter prompting would occur here." # Placeholder
        # This part needs to be fully implemented similar to other _prompt_* functions
        # For brevity in this refactoring phase, we'll use defaults for advanced if not explicitly prompted
        log_message "INFO" "Advanced setup chosen - advanced parameters would be prompted here."
    fi
    
    # --- Step 6 (Conditional): TLS Configuration ---
    if [[ "$transport_protocol" =~ ^(wss|wssmux)$ ]]; then
        if ! _prompt_tls_config "$transport_protocol" cfg_tls_cert_path cfg_tls_key_path; then
             if [[ "$CURRENT_MENU_FUNCTION" == "main_menu" || -z "$CURRENT_MENU_FUNCTION" ]]; then return_from_menu; fi
             return
        fi
        if [[ -z "$cfg_tls_cert_path" || -z "$cfg_tls_key_path" ]]; then
            print_warning "WSS/WSSMUX selected but TLS cert/key not configured. Tunnel may not work."
        fi
    fi

    # --- Step 7: Configuration Summary & Confirmation ---
    print_menu_header "secondary" "Configuration Summary" "Review and Confirm"
    echo "  Mode: $tunnel_mode"
    echo "  Transport: $transport_protocol"
    if [[ "$tunnel_mode" == "server" ]]; then
        echo "  Listen Port: $server_listen_port"
    else # client
        echo "  Remote Server: $client_remote_ip:$client_remote_port"
        echo "  Local Forward Port: $client_local_fwd_port"
    fi
    echo "  Auth Token: [set]" # Don't display token
    
    if $setup_is_advanced; then
        echo "  --- Advanced Settings ---"
        echo "  Log Level: $cfg_log_level"
        # ... print other advanced settings ...
    fi
    if [[ -n "$cfg_tls_cert_path" ]]; then
        echo "  TLS Certificate: $cfg_tls_cert_path"
        echo "  TLS Key: $cfg_tls_key_path"
    fi
    
    if ! prompt_yes_no "Proceed with this configuration?" "y"; then
        print_info "Configuration cancelled."
        press_any_key
        return_from_menu # Or go_to_main_menu
        return
    fi

    # --- Step 8: Generate Tunnel Name and Save Configuration ---
    local tunnel_name_suffix
    tunnel_name_suffix="${tunnel_mode}-${transport_protocol}-$(date +%s | tail -c 5)" # Shorter timestamp part
    local final_tunnel_name="bh-$tunnel_name_suffix" # Prefix for clarity
    
    local config_file_path="$CONFIG_DIR/config-${final_tunnel_name}.toml"
    ensure_dir "$CONFIG_DIR" # From helpers.sh
    
    # Start building TOML content
    # Using printf for TOML generation for more control over quoting and types
    # Clear file first
    : > "$config_file_path"

    update_toml_value "$config_file_path" "mode" "$tunnel_mode" "string"
    update_toml_value "$config_file_path" "transport" "$transport_protocol" "string"
    update_toml_value "$config_file_path" "auth_token" "$common_auth_token" "string"

    if [[ "$tunnel_mode" == "server" ]]; then
        update_toml_value "$config_file_path" "listen" ":$server_listen_port" "string"
    else # client
        update_toml_value "$config_file_path" "server" "${client_remote_ip}:${client_remote_port}" "string"
        update_toml_value "$config_file_path" "local" ":$client_local_fwd_port" "string"
    fi

    if $setup_is_advanced; then
        update_toml_value "$config_file_path" "log_level" "$cfg_log_level" "string"
        update_toml_value "$config_file_path" "sniffer" "$cfg_sniffer" "boolean"
        if [[ "$cfg_sniffer" == "true" ]]; then
             local final_sniffer_log="/var/log/easybackhaul/${final_tunnel_name}-sniffer.json"
             update_toml_value "$config_file_path" "sniffer_log" "$final_sniffer_log" "string"
        fi
        if (( cfg_web_port > 0 )); then
            update_toml_value "$config_file_path" "web_port" "$cfg_web_port" "numeric"
        fi
        # ... and so on for all advanced parameters using update_toml_value
        # Example for nodelay:
        if [[ "$transport_protocol" != "udp" ]]; then # nodelay is TCP specific
             update_toml_value "$config_file_path" "nodelay" "$cfg_nodelay" "boolean"
             update_toml_value "$config_file_path" "keepalive_period" "$cfg_keepalive_period" "numeric"
        fi
        # ... etc. for all advanced params ...
    fi

    if [[ -n "$cfg_tls_cert_path" && -n "$cfg_tls_key_path" ]]; then
        update_toml_value "$config_file_path" "tls_cert" "$cfg_tls_cert_path" "string"
        update_toml_value "$config_file_path" "tls_key" "$cfg_tls_key_path" "string"
    fi
    
    set_secure_file_permissions "$config_file_path" "600"
    handle_success "Configuration saved: $config_file_path"

    # --- Step 9: Post-creation (Systemd, Start) ---
    # create_systemd_service is in systemd.sh, ensure it's sourced/available
    if type create_systemd_service &>/dev/null; then
        if create_systemd_service "$final_tunnel_name" "$config_file_path"; then # create_systemd_service should handle its own success/error messages
            if prompt_yes_no "Start the tunnel '$final_tunnel_name' now?" "y"; then
                if run_with_spinner "Starting tunnel $final_tunnel_name..." systemctl start "backhaul-${final_tunnel_name}.service"; then
                    handle_success "Tunnel '$final_tunnel_name' started."
                else
                    handle_error "ERROR" "Failed to start tunnel '$final_tunnel_name'. Check logs: journalctl -u backhaul-${final_tunnel_name}.service"
                fi
            else
                print_info "Tunnel '$final_tunnel_name' created but not started."
            fi
        else
             handle_error "ERROR" "Failed to create systemd service for '$final_tunnel_name'."
        fi
    else
        handle_error "WARNING" "Function 'create_systemd_service' not found. Cannot create service automatically."
    fi
    
    press_any_key
    return_from_menu # Return to the menu that called configure_tunnel
}


# --- Decommissioned/Old Functions ---
# update_config_file() { log_message "WARN" "DEPRECATED: update_config_file called. Use TOML-based config."; }
# remove_from_config() { log_message "WARN" "DEPRECATED: remove_from_config called. Use TOML-based config."; }
# backup_configuration() { log_message "WARN" "DEPRECATED: backup_configuration called. Use backup_configuration_path from helpers.sh."; }
# restore_configuration() { log_message "WARN" "DEPRECATED: restore_configuration called."; }
# export_configuration() { log_message "WARN" "DEPRECATED: export_configuration called."; }
# configure_advanced_settings() { log_message "WARN" "DEPRECATED: configure_advanced_settings called."; }


true # Ensure script is valid if sourced.

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
# modules/ufw.sh
# UFW (Uncomplicated Firewall) management functions.

# --- UFW Rule Management for Tunnels ---

# Adds a UFW rule for a specific tunnel port.
# Parameters:
#   $1: port - The port number.
#   $2: transport - "tcp" or "udp".
#   $3: tunnel_suffix - Unique identifier for the tunnel (e.g., server-tcp-timestamp).
#                       Used in the UFW rule comment for identification.
# This function is typically called when a new tunnel is configured.
add_ufw_rule_for_tunnel() {
    local port="$1"
    local transport_protocol="$2" # Should be "tcp" or "udp"
    local tunnel_suffix="$3"

    if ! command -v ufw &>/dev/null; then
        log_message "WARN" "UFW is not installed. Skipping firewall rule addition for port $port/$transport_protocol."
        return 1
    fi

    local ufw_status_output
    ufw_status_output=$(ufw status)
    if ! echo "$ufw_status_output" | grep -q "Status: active"; then
        log_message "WARN" "UFW is not active."
        if prompt_yes_no "UFW is inactive. Enable UFW and add required SSH/tunnel rules?" "n"; then
            _enable_ufw_with_ssh_allow # Call helper to enable UFW and allow SSH
        else
            log_message "WARN" "User chose not to enable UFW. Skipping firewall rule addition for port $port/$transport_protocol."
            return 1
        fi
    fi

    local ufw_comment="EasyBackhaul: tunnel-${tunnel_suffix}"
    log_message "INFO" "Adding UFW rule: allow $port/$transport_protocol (Comment: $ufw_comment)"

    if run_with_spinner "Adding UFW rule for port $port/$transport_protocol..." \
        ufw allow "$port/$transport_protocol" comment "$ufw_comment"; then
        if run_with_spinner "Reloading UFW..." ufw reload; then
            handle_success "UFW rule for port $port/$transport_protocol added and UFW reloaded."
            return 0
        else
            handle_error "ERROR" "Failed to reload UFW after adding rule for port $port/$transport_protocol."
            return 1
        fi
    else
        handle_error "ERROR" "Failed to add UFW rule for port $port/$transport_protocol. Please add it manually."
        return 1
    fi
}

# Deletes UFW rules associated with a specific tunnel suffix.
# Parameters:
#   $1: tunnel_suffix - Unique identifier for the tunnel.
# This function is typically called when a tunnel is deleted.
delete_ufw_rules_for_tunnel() {
    local tunnel_suffix="$1"

    if ! command -v ufw &>/dev/null; then
        log_message "WARN" "UFW is not installed. Skipping firewall rule removal for tunnel $tunnel_suffix."
        return 1
    fi
    
    local ufw_status_output
    ufw_status_output=$(ufw status)
    if ! echo "$ufw_status_output" | grep -q "Status: active"; then
        log_message "INFO" "UFW is not active. No rules to remove for tunnel $tunnel_suffix."
        return 0
    fi

    local ufw_comment_pattern="EasyBackhaul: tunnel-${tunnel_suffix}"
    log_message "INFO" "Searching for UFW rules to delete with comment pattern: '$ufw_comment_pattern'"

    local rules_deleted_count=0
    # Loop to delete rules by number, as rule numbers change after each deletion.
    # We get all matching rules, sort them in reverse order, and delete.
    while true; do
        local rule_to_delete_num
        # Get the highest rule number that matches the comment
        rule_to_delete_num=$(ufw status numbered | grep -F "$ufw_comment_pattern" | head -n 1 | awk -F'[][]' '{print $2}')
        
        if [[ -z "$rule_to_delete_num" ]]; then
            break # No more rules found with this comment
        fi

        log_message "INFO" "Deleting UFW rule #$rule_to_delete_num (comment: $ufw_comment_pattern)"
        if echo "y" | ufw delete "$rule_to_delete_num"; then # Auto-confirm deletion
            log_message "DEBUG" "Successfully deleted UFW rule #$rule_to_delete_num."
            ((rules_deleted_count++))
        else
            handle_error "ERROR" "Failed to delete UFW rule #$rule_to_delete_num. You may need to remove it manually."
            # Potentially break here or try to continue, depending on desired robustness
        fi
    done

    if (( rules_deleted_count > 0 )); then
        if run_with_spinner "Reloading UFW..." ufw reload; then
            handle_success "Deleted $rules_deleted_count UFW rule(s) for tunnel $tunnel_suffix and reloaded UFW."
        else
            handle_error "ERROR" "Failed to reload UFW after deleting rules for tunnel $tunnel_suffix."
        fi
    elif [[ -z "$rule_to_delete_num" ]]; then # Check if any rule was found initially
        log_message "INFO" "No UFW rules found with comment pattern '$ufw_comment_pattern' for tunnel $tunnel_suffix."
    fi
    return 0
}


# --- UFW General Management Menu & Functions ---

_ufw_menu_help() {
    print_menu_header "secondary" "UFW Firewall Management Help"
    echo "This menu allows you to manage the UFW (Uncomplicated Firewall) on your system."
    echo
    print_info "Options:"
    echo "  1. Enable UFW: Activates the firewall. Ensures SSH is allowed."
    echo "  2. Disable UFW: Deactivates the firewall (not recommended)."
    echo "  3. View Status: Shows current UFW status and rules."
    echo "  4. Reset UFW: Disables UFW and deletes ALL rules (use with caution)."
    echo "  5. Clean Orphaned Rules: Removes EasyBackhaul rules for non-existent tunnels."
    echo
    print_info "Important Notes:"
    echo " - Enabling UFW without allowing SSH can lock you out of your server."
    echo " - This script attempts to allow common SSH ports when enabling UFW."
    echo " - Tunnel configurations automatically add/remove their specific UFW rules if UFW is active."
    press_any_key
}

# Main menu for UFW management
manage_ufw_main_menu() {
    local ufw_menu_options=(
        "1. Enable UFW Firewall"
        "2. Disable UFW Firewall"
        "3. View UFW Status & Rules"
        "4. Reset UFW (Deletes ALL rules)"
        "5. Clean Orphaned EasyBackhaul Rules"
    )
    local ufw_exit_details=("0" "Back to Main Menu") # Array: [key, text]
    local user_choice menu_rc

    while true; do
        local ufw_current_status="Inactive"
        if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then # Added 2>/dev/null for ufw status
            ufw_current_status="Active"
        elif ! command -v ufw &>/dev/null; then
            ufw_current_status="Not Installed"
        fi
        print_menu_header "primary" "UFW Firewall Management" "Status: $ufw_current_status"
        
        menu_loop "Select UFW option" ufw_menu_options ufw_exit_details "_ufw_menu_help"
        user_choice="$MENU_CHOICE" # menu_loop sets MENU_CHOICE
        menu_rc=$?                # menu_loop returns status code
        
        # Handle universal navigation keys based on menu_rc
        case "$menu_rc" in
            3) go_to_main_menu; return 0 ;; # m -> main menu
            4) request_script_exit; return 0 ;; # e -> exit script
            5) return_from_menu; return 0 ;; # r -> return/back (to previous menu)
            2) continue ;; # ? -> help was shown, re-loop current menu
            0) # Numeric choice or default exit "0"
               # Proceed to specific choice handling below
               ;;
            *) handle_error "ERROR" "Unhandled menu_loop code $menu_rc in manage_ufw_main_menu"; press_any_key; continue ;;
        esac

        # Handle numeric choices and the specific default exit ("0")
        case "$user_choice" in
            "1") _enable_ufw_with_ssh_allow ;;
            "2") _disable_ufw ;;
            "3") _view_ufw_status ;;
            "4") _reset_ufw ;;
            "5") _clean_orphaned_ufw_rules ;;
            "0") return_from_menu; return 0 ;; # Default exit for this menu
            *) print_warning "Invalid option. Please try again."; press_any_key ;;
        esac
    done
}

_enable_ufw_with_ssh_allow() {
    print_menu_header "secondary" "Enable UFW Firewall"
    if ! command -v ufw &>/dev/null; then
        handle_error "ERROR" "UFW command not found. Please install UFW first."
        press_any_key
        return 1
    fi

    if ufw status | grep -q "Status: active"; then
        handle_success "UFW is already active."
        press_any_key
        return 0
    fi

    print_warning "Enabling UFW may block SSH access if not configured properly."
    print_info "This script will attempt to allow common SSH ports (22 and any custom SSH port found)."
    if ! prompt_yes_no "Proceed with enabling UFW?" "y"; then
        print_info "UFW enable cancelled."
        press_any_key
        return 1
    fi

    # Allow SSH - find common and configured SSH ports
    local ssh_ports_to_allow=("22") # Default SSH port
    if [[ -f /etc/ssh/sshd_config ]]; then
        local custom_ssh_port
        custom_ssh_port=$(grep -E "^Port\s+[0-9]+" /etc/ssh/sshd_config | awk '{print $2}' | head -n1)
        if [[ -n "$custom_ssh_port" && "$custom_ssh_port" != "22" ]]; then
            ssh_ports_to_allow+=("$custom_ssh_port")
        fi
    fi
    # Also check currently listening SSHD ports
    if command -v ss &>/dev/null; then
         local listening_ssh_ports
         listening_ssh_ports=$(ss -tlpn | grep sshd | awk '{print $4}' | sed 's/.*://' | sort -u)
         for port in $listening_ssh_ports; do
             if [[ ! " ${ssh_ports_to_allow[*]} " =~ " ${port} " ]]; then # Check if port already in array
                 ssh_ports_to_allow+=("$port")
             fi
         done
    fi

    for port in "${ssh_ports_to_allow[@]}"; do
        if validate_port "$port"; then # from helpers.sh
            log_message "INFO" "Allowing SSH on port $port/tcp in UFW..."
            if ! run_with_spinner "Allowing port $port/tcp (SSH)..." ufw allow "$port/tcp" comment "SSH access (EasyBackhaul)"; then
                handle_error "WARNING" "Failed to add UFW rule for SSH on port $port/tcp."
            fi
        fi
    done

    if run_with_spinner "Enabling UFW..." ufw --force enable; then # --force to enable without prompt
        handle_success "UFW enabled successfully."
    else
        handle_error "ERROR" "Failed to enable UFW. Check UFW logs or status."
    fi
    press_any_key
}

_disable_ufw() {
    print_menu_header "secondary" "Disable UFW Firewall"
    if ! command -v ufw &>/dev/null; then
        handle_error "ERROR" "UFW command not found."
        press_any_key
        return 1
    fi

    if ! ufw status | grep -q "Status: active"; then
        handle_warning "UFW is already inactive."
        press_any_key
        return 0
    fi
    
    print_warning "Disabling UFW will remove firewall protection from this server."
    if ! prompt_yes_no "Are you sure you want to disable UFW?" "n"; then
        print_info "UFW disable cancelled."
        press_any_key
        return 1
    fi

    if run_with_spinner "Disabling UFW..." ufw disable; then
        handle_success "UFW disabled successfully."
    else
        handle_error "ERROR" "Failed to disable UFW."
    fi
    press_any_key
}

_view_ufw_status() {
    print_menu_header "secondary" "UFW Status & Rules"
    if ! command -v ufw &>/dev/null; then
        handle_error "ERROR" "UFW command not found."
        press_any_key
        return 1
    fi

    if ! ufw status | grep -q "Status: active"; then
        handle_warning "UFW is not active."
    else
        print_success "UFW is active."
    fi
    echo
    print_info "Current UFW Rules (numbered):"
    ufw status numbered
    echo
    print_info "EasyBackhaul specific rules are typically commented with 'EasyBackhaul: tunnel-<name>'."
    press_any_key
}

_reset_ufw() {
    print_menu_header "secondary" "Reset UFW Firewall"
     if ! command -v ufw &>/dev/null; then
        handle_error "ERROR" "UFW command not found."
        press_any_key
        return 1
    fi

    print_warning "WARNING: This will disable UFW and delete ALL existing rules."
    print_warning "This action is irreversible and will remove all firewall protection."
    if ! prompt_yes_no "ARE YOU ABSOLUTELY SURE you want to reset UFW?" "n"; then
        print_info "UFW reset cancelled."
        press_any_key
        return 1
    fi
    
    # Second confirmation for such a destructive action
    read -r -p "Type 'CONFIRM RESET UFW' to proceed: " confirmation_text
    if [[ "$confirmation_text" != "CONFIRM RESET UFW" ]]; then
        print_info "Confirmation failed. UFW reset cancelled."
        press_any_key
        return 1
    fi

    if run_with_spinner "Resetting UFW (disabling and deleting all rules)..." ufw --force reset; then
        handle_success "UFW has been reset to its default (inactive) state. All rules deleted."
    else
        handle_error "ERROR" "Failed to reset UFW."
    fi
    press_any_key
}

_clean_orphaned_ufw_rules() {
    print_menu_header "secondary" "Clean Orphaned EasyBackhaul UFW Rules"
    if ! command -v ufw &>/dev/null; then
        handle_error "ERROR" "UFW command not found."
        press_any_key
        return 1
    fi
    if ! ufw status | grep -q "Status: active"; then
        handle_warning "UFW is not active. No rules to clean."
        press_any_key
        return 0
    fi

    log_message "INFO" "Scanning for orphaned EasyBackhaul UFW rules..."
    local ufw_comment_base="EasyBackhaul: tunnel-"
    
    local orphaned_rule_numbers=()
    # Get all rules with EasyBackhaul comments
    # Use process substitution and a while read loop for safer parsing
    while IFS= read -r line; do
        # Extract rule number and comment
        local rule_num comment
        rule_num=$(echo "$line" | awk -F'[][]' '{print $2}')
        comment=$(echo "$line" | sed -n 's/.*comment '"'"'\([^'"'"']*\)'"'"'.*/\1/p')

        if [[ -n "$rule_num" && "$comment" == ${ufw_comment_base}* ]]; then
            local tunnel_suffix
            tunnel_suffix=${comment#${ufw_comment_base}} # Extract suffix from comment
            local tunnel_config_file="$CONFIG_DIR/config-${tunnel_suffix}.toml" # Adjusted to new name format

            if [[ -n "$tunnel_suffix" && ! -f "$tunnel_config_file" ]]; then
                log_message "WARN" "Found orphaned UFW rule #$rule_num for non-existent tunnel '$tunnel_suffix' (Comment: '$comment')."
                orphaned_rule_numbers+=("$rule_num")
            fi
        fi
    done < <(ufw status numbered)

    if [[ ${#orphaned_rule_numbers[@]} -eq 0 ]]; then
        handle_success "No orphaned EasyBackhaul UFW rules found."
        press_any_key
        return 0
    fi

    print_warning "Found ${#orphaned_rule_numbers[@]} orphaned UFW rule(s) linked to deleted tunnels:"
    # Displaying rules again for confirmation can be tricky as numbers might shift if user manually deletes.
    # Best to show the numbers found now.
    for num in "${orphaned_rule_numbers[@]}"; do
        echo "  - Rule #$num"
    done
    echo
    if ! prompt_yes_no "Delete these ${#orphaned_rule_numbers[@]} orphaned rule(s)?" "n"; then
        print_info "Orphaned rule cleanup cancelled."
        press_any_key
        return 1
    fi

    local deleted_count=0
    # Sort numbers in reverse order for deletion to avoid shifting rule numbers
    local sorted_orphans
    IFS=$'\n' sorted_orphans=($(sort -nr <<<"${orphaned_rule_numbers[*]}"))
    unset IFS

    for rule_num_to_delete in "${sorted_orphans[@]}"; do
        log_message "INFO" "Deleting orphaned UFW rule #$rule_num_to_delete."
        if echo "y" | ufw delete "$rule_num_to_delete"; then
            ((deleted_count++))
        else
            handle_error "ERROR" "Failed to delete orphaned UFW rule #$rule_num_to_delete."
        fi
    done

    if (( deleted_count > 0 )); then
        if run_with_spinner "Reloading UFW..." ufw reload; then
            handle_success "Successfully deleted $deleted_count orphaned UFW rule(s) and reloaded UFW."
        else
            handle_error "ERROR" "Failed to reload UFW after deleting orphaned rules."
        fi
    else
        print_info "No orphaned rules were deleted."
    fi
    press_any_key
}

true # Ensure script is valid
# --- MODULE: modules/systemd.sh ---
# modules/systemd.sh
# Systemd service creation and management 

# --- Systemd Service Management ---
# Creates and manages a systemd service for a given tunnel.
# Parameters:
#   $1: name_suffix - The unique suffix for the tunnel (e.g., server-tcp-timestamp)
#   $2: config_path - Full path to the tunnel's TOML configuration file
#   $3: (Optional) user - User to run the service as (defaults to current user or root if not specified)
#   $4: (Optional) group - Group to run the service as (defaults to current user or root if not specified)
create_systemd_service() {
    local name_suffix="$1"
    local config_path="$2"
    local service_user="${3:-}" # User to run as
    local service_group="${4:-}" # Group to run as

    # Ensure SERVICE_DIR and BIN_PATH are available (should be from globals.sh)
    if [[ -z "$SERVICE_DIR" || -z "$BIN_PATH" ]]; then
        handle_error "CRITICAL" "SERVICE_DIR or BIN_PATH not defined. Cannot create systemd service."
        return 1
    fi

    local service_name="backhaul-${name_suffix}.service"
    local service_file_path="${SERVICE_DIR}/${service_name}"

    if ! command -v systemctl &>/dev/null; then
        handle_error "WARNING" "Systemd (systemctl) not found on this system."
        print_info "A persistent service cannot be automatically created."
        print_info "To run the tunnel manually (for testing), you can use:"
        print_info "  $BIN_PATH -c \"$config_path\""
        print_info "For persistence without systemd, consider 'nohup', 'screen', 'tmux', or your system's init."
        if prompt_yes_no "Run the tunnel in the foreground for this session (for testing)?" "n"; then
            log_message "INFO" "Attempting to run tunnel in foreground: $BIN_PATH -c \"$config_path\""
            "$BIN_PATH" -c "$config_path" # This will block until Ctrl+C
        fi
        return 1 # Indicate service was not created
    fi

    log_message "INFO" "Creating systemd service file: $service_file_path for tunnel $name_suffix"

    # Determine User and Group for the service
    # If not provided, and script is run as root, use 'nobody' or a dedicated user if exists.
    # If script is not root, it will likely fail to write to /etc/systemd/system anyway.
    local effective_user="$service_user"
    local effective_group="$service_group"

    if [[ "$(id -u)" -eq 0 ]]; then # Running as root
        if [[ -z "$effective_user" ]]; then effective_user="nobody"; fi
        if [[ -z "$effective_group" ]]; then effective_group="nogroup"; fi # or 'nobody' depending on distro
        # Check if user 'nobody' exists, else use current user if not root (which it is)
        if ! id -u "$effective_user" >/dev/null 2>&1; then
            log_message "WARN" "User '$effective_user' not found, service will run as root. Consider creating a dedicated user."
            effective_user="root"
            effective_group="root"
        fi
    elif [[ -n "$effective_user" ]]; then
         log_message "WARN" "Running as non-root. Service User/Group might not be applied effectively by systemd unless root manages it."
    fi


    # Ensure the directory for service files exists
    ensure_dir "$(dirname "$service_file_path")" "755" # Systemd service dir usually root owned

    # Create the service file content
    # Added User and Group. Increased LimitNOFILE. Added some hardening.
    cat > "$service_file_path" <<EOL
[Unit]
Description=Backhaul Tunnel Service (${name_suffix})
Documentation=https://github.com/Musixal/Backhaul
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=simple
ExecStart=${BIN_PATH} -c "${config_path}"
Restart=always
RestartSec=5s
TimeoutStopSec=10s
LimitNOFILE=1048576
$( [[ -n "$effective_user" ]] && echo "User=${effective_user}" )
$( [[ -n "$effective_group" ]] && echo "Group=${effective_group}" )

# Security Hardening Options (optional, but good practice)
# ProtectSystem=full
# ProtectHome=true
# PrivateTmp=true
# NoNewPrivileges=true
# ReadWritePaths=${CONFIG_DIR} ${LOG_DIR} # Paths Backhaul needs to write to, adjust as needed
# CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW # Example, adjust to minimum required

[Install]
WantedBy=multi-user.target
EOL

    if ! run_with_spinner "Reloading systemd daemon..." systemctl daemon-reload; then
        handle_error "ERROR" "Failed to reload systemd daemon. Service file might be invalid: $service_file_path"
        return 1
    fi

    log_message "INFO" "Enabling service $service_name..."
    if ! run_with_spinner "Enabling service $service_name..." systemctl enable "$service_name"; then
        handle_error "ERROR" "Failed to enable service $service_name. Check systemd logs."
        # Attempt to show specific error if possible
        journalctl -u "$service_name" -n 5 --no-pager
        return 1
    fi

    log_message "INFO" "Starting service $service_name..."
    if ! run_with_spinner "Starting service $service_name..." systemctl start "$service_name"; then
        handle_error "ERROR" "Failed to start service $service_name."
        print_info "Check configuration and logs: journalctl -u $service_name -n 50 --no-pager"
        if prompt_yes_no "Show last 20 lines of the service log now?" "y"; then
            journalctl -u "$service_name" -n 20 --no-pager
        fi
        return 1
    fi

    handle_success "Service $service_name created, enabled, and started."

    if prompt_yes_no "Check service status now?" "y"; then
        systemctl status "$service_name" --no-pager
    fi
    return 0
}
true # Ensure script is valid
# --- MODULE: modules/cron.sh ---
# modules/cron.sh
# Cron job management for auto-restart of services.

# --- Cron Management ---

# Local helper for cron menu help text
_manage_cron_menu_help() {
    print_menu_header "secondary" "Cron Auto-Restart Help" "Service: $1" # Pass service name for context
    echo "Cron jobs can automatically restart your tunnel service at regular intervals."
    echo "This helps ensure the tunnel remains operational even if it encounters an issue."
    echo
    print_info "Available Intervals:"
    echo "  - Every 15 Minutes: Frequent restarts, useful for potentially unstable connections."
    echo "  - Every Hour: A balanced approach."
    echo "  - Every 6 Hours: Less frequent, suitable for generally stable connections."
    echo "  - Every 24 Hours: Daily restart, minimal operational overhead."
    echo "  - Custom: Define your own restart interval in minutes."
    echo
    print_info "Important Notes:"
    echo "  - Only one auto-restart cron job can be active per service at a time."
    echo "  - Setting a new job will replace any existing EasyBackhaul-managed cron job for this service."
    echo "  - Cron jobs are identified by the comment tag: '$CRON_COMMENT_TAG'"
    press_any_key
}

# Main menu for managing cron jobs for a specific service
manage_cron_job_for_service() {
    local service_name="$1" # e.g., backhaul-server-tcp-xxxx

    if [[ -z "$service_name" ]]; then
        handle_error "ERROR" "Service name not provided to manage_cron_job_for_service."
        return 1
    fi
    # Ensure CRON_COMMENT_TAG is available (from globals.sh)
    if [[ -z "$CRON_COMMENT_TAG" ]]; then
        handle_error "CRITICAL" "CRON_COMMENT_TAG is not defined. Cannot manage cron jobs."
        return 1
    fi

    local current_cron_job
    local cron_menu_options=(
        "1. Set/Update: Every 15 Minutes"
        "2. Set/Update: Every Hour"
        "3. Set/Update: Every 6 Hours"
        "4. Set/Update: Every 24 Hours"
        "5. Set/Update: Custom Interval (minutes)"
        "6. Remove Auto-Restart Cron Job"
    )
    local cron_exit_details=("0" "Back to Tunnel Management") # Array: [key, text]
    local user_choice menu_rc

    while true; do
        print_menu_header "secondary" "Cron Auto-Restart Management" "Service: $service_name"
        
        current_cron_job=$(crontab -l 2>/dev/null | grep -F "$service_name" | grep -F "# $CRON_COMMENT_TAG")
        if [[ -n "$current_cron_job" ]]; then
            print_success "Current Cron Job: $current_cron_job"
        else
            print_warning "No EasyBackhaul-managed cron job found for this service."
        fi
        echo

        # Pass service_name to the help function for context
        menu_loop "Select option" cron_menu_options cron_exit_details "_manage_cron_menu_help \"$service_name\""
        user_choice="$MENU_CHOICE" # menu_loop sets MENU_CHOICE
        menu_rc=$?                # menu_loop returns status code
        
        # Handle universal navigation keys based on menu_rc
        case "$menu_rc" in
            3) go_to_main_menu; return 0 ;; # m -> main menu
            4) request_script_exit; return 0 ;; # e -> exit script
            5) return_from_menu; return 0 ;; # r -> return/back (to previous menu)
            2) continue ;; # ? -> help was shown, re-loop current menu
            0) # Numeric choice or default exit "0"
               # Proceed to specific choice handling below
               ;;
            *) handle_error "ERROR" "Unhandled menu_loop code $menu_rc in manage_cron_job_for_service"; press_any_key; continue;;
        esac

        # Handle numeric choices and the specific default exit ("0")
        case "$user_choice" in
            "1") _set_service_cron_job "*/15 * * * *" "$service_name"; break ;;
            "2") _set_service_cron_job "0 * * * *" "$service_name"; break ;;
            "3") _set_service_cron_job "0 */6 * * *" "$service_name"; break ;;
            "4") _set_service_cron_job "0 0 * * *" "$service_name"; break ;;
            "5")
                local custom_interval
                print_info "Enter custom interval in minutes (1-1440, or 0 to cancel)."
                while true; do
                    read -r -p "Interval (minutes): " custom_interval
                    if [[ "$custom_interval" == "0" ]]; then
                        print_info "Custom interval setup cancelled."
                        break # Breaks inner loop, will re-show cron menu
                    elif [[ "$custom_interval" =~ ^[0-9]+$ ]] && (( custom_interval >= 1 && custom_interval <= 1440 )); then
                        _set_service_cron_job "*/${custom_interval} * * * *" "$service_name"
                        break 2 # Breaks both loops, exiting manage_cron_job_for_service after success
                    else
                        print_warning "Invalid interval. Please enter a number between 1 and 1440, or 0 to cancel."
                    fi
                done
                # If inner loop broken by '0', outer loop continues. If broken by valid custom interval, outer loop also breaks.
                if [[ "$custom_interval" != "0" ]]; then break; fi
                ;;
            "6") _remove_service_cron_job "$service_name"; break ;;
            "0") return_from_menu; return 0 ;;
            *) print_warning "Invalid option. Please try again."; press_any_key ;;
        esac
    done
    press_any_key # After a cron job action
    return_from_menu # Return to the calling menu (likely tunnel management)
}

# Internal function to set a cron job for a specific service
_set_service_cron_job() {
    local schedule_expression="$1"
    local service_to_manage="$2"

    # Remove any existing cron job for this service managed by this script
    _remove_service_cron_job "$service_to_manage" "quiet" # quiet mode for removal

    local new_cron_job_line="${schedule_expression} systemctl restart ${service_to_manage} # ${CRON_COMMENT_TAG}"

    # Add the new job
    # Fetch current crontab, append new job, then load it. Handle empty crontab.
    local current_crontab
    current_crontab=$(crontab -l 2>/dev/null)

    if [[ -z "$current_crontab" ]]; then
        echo "$new_cron_job_line" | crontab -
    else
        (echo "$current_crontab"; echo "$new_cron_job_line") | crontab -
    fi

    if crontab -l 2>/dev/null | grep -Fq "$new_cron_job_line"; then
        handle_success "Cron job set successfully for $service_to_manage."
        log_message "INFO" "Cron job set for $service_to_manage: $new_cron_job_line"
    else
        handle_error "ERROR" "Failed to set cron job for $service_to_manage. Check crontab permissions or syntax."
    fi
}

# Internal function to remove a cron job for a specific service
# Param $2: "quiet" to suppress "no job found" message.
_remove_service_cron_job() {
    local service_to_manage="$1"
    local mode="${2:-verbose}" # Default to verbose
    local job_found=false

    # Check if crontab command exists
    if ! command -v crontab &> /dev/null; then
        handle_error "WARNING" "crontab command not found. Cannot manage cron jobs."
        return 1
    fi

    local current_crontab
    current_crontab=$(crontab -l 2>/dev/null)

    if echo "$current_crontab" | grep -Fq "$service_to_manage" && \
       echo "$current_crontab" | grep -Fq "# $CRON_COMMENT_TAG"; then
        job_found=true
        # Filter out the job for the specific service and comment tag
        echo "$current_crontab" | grep -vF "$service_to_manage" | grep -vF "# $CRON_COMMENT_TAG" | crontab -
        # This grep logic is a bit broad, ideally it should remove the specific line.
        # A more precise way:
        # echo "$current_crontab" | grep -vE "systemctl restart ${service_to_manage} # ${CRON_COMMENT_TAG}$" | crontab -
        # For simplicity, the above is okay if we assume one job per service.
        # Let's refine it:
        echo "$current_crontab" | grep -v "systemctl restart ${service_to_manage} # ${CRON_COMMENT_TAG}" | crontab -


        # Verify removal
        if ! crontab -l 2>/dev/null | grep -Fq "$service_to_manage" | grep -Fq "# $CRON_COMMENT_TAG"; then
             if [[ "$mode" != "quiet" ]]; then
                handle_success "Cron job for $service_to_manage removed."
            fi
            log_message "INFO" "Cron job removed for $service_to_manage."
        else
            if [[ "$mode" != "quiet" ]]; then
                handle_error "ERROR" "Failed to remove cron job for $service_to_manage."
            fi
        fi
    elif [[ "$mode" != "quiet" ]]; then
        print_warning "No EasyBackhaul-managed cron job found for $service_to_manage."
    fi
    return 0
}
true # Ensure script is valid
# --- MODULE: modules/restart_watcher.sh ---
# modules/restart_watcher.sh
# Coordinated restart watcher for EasyBackhaul tunnels.

# This script defines functions for the watcher's core logic (executed by a background process)
# and for managing watcher instances (enabling, disabling, configuring from the main UI).

# --- Watcher Core Logic (for background process) ---

# Main entry point for the background watcher process.
# This function is NOT called directly by the main EasyBackhaul script's UI flow.
# It's intended to be run by the launcher script created by 'enable_tunnel_watcher'.
# Required environment variables (set by the launcher script from the .conf file):
#   SERVICE_NAME, LOG_PATTERN, REMOTE_HOST, REMOTE_PORT, RESTART_SECRET,
#   RESTART_DELAY_LOCAL, RESTART_DELAY_REMOTE, MAX_RETRIES, ROLE, LISTEN_PORT
_run_watcher_process() {
    # Source the main helpers to get log_message, etc.
    # This assumes helpers.sh is available in a known location relative to the main script,
    # or that build.sh makes it available. For now, assume globals and helpers are sourced by easybh.sh.
    # If this script were truly standalone, it would need its own minimal logging.

    # Use local copies of env vars or defaults if not set (though they should be by launcher)
    local service_name_local="${SERVICE_NAME:?SERVICE_NAME is required for watcher process}"
    local log_pattern_local="${LOG_PATTERN:-ERROR|FATAL|connection.*failed|timeout}"
    local remote_host_local="${REMOTE_HOST:?REMOTE_HOST is required}"
    local remote_port_local="${REMOTE_PORT:-45680}" # Default if not set by conf
    local restart_secret_local="${RESTART_SECRET:?RESTART_SECRET is required}"
    local delay_local="${RESTART_DELAY_LOCAL:-10}"
    local delay_remote="${RESTART_DELAY_REMOTE:-10}"
    local max_retries_local="${MAX_RETRIES:-3}"
    local role_local="${ROLE:-unknown_watcher_role}"
    local listen_port_local="${LISTEN_PORT:-45679}" # Default if not set by conf
    local ack_file_path="/tmp/restart_ack_${service_name_local}" # Standardized ACK file path

    log_message "INFO" "[Watcher:$role_local] Starting for service: $service_name_local. Listening on $listen_port_local. Remote: $remote_host_local:$remote_port_local."

    # Start listener in background (within this watcher process)
    _watcher_listen_for_requests "$listen_port_local" "$remote_host_local" "$remote_port_local" \
                                "$restart_secret_local" "$role_local" "$delay_remote" \
                                "$service_name_local" "$ack_file_path" &
    local listener_bg_pid=$!

    # Trap signals for cleanup
    trap '_watcher_cleanup $listener_bg_pid; exit 0' SIGINT SIGTERM

    # Start log monitoring (this will block)
    _watcher_monitor_logs "$service_name_local" "$log_pattern_local" \
                          "$remote_host_local" "$remote_port_local" \
                          "$restart_secret_local" "$role_local" "$delay_local" \
                          "$max_retries_local" "$ack_file_path"

    _watcher_cleanup $listener_bg_pid # Cleanup if monitor_logs exits
    log_message "INFO" "[Watcher:$role_local] Exiting for service: $service_name_local."
}

_watcher_cleanup() {
    local listener_pid_to_kill="$1"
    log_message "INFO" "[Watcher] Cleaning up listener PID $listener_pid_to_kill..."
    if [[ -n "$listener_pid_to_kill" ]] && kill -0 "$listener_pid_to_kill" 2>/dev/null; then
        kill "$listener_pid_to_kill" 2>/dev/null && sleep 0.1 && kill -9 "$listener_pid_to_kill" 2>/dev/null
    fi
    # Ack file is specific to an event, usually removed after processing.
}

_watcher_listen_for_requests() {
    local listen_port="$1" remote_host="$2" remote_port="$3" secret_val="$4" \
          current_role="$5" remote_delay="$6" service_to_restart="$7" ack_file="$8"

    # Check nc compatibility once at the start of listener
    if [[ "${NC_COMPATIBLE:-false}" != "true" ]]; then
        log_message "ERROR" "[Watcher:$current_role] Netcat incompatible. Listener for $service_to_restart cannot reliably start."
        return 1
    fi

    while true; do
        local received_msg
        # Use timeout with nc if available and compatible, otherwise nc might block indefinitely
        if command -v timeout &>/dev/null; then
            received_msg=$(timeout 65s nc -l -p "$listen_port" -w 60 2>/dev/null)
        else
            # Less reliable without timeout, -w might not work with -l on all nc versions
            received_msg=$(nc -l -p "$listen_port" -w 60 2>/dev/null)
        fi

        if [[ -z "$received_msg" ]]; then # Timeout or empty message
            sleep 1 # Prevent tight loop on continuous timeouts/errors
            continue
        fi

        log_message "DEBUG" "[Watcher:$current_role] Received on $listen_port: $received_msg"

        if [[ "$received_msg" =~ ^RESTART_REQUEST:([^:]+):([^:]+)$ ]]; then
            local received_secret="${BASH_REMATCH[1]}"
            local sender_role="${BASH_REMATCH[2]}"
            if [[ "$received_secret" == "$secret_val" ]]; then
                log_message "INFO" "[Watcher:$current_role] Auth OK. Received RESTART_REQUEST from $sender_role for $service_to_restart."
                log_message "INFO" "[Watcher:$current_role] Sending ACK to $remote_host:$remote_port and scheduling restart in $remote_delay s."
                echo "RESTART_ACK:$secret_val:$current_role" | nc "$remote_host" "$remote_port" -w 3 # Short timeout for ACK

                ( # Subshell for delayed restart
                    sleep "$remote_delay"
                    log_message "INFO" "[Watcher:$current_role] Executing restart for $service_to_restart (triggered by remote)."
                    systemctl restart "$service_to_restart"
                ) & # Run in background
            else
                log_message "WARN" "[Watcher:$current_role] Received RESTART_REQUEST with INVALID secret from $sender_role. Ignoring."
            fi
        elif [[ "$received_msg" =~ ^RESTART_ACK:([^:]+):([^:]+)$ ]]; then
            local received_secret="${BASH_REMATCH[1]}"
            # local ack_sender_role="${BASH_REMATCH[2]}" # Can log this if needed
            if [[ "$received_secret" == "$secret_val" ]]; then
                log_message "INFO" "[Watcher:$current_role] Received RESTART_ACK for $service_to_restart. Storing in $ack_file."
                touch "$ack_file" # Signal that ACK was received
            else
                 log_message "WARN" "[Watcher:$current_role] Received RESTART_ACK with INVALID secret. Ignoring."
            fi
        else
            log_message "WARN" "[Watcher:$current_role] Received unknown message on $listen_port: $received_msg"
        fi
    done
}

_watcher_monitor_logs() {
    local service_to_monitor="$1" pattern="$2" r_host="$3" r_port="$4" secret_val="$5" \
          current_role="$6" local_delay="$7" max_tries="$8" ack_file="$9"

    log_message "INFO" "[Watcher:$current_role] Monitoring logs for $service_to_monitor (Pattern: '$pattern')."

    # Ensure nc compatibility for sending requests
    if [[ "${NC_COMPATIBLE:-false}" != "true" ]]; then
        log_message "ERROR" "[Watcher:$current_role] Netcat incompatible. Cannot reliably send restart requests for $service_to_monitor."
        # Could choose to only do local restarts or exit. For now, will proceed but log error.
    fi

    journalctl -u "$service_to_monitor" -f --no-pager | while IFS= read -r log_line; do
        if echo "$log_line" | grep -qE "$pattern"; then
            log_message "WARN" "[Watcher:$current_role] Error detected in logs for $service_to_monitor: $log_line"
            log_message "INFO" "[Watcher:$current_role] Initiating coordinated restart procedure for $service_to_monitor."

            local attempt_num=1
            local ack_is_received=false
            while (( attempt_num <= max_tries )); do
                log_message "INFO" "[Watcher:$current_role] Sending RESTART_REQUEST to $r_host:$r_port for $service_to_monitor (Attempt $attempt_num/$max_tries)."
                # Clear any old ACK file before sending request
                rm -f "$ack_file"
                echo "RESTART_REQUEST:$secret_val:$current_role" | nc "$r_host" "$r_port" -w 3 # Short timeout for send

                # Wait for ACK (e.g., up to 5 seconds)
                for (( i=0; i<5; i++ )); do
                    if [[ -f "$ack_file" ]]; then
                        log_message "INFO" "[Watcher:$current_role] RESTART_ACK received for $service_to_monitor."
                        rm -f "$ack_file" # Consume ACK
                        ack_is_received=true
                        break # Break inner loop (wait for ACK)
                    fi
                    sleep 1
                done

                if $ack_is_received; then
                    break # Break outer loop (retry attempts)
                fi

                log_message "WARN" "[Watcher:$current_role] No ACK received for $service_to_monitor (Attempt $attempt_num). Retrying if attempts remain."
                ((attempt_num++))
            done

            if $ack_is_received; then
                log_message "INFO" "[Watcher:$current_role] Coordinated restart approved. Restarting $service_to_monitor locally in $local_delay seconds."
            else
                log_message "ERROR" "[Watcher:$current_role] Failed to coordinate restart for $service_to_monitor after $max_tries attempts. Proceeding with local restart only in $local_delay seconds."
            fi

            ( # Subshell for delayed local restart
                sleep "$local_delay"
                log_message "INFO" "[Watcher:$current_role] Executing local restart for $service_to_monitor."
                systemctl restart "$service_to_monitor"
            ) &

            # IMPORTANT: If monitor_and_restart is part of the main watcher script that gets backgrounded,
            # this 'return' will exit the 'while read' loop from journalctl, effectively stopping monitoring
            # for this particular error instance. The watcher process itself would then exit due to _run_watcher_process structure.
            # This is usually the desired behavior: detect error, attempt restart, then the new service instance's logs will be monitored.
            return
        fi
    done
    # If journalctl -f exits (e.g. service stopped manually and journalctl terminated), this loop ends.
    log_message "INFO" "[Watcher:$current_role] Log monitoring for $service_to_monitor ended (journalctl -f exited)."
}


# --- Watcher UI Management Functions (called by main EasyBackhaul script) ---

_tunnel_watcher_menu_help() {
    local service_name_ctx="$1" # Context for help
    print_menu_header "secondary" "Restart Watcher Help" "Service: $service_name_ctx"
    echo "The Coordinated Restart Watcher monitors a tunnel service for errors."
    echo "If an error is detected (based on a log pattern), it attempts to"
    echo "coordinate a restart with the remote end of the tunnel."
    echo
    print_info "Key Features:"
    echo "  - Error Detection: Monitors service logs using 'journalctl -f'."
    echo "  - Coordinated Restart: Communicates with the remote watcher via netcat."
    echo "  - Secure Communication: Uses a shared secret for authentication."
    echo "  - Configurable: Delays, retries, ports, and log patterns can be set."
    echo
    print_info "Setup:"
    echo "  1. Enable watcher on one side (e.g., server)."
    echo "  2. A shared secret is generated/used. Note this secret."
    echo "  3. Enable watcher on the other side (e.g., client), providing the SAME secret."
    echo "  4. Configure IP addresses and ports for communication between watchers."
    echo
    print_info "Important:"
    echo "  - Requires a compatible 'nc' (netcat) version (netcat-openbsd recommended)."
    echo "  - Ensure firewall rules allow communication on the watcher ports."
    press_any_key
}

manage_tunnel_watcher() {
    local main_service_name="$1" # e.g., backhaul-bh-server-tcp-xxxxx
    local tunnel_short_suffix="$2" # e.g., bh-server-tcp-xxxxx
    local tunnel_config_file="$3"  # Path to the main tunnel's TOML config

    # Construct paths for watcher-specific files (convention)
    local watcher_launcher_script="/tmp/backhaul-watcher-${tunnel_short_suffix}.sh"
    local watcher_conf_file="/tmp/backhaul-watcher-${tunnel_short_suffix}.conf"
    local watcher_pid_file="/tmp/backhaul-watcher-${tunnel_short_suffix}.pid"
    # Watcher log is managed by nohup redirection in _enable_tunnel_watcher

    local menu_options=(
        "1. Enable Watcher"
        "2. Disable Watcher"
        "3. Show Watcher Status"
        "4. View Watcher Log"
        "5. Edit Watcher Configuration"
        "6. Test Watcher Communication (experimental)"
        "7. Manage Watcher Shared Secret"
    )
    local current_exit_details=("0" "Back to Tunnel Management") # Array: [key, text]
    local user_choice menu_rc

    while true; do
        local watcher_status="Disabled/Not Running"
        if [[ -f "$watcher_pid_file" ]]; then
            local pid_val
            pid_val=$(cat "$watcher_pid_file" 2>/dev/null)
            if [[ -n "$pid_val" ]] && ps -p "$pid_val" > /dev/null 2>&1; then
                watcher_status="Running (PID: $pid_val)"
            fi
        fi
        print_menu_header "secondary" "Restart Watcher Management" "Tunnel: $tunnel_short_suffix" "Watcher: $watcher_status"

        menu_loop "Select watcher option" menu_options current_exit_details "_tunnel_watcher_menu_help \"$tunnel_short_suffix\""
        user_choice="$MENU_CHOICE" # menu_loop sets MENU_CHOICE
        menu_rc=$?                # menu_loop returns status code

        # Handle universal navigation keys based on menu_rc
        case "$menu_rc" in
            3) go_to_main_menu; return 0 ;; # m -> main menu
            4) request_script_exit; return 0 ;; # e -> exit script
            5) return_from_menu; return 0 ;; # r -> return/back (to previous menu)
            2) continue ;; # ? -> help was shown, re-loop current menu
            0) # Numeric choice or default exit "0"
               # Proceed to specific choice handling below
               ;;
            *) handle_error "ERROR" "Unhandled menu_loop code $menu_rc in manage_tunnel_watcher"; press_any_key; continue;;
        esac

        # Handle numeric choices and the specific default exit ("0")
        case "$user_choice" in
            "1") _enable_tunnel_watcher "$main_service_name" "$tunnel_short_suffix" "$tunnel_config_file" ;;
            "2") _disable_tunnel_watcher "$tunnel_short_suffix" "$tunnel_config_file" ;;
            "3") _show_tunnel_watcher_status "$tunnel_short_suffix" ;;
            "4") _view_tunnel_watcher_log "$tunnel_short_suffix" ;;
            "5") _edit_tunnel_watcher_config "$tunnel_short_suffix" "$tunnel_config_file" ;;
            "6") _test_tunnel_watcher_comm "$tunnel_short_suffix" ;;
            "7") _manage_watcher_shared_secret "$tunnel_config_file" ;;
            "0") return_from_menu; return 0;;
            *) print_warning "Invalid option."; press_any_key ;;
        esac
    done
}

_enable_tunnel_watcher() {
    local service_name="$1" tunnel_suffix="$2" config_file="$3"
    print_menu_header "secondary" "Enable Restart Watcher" "Tunnel: $tunnel_suffix"

    # Check for nc compatibility first
    ensure_netcat_installed # From helpers.sh, also runs check_nc_compatibility
    if [[ "${NC_COMPATIBLE:-false}" != "true" ]]; then
        handle_error "ERROR" "Netcat is not compatible. Watcher cannot be reliably enabled."
        press_any_key
        return 1
    fi

    # Default watcher config values
    local w_role w_remote_host w_listen_port w_remote_port w_secret w_log_pattern
    local w_delay_local=10 w_delay_remote=10 w_max_retries=3

    # Determine role and pre-fill some values based on tunnel config
    if grep -q 'mode[[:space:]]*=[[:space:]]*"server"' "$config_file"; then
        w_role="server"
        print_info "This is a SERVER tunnel. You need the CLIENT's public IP for watcher communication."
        read -r -p "Enter CLIENT's public IP address: " w_remote_host
        if ! validate_ip "$w_remote_host"; then handle_error "ERROR" "Invalid IP address for remote host."; press_any_key; return 1; fi
        w_listen_port="${WATCHER_SERVER_LISTEN_PORT:-45679}" # Server listens on one port
        w_remote_port="${WATCHER_CLIENT_LISTEN_PORT:-45680}" # Server sends to client's listen port
    elif grep -q 'mode[[:space:]]*=[[:space:]]*"client"' "$config_file"; then
        w_role="client"
        w_remote_host=$(grep 'server[[:space:]]*=' "$config_file" | sed 's/.*=[[:space:]]*"\(.*\):.*"/\1/')
        if ! validate_ip "$w_remote_host"; then handle_error "ERROR" "Could not parse server IP from tunnel config."; press_any_key; return 1; fi
        print_info "This is a CLIENT tunnel. Remote server IP for watcher: $w_remote_host"
        w_listen_port="${WATCHER_CLIENT_LISTEN_PORT:-45680}" # Client listens on one port
        w_remote_port="${WATCHER_SERVER_LISTEN_PORT:-45679}" # Client sends to server's listen port
    else
        handle_error "ERROR" "Cannot determine tunnel mode (server/client) from config: $config_file"
        press_any_key
        return 1
    fi

    # Get/Generate Shared Secret
    w_secret=$(_get_or_set_watcher_secret "$config_file" "$w_role")
    if [[ -z "$w_secret" ]]; then return 1; fi # Error handled in _get_or_set_watcher_secret

    w_log_pattern=$(grep 'log_pattern[[:space:]]*=' "$config_file" | sed 's/.*=[[:space:]]*"\(.*\)"/\1/' 2>/dev/null || echo "ERROR|FATAL|connection.*failed|timeout|reset by peer")

    print_info "--- Watcher Configuration ---"
    echo "  Role: $w_role"
    echo "  Service to Monitor: $service_name"
    echo "  Log Pattern for Errors: $w_log_pattern"
    echo "  This Watcher Listens on Port: $w_listen_port"
    echo "  Remote Watcher Host: $w_remote_host"
    echo "  Remote Watcher Port: $w_remote_port"
    echo "  Shared Secret: [set]" # Don't display

    if ! prompt_yes_no "Proceed with these watcher settings?" "y"; then
        print_info "Watcher enablement cancelled."
        press_any_key
        return 1
    fi

    # Create watcher configuration file (e.g., /tmp/backhaul-watcher-suffix.conf)
    local watcher_conf_file_path="/tmp/backhaul-watcher-${tunnel_suffix}.conf"
    cat > "$watcher_conf_file_path" <<EOL
# Watcher configuration for tunnel: $tunnel_suffix
SERVICE_NAME="$service_name"
LOG_PATTERN="$w_log_pattern"
REMOTE_HOST="$w_remote_host"
REMOTE_PORT="$w_remote_port"
RESTART_SECRET="$w_secret"
RESTART_DELAY_LOCAL="$w_delay_local"
RESTART_DELAY_REMOTE="$w_delay_remote"
MAX_RETRIES="$w_max_retries"
ROLE="$w_role"
LISTEN_PORT="$w_listen_port"
EOL
    chmod 600 "$watcher_conf_file_path"
    log_message "INFO" "Watcher config file created: $watcher_conf_file_path"

    # Create watcher launcher script (e.g., /tmp/backhaul-watcher-suffix.sh)
    # This launcher script will source globals.sh, then helpers.sh, then the watcher conf, then call _run_watcher_process
    local watcher_launcher_script_path="/tmp/backhaul-watcher-${tunnel_suffix}.sh"
    cat > "$watcher_launcher_script_path" <<EOLSCRIPT
#!/bin/bash
# Launcher for EasyBackhaul Watcher: ${tunnel_suffix}

# Determine script's own directory to find other modules if needed
SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
EASYBACKHAUL_BASE_DIR="\$(dirname "\$SCRIPT_DIR")" # Assuming modules are one level up from a bin dir or similar

# Source required global variables and helper functions
# This assumes that when easybh.sh is built, globals.sh and helpers.sh contents are available
# For a truly standalone script, these would need to be embedded or sourced differently.
# For now, we rely on the main script's structure.
if [[ -f "\${EASYBACKHAUL_BASE_DIR}/modules/globals.sh" ]]; then
    source "\${EASYBACKHAUL_BASE_DIR}/modules/globals.sh"
else
    echo "FATAL: globals.sh not found for watcher." >&2; exit 1;
fi
if [[ -f "\${EASYBACKHAUL_BASE_DIR}/modules/helpers.sh" ]]; then
    source "\${EASYBACKHAUL_BASE_DIR}/modules/helpers.sh"
else
    echo "FATAL: helpers.sh not found for watcher." >&2; exit 1;
fi
# Source the watcher's own functions (this file itself, if structured for it)
# This is tricky if restart_watcher.sh contains both UI and core logic.
# For now, assume _run_watcher_process is available because this whole module is sourced by easybh.sh
# This means the launcher is simpler, it just sets up env and calls the function.

# Load specific watcher config
source "$watcher_conf_file_path"

# Call the main watcher process function (defined in the sourced modules/restart_watcher.sh)
_run_watcher_process
EOLSCRIPT
    chmod +x "$watcher_launcher_script_path"
    log_message "INFO" "Watcher launcher script created: $watcher_launcher_script_path"

    # Start the watcher in the background
    local watcher_log_file="/var/log/easybackhaul/watcher-${tunnel_suffix}.log" # Log to main log dir
    ensure_dir "$(dirname "$watcher_log_file")"
    
    nohup "$watcher_launcher_script_path" >> "$watcher_log_file" 2>&1 &
    local watcher_pid=$!
    sleep 1 # Give it a moment to start or fail

    local watcher_pid_file_path="/tmp/backhaul-watcher-${tunnel_suffix}.pid"
    if ps -p $watcher_pid > /dev/null 2>&1; then
        echo "$watcher_pid" > "$watcher_pid_file_path"
        chmod 600 "$watcher_pid_file_path"
        update_toml_value "$config_file" "restart_watcher_enabled" "true" "boolean"
        update_toml_value "$config_file" "restart_watcher_pid" "$watcher_pid" "numeric"
        # Store other watcher params in the main tunnel config for visibility/editing later
        update_toml_value "$config_file" "watcher_role" "$w_role" "string"
        update_toml_value "$config_file" "watcher_listen_port" "$w_listen_port" "numeric"
        update_toml_value "$config_file" "watcher_remote_host" "$w_remote_host" "string"
        update_toml_value "$config_file" "watcher_remote_port" "$w_remote_port" "numeric"
        update_toml_value "$config_file" "watcher_log_pattern" "$w_log_pattern" "string"

        handle_success "Watcher enabled and started for $service_name (PID: $watcher_pid)."
        print_info "Watcher log: $watcher_log_file"
    else
        handle_error "ERROR" "Watcher process failed to start for $service_name. Check $watcher_log_file for details."
        # Cleanup temp files if start failed
        rm -f "$watcher_conf_file_path" "$watcher_launcher_script_path"
    fi
    press_any_key
}

_disable_tunnel_watcher() {
    local tunnel_suffix="$1" config_file="$2"
    print_menu_header "secondary" "Disable Restart Watcher" "Tunnel: $tunnel_suffix"

    # cleanup_watcher_files (from helpers.sh) handles stopping the process and removing tmp files
    if cleanup_watcher_files "$tunnel_suffix"; then
        update_toml_value "$config_file" "restart_watcher_enabled" "false" "boolean"
        update_toml_value "$config_file" "restart_watcher_pid" "0" "numeric" # Clear PID
        handle_success "Watcher disabled and files cleaned up for tunnel: $tunnel_suffix."
    else
        handle_error "WARNING" "Watcher cleanup reported issues, but proceeding to mark as disabled in config."
        update_toml_value "$config_file" "restart_watcher_enabled" "false" "boolean"
    fi
    press_any_key
}

_show_tunnel_watcher_status() {
    local tunnel_suffix="$1"
    print_menu_header "secondary" "Watcher Status" "Tunnel: $tunnel_suffix"

    local watcher_pid_file_path="/tmp/backhaul-watcher-${tunnel_suffix}.pid"
    local watcher_conf_file_path="/tmp/backhaul-watcher-${tunnel_suffix}.conf"

    if [[ -f "$watcher_pid_file_path" ]]; then
        local pid_val
        pid_val=$(cat "$watcher_pid_file_path" 2>/dev/null)
        if [[ -n "$pid_val" ]] && ps -p "$pid_val" > /dev/null 2>&1; then
            print_success "Watcher is RUNNING (PID: $pid_val)."
            echo "  Launcher: /tmp/backhaul-watcher-${tunnel_suffix}.sh"
            echo "  Config: $watcher_conf_file_path"
            echo "  Log: /var/log/easybackhaul/watcher-${tunnel_suffix}.log"
            if [[ -f "$watcher_conf_file_path" ]]; then
                echo "  --- Configuration from $watcher_conf_file_path ---"
                grep -v "RESTART_SECRET" "$watcher_conf_file_path" | sed 's/^/    /' # Hide secret
            fi
        else
            print_error "Watcher is NOT RUNNING (PID file found but process dead or PID invalid)."
            print_info "Consider disabling and re-enabling the watcher."
        fi
    else
        print_warning "Watcher is DISABLED or its PID file is missing."
        print_info "To enable, use the 'Enable Watcher' option."
    fi
    press_any_key
}

_view_tunnel_watcher_log() {
    local tunnel_suffix="$1"
    local watcher_log_file="/var/log/easybackhaul/watcher-${tunnel_suffix}.log"
    if [[ -f "$watcher_log_file" ]]; then
        view_system_log "file" "$watcher_log_file" "Watcher Log: $tunnel_suffix"
    else
        handle_error "WARNING" "Watcher log file not found: $watcher_log_file"
        press_any_key
    fi
}

_edit_tunnel_watcher_config() {
    local tunnel_suffix="$1" main_tunnel_config_file="$2"
    local watcher_conf_file_path="/tmp/backhaul-watcher-${tunnel_suffix}.conf" # This is the live config for the running watcher
    
    print_menu_header "secondary" "Edit Watcher Configuration" "Tunnel: $tunnel_suffix"

    if [[ ! -f "$watcher_conf_file_path" ]]; then
        handle_error "ERROR" "Watcher process config file not found: $watcher_conf_file_path. Enable watcher first or check /tmp."
        press_any_key
        return 1
    fi

    # Display current settings from the watcher's .conf file
    print_info "Current settings from $watcher_conf_file_path (effective on next watcher restart):"
    # Exclude secret for display security
    grep -v "RESTART_SECRET" "$watcher_conf_file_path" | sed 's/^/  /'
    echo
    print_info "Editing these values requires the watcher process to be restarted to take effect."
    print_info "The main tunnel config ($main_tunnel_config_file) also stores some of these for UI display."

    # For simplicity, prompt for common fields. Direct edit of .conf for full power.
    # This is a simplified editor.
    local new_log_pattern new_delay_local new_delay_remote new_max_retries
    
    # Example: Edit Log Pattern
    read -r -p "New Log Pattern (leave blank to keep current '$(grep LOG_PATTERN "$watcher_conf_file_path" | cut -d'=' -f2- | tr -d '"')'): " new_log_pattern
    if [[ -n "$new_log_pattern" ]]; then
        sed -i "s|^LOG_PATTERN=.*|LOG_PATTERN=\"$new_log_pattern\"|" "$watcher_conf_file_path"
        update_toml_value "$main_tunnel_config_file" "watcher_log_pattern" "$new_log_pattern" "string"
        print_success "Log pattern updated in $watcher_conf_file_path and main config."
    fi
    
    # Add more fields similarly... (RESTART_DELAY_LOCAL, etc.)

    print_info "Configuration in $watcher_conf_file_path updated."
    print_warning "Restart the watcher for tunnel '$tunnel_suffix' for changes to take effect."
    press_any_key
}

_test_tunnel_watcher_comm() {
    local tunnel_suffix="$1"
    local watcher_conf_file_path="/tmp/backhaul-watcher-${tunnel_suffix}.conf"
    print_menu_header "secondary" "Test Watcher Communication" "Tunnel: $tunnel_suffix"

    if [[ ! -f "$watcher_conf_file_path" ]]; then
        handle_error "ERROR" "Watcher config file not found: $watcher_conf_file_path. Cannot perform test."
        press_any_key; return 1;
    fi
    source "$watcher_conf_file_path" # Load REMOTE_HOST, REMOTE_PORT, RESTART_SECRET, ROLE

    if [[ -z "$REMOTE_HOST" || -z "$REMOTE_PORT" || -z "$RESTART_SECRET" || -z "$ROLE" ]]; then
        handle_error "ERROR" "Watcher config is incomplete. Cannot perform test."
        press_any_key; return 1;
    fi
    
    ensure_netcat_installed
    if [[ "${NC_COMPATIBLE:-false}" != "true" ]]; then
        handle_error "ERROR" "Netcat is not compatible. Watcher communication test cannot be reliably performed."
        press_any_key; return 1;
    fi

    print_info "Testing communication with remote watcher at $REMOTE_HOST:$REMOTE_PORT"
    print_info "Sending a TEST_PING message..."
    local test_message="TEST_PING:$RESTART_SECRET:$ROLE"
    local ack_file_path="/tmp/test_ack_${SERVICE_NAME:-$tunnel_suffix}" # SERVICE_NAME might not be in scope here from conf
    rm -f "$ack_file_path"

    echo "$test_message" | nc "$REMOTE_HOST" "$REMOTE_PORT" -w 5 # Send with timeout
    
    print_info "Waiting for TEST_ACK (up to 5 seconds)..."
    local i
    for i in {1..5}; do
        if [[ -f "$ack_file_path" ]]; then
            local ack_content
            ack_content=$(cat "$ack_file_path")
            handle_success "TEST_ACK received! Content: $ack_content"
            rm -f "$ack_file_path"
            press_any_key; return 0;
        fi
        sleep 1
    done

    handle_error "WARNING" "No TEST_ACK received. Check remote watcher, firewall, and secret."
    press_any_key
}

_get_or_set_watcher_secret() {
    local main_tunnel_config_file="$1"
    local current_tunnel_role="$2" # "server" or "client"
    local existing_secret
    
    # Try to get secret from the main tunnel config file first
    if [[ -f "$main_tunnel_config_file" ]]; then
        existing_secret=$(grep 'watcher_shared_secret' "$main_tunnel_config_file" | sed 's/.*=[[:space:]]*"\(.*\)"/\1/' 2>/dev/null)
    fi

    # If not in tunnel config, try global watcher secret file (usually for first server setup)
    if [[ -z "$existing_secret" && -f "$CONFIG_DIR/watcher_secret" ]]; then
        existing_secret=$(cat "$CONFIG_DIR/watcher_secret")
        # If found globally, also save it to the tunnel config for consistency
        if [[ -n "$existing_secret" && -f "$main_tunnel_config_file" ]]; then
             update_toml_value "$main_tunnel_config_file" "watcher_shared_secret" "$existing_secret" "string"
        fi
    fi

    if [[ -n "$existing_secret" ]]; then
        print_info "Using existing shared secret: [hidden]"
        if prompt_yes_no "Use this existing secret?" "y"; then
            echo "$existing_secret"
            return 0
        fi
    fi

    # If no existing secret or user wants to change/set one
    if [[ "$current_tunnel_role" == "server" ]]; then
        print_info "This is a SERVER. You can generate a new secret or enter one if you have it."
        if prompt_yes_no "Generate a new random secret for this watcher pair?" "y"; then
            local new_generated_secret
            new_generated_secret=$(generate_random_secret 32) # From helpers.sh
            print_info "Generated new secret: $new_generated_secret"
            print_warning "IMPORTANT: You MUST use this exact secret when configuring the CLIENT watcher."
            if prompt_yes_no "Use this generated secret?" "y"; then
                # Save to global and tunnel config
                echo "$new_generated_secret" > "$CONFIG_DIR/watcher_secret"
                set_secure_file_permissions "$CONFIG_DIR/watcher_secret" "600"
                if [[ -f "$main_tunnel_config_file" ]]; then
                    update_toml_value "$main_tunnel_config_file" "watcher_shared_secret" "$new_generated_secret" "string"
                fi
                echo "$new_generated_secret"
                return 0
            fi
        fi
    fi
    
    # Prompt to enter manually (always for client if not found, or if server chose not to generate)
    print_info "Please enter the shared watcher secret."
    if [[ "$current_tunnel_role" == "client" ]]; then
        print_info "This MUST match the secret on the SERVER side watcher."
    else # server, but chose not to generate
        print_info "This secret will be used for this watcher pair."
    fi

    local entered_secret
    while true; do
        read -r -s -p "Enter Shared Secret (min 8 chars): " entered_secret; echo
        if [[ "${#entered_secret}" -ge 8 ]]; then
            if [[ -f "$main_tunnel_config_file" ]]; then
                 update_toml_value "$main_tunnel_config_file" "watcher_shared_secret" "$entered_secret" "string"
            fi
            # Also update global if this is the server setting it for the first time potentially
            if [[ "$current_tunnel_role" == "server" ]]; then
                 echo "$entered_secret" > "$CONFIG_DIR/watcher_secret"
                 set_secure_file_permissions "$CONFIG_DIR/watcher_secret" "600"
            fi
            echo "$entered_secret"
            return 0
        else
            print_warning "Secret too short. Must be at least 8 characters."
            if prompt_yes_no "Try entering secret again?" "y"; then continue; else return 1; fi
        fi
    done
}


_manage_watcher_shared_secret() {
    local main_tunnel_config_file="$1"
    print_menu_header "secondary" "Watcher Shared Secret" "Manage"

    local current_secret # This will be populated by _get_or_set_watcher_secret if it exists
    current_secret=$(_get_or_set_watcher_secret "$main_tunnel_config_file" "unknown") # Role unknown just for display
    
    if [[ -n "$current_secret" ]]; then
        print_success "Current shared secret is set."
        print_info "(Secret is hidden for security. Choose 'View/Copy' to see it.)"
    else
        print_warning "No shared secret is currently set in the tunnel config."
    fi
    echo

    local secret_menu_options=(
        "1. View/Copy Current Secret"
        "2. Set/Update Secret Manually"
        "3. Generate New Secret (Server Role Recommended)"
    )
    local secret_exit_details=("0" "Back") # Array: [key, text]
    local user_choice menu_rc

    _secret_menu_help() {
        print_info "Shared Secret Help:"
        echo " - The watcher secret MUST be identical on both client and server watchers."
        echo " - View/Copy: Shows current secret (use 'xclip' or 'pbcopy' if available)."
        echo " - Set/Update: Manually enter or change the secret."
        echo " - Generate New: Creates a new random secret. If this is a server,"
        echo "   you must then update the client with this new secret."
        press_any_key
    }

    menu_loop "Select secret option" secret_menu_options secret_exit_details "_secret_menu_help"
    user_choice="$MENU_CHOICE" # menu_loop sets MENU_CHOICE
    menu_rc=$?                # menu_loop returns status code

    # Handle universal navigation keys based on menu_rc
    case "$menu_rc" in
        3) go_to_main_menu; return 0 ;; # m -> main menu
        4) request_script_exit; return 0 ;; # e -> exit script
        5) return_from_menu; return 0 ;; # r -> return/back (to previous menu - manage_tunnel_watcher)
        2) _manage_watcher_shared_secret "$main_tunnel_config_file"; return $? ;; # ? -> help shown, re-call current function
        0) # Numeric choice or default exit "0"
            # Proceed to specific choice handling below
            ;;
        *) handle_error "ERROR" "Unhandled menu_loop code $menu_rc in _manage_watcher_shared_secret"; press_any_key; return 1;;
    esac

    # Handle numeric choices and the specific default exit ("0")
    case "$user_choice" in
        "1") # View/Copy
            local secret_to_show
            secret_to_show=$(grep 'watcher_shared_secret' "$main_tunnel_config_file" | sed 's/.*=[[:space:]]*"\(.*\)"/\1/' 2>/dev/null || cat "$CONFIG_DIR/watcher_secret" 2>/dev/null)
            if [[ -n "$secret_to_show" ]]; then
                print_info "Current Secret: $secret_to_show"
                if command -v xclip &>/dev/null; then
                    echo -n "$secret_to_show" | xclip -selection clipboard
                    print_success "Secret copied to clipboard (xclip)."
                elif command -v pbcopy &>/dev/null; then # macOS
                    echo -n "$secret_to_show" | pbcopy
                    print_success "Secret copied to clipboard (pbcopy)."
                fi
            else
                print_warning "No secret found to display/copy."
            fi
            ;;
        "2") # Set manually
            local role_for_set="client" # Assume client unless server mode is detected in main config
            if grep -q 'mode[[:space:]]*=[[:space:]]*"server"' "$main_tunnel_config_file"; then role_for_set="server"; fi
            _get_or_set_watcher_secret "$main_tunnel_config_file" "$role_for_set" > /dev/null # Re-prompt
            ;;
        "3") # Generate new
             if prompt_yes_no "Generate a new random secret? This will overwrite existing." "n"; then
                local new_s
                new_s=$(generate_random_secret 32)
                print_info "New Generated Secret: $new_s"
                print_warning "You MUST update the other side of the tunnel with this secret."
                if prompt_yes_no "Use this new secret?" "y"; then
                    echo "$new_s" > "$CONFIG_DIR/watcher_secret" # Global default
                    set_secure_file_permissions "$CONFIG_DIR/watcher_secret"
                    update_toml_value "$main_tunnel_config_file" "watcher_shared_secret" "$new_s" "string"
                    handle_success "New secret set and saved."
                else
                    print_info "New secret generation cancelled."
                fi
            fi
            ;;
        "0") return_from_menu; return;;
    esac
    press_any_key
}
true # Ensure script is valid if sourced.
# --- MODULE: modules/tunnel_mgmt.sh ---
# modules/tunnel_mgmt.sh
# List/manage tunnels, single tunnel management, connection test.

# --- Main Tunnel Listing and Management Menu ---
manage_tunnels_menu() {
    # This function is the entry point for managing all tunnels.
    # It will use the new menu navigation system.

    _manage_tunnels_menu_help() {
        print_menu_header "secondary" "Tunnel Management Help"
        echo "This menu lists all configured Backhaul tunnels."
        echo "Select a tunnel number to manage its operations (start, stop, logs, etc.)."
        echo
        print_info "Status Indicators:"
        echo "  - Running: The tunnel's systemd service is active."
        echo "  - Stopped: The service is inactive or not found."
        echo "  - Failed: The service encountered an error."
        echo
        print_info "Navigation:"
        echo "  - Use number keys to select a tunnel."
        echo "  - '0' or 'x' or 'm' will behave as per the footer." # 'x' is alias for 'e' in menu_loop
        press_any_key
    }

    while true; do
        if [[ -z "$CONFIG_DIR" ]]; then
            handle_critical_error "CONFIG_DIR is not defined. Cannot list tunnels."
            # This is a critical error, usually means globals.sh didn't source.
            # Standard navigation might not be appropriate. However, to be safe:
            request_script_exit; return 1;
        fi

        mapfile -t config_files < <(find "$CONFIG_DIR" -maxdepth 1 -name "config-bh-*.toml" -type f 2>/dev/null | sort)

        local tunnel_options=()
        local service_name_map=()
        local tunnel_suffix_map=()

        if [[ ${#config_files[@]} -eq 0 ]]; then
            # No tunnels configured, present a simplified menu
            print_menu_header "primary" "Manage Tunnels" "No Tunnels Found"
            print_warning "No Backhaul tunnels configured yet."
            print_info "Use 'Configure a New Tunnel' from the main menu to create one."

            local no_tunnel_exit_options=("0. Back to Main Menu") # Only one sensible option
            local no_tunnel_choice no_tunnel_rc

            # Prompt is empty as options are self-explanatory or covered by footer
            menu_loop "" tunnel_options no_tunnel_exit_options "_manage_tunnels_menu_help"
            no_tunnel_choice="$MENU_CHOICE"
            no_tunnel_rc=$?

            case "$no_tunnel_rc" in
                0) # User selected "0. Back to Main Menu"
                    if [[ "$no_tunnel_choice" == "0" ]]; then return_from_menu; return 0; fi
                    ;; # Should not happen if only "0" is an option.
                1) # User selected a numeric choice - not possible here.
                    print_warning "Unexpected choice: $no_tunnel_choice"; press_any_key; continue ;;
                2) # Help
                    continue ;;
                3) # Main Menu
                    go_to_main_menu; return 0 ;;
                4) # Exit
                    request_script_exit; return 0 ;;
                *) # Default (e.g. Enter with no input) - treat as back
                    return_from_menu; return 0 ;;
            esac
            continue # Re-loop if help was shown or unexpected case.
        fi
        
        print_menu_header "primary" "Manage Tunnels" "Select a Tunnel"

        local idx=1
        for cfg_file in "${config_files[@]}"; do
            local current_tunnel_suffix
            current_tunnel_suffix=$(basename "$cfg_file" .toml | sed 's/^config-//')
            local current_service_name="backhaul-${current_tunnel_suffix}.service"

            local status_str="Unknown"
            local status_color="$COLOR_YELLOW"

            if systemctl list-units --full --all --type=service --no-legend "$current_service_name" | grep -q "$current_service_name"; then
                if systemctl is-active --quiet "$current_service_name"; then
                    status_str="Running"
                    status_color="$COLOR_GREEN"
                elif systemctl is-failed --quiet "$current_service_name"; then
                    status_str="Failed"
                    status_color="$COLOR_RED"
                else
                    status_str="Stopped"
                    status_color="$COLOR_YELLOW"
                fi
            else
                 status_str="No Service"
                 status_color="$COLOR_RED"
            fi

            tunnel_options+=("$idx. $current_tunnel_suffix [${status_color}${status_str}${COLOR_RESET}]")
            service_name_map[$idx]="$current_service_name"
            tunnel_suffix_map[$idx]="$current_tunnel_suffix"
            ((idx++))
        done

        local exit_options=("0. Back to Main Menu")
        local user_choice menu_rc

        menu_loop "Select tunnel to manage" tunnel_options exit_options "_manage_tunnels_menu_help"
        user_choice="$MENU_CHOICE"
        menu_rc=$?

        case "$menu_rc" in
            0) # Numeric choice or "0"
                if [[ "$user_choice" == "0" ]]; then
                    return_from_menu; return 0;
                elif [[ -n "${service_name_map[$user_choice]}" ]]; then
                    local selected_service="${service_name_map[$user_choice]}"
                    local selected_suffix="${tunnel_suffix_map[$user_choice]}"
                    navigate_to_menu "manage_specific_tunnel_menu \"$selected_service\" \"$selected_suffix\""
                    return 0 # Let main loop call the new menu function
                else
                    print_warning "Invalid selection. Please try again."
                    press_any_key
                fi
                ;;
            1) # Default/Enter - Treat as invalid in this context or re-prompt
                print_warning "Invalid selection. Please try again."
                press_any_key
                ;;
            2) # Help
                continue ;;
            3) # Main Menu
                go_to_main_menu; return 0 ;;
            4) # Exit
                request_script_exit; return 0 ;;
            *) # Should not happen
                print_warning "Unexpected menu_loop return. Please try again."
                press_any_key
                ;;
        esac
    done
}

# --- Specific Tunnel Management Menu ---
manage_specific_tunnel_menu() {
    local service_name="$1"
    local tunnel_suffix="$2"
    local config_file_path="$CONFIG_DIR/config-${tunnel_suffix}.toml"

    _specific_tunnel_menu_help() {
        print_menu_header "secondary" "Tunnel Menu Help" "Tunnel: $tunnel_suffix"
        echo "Manage individual operations for the selected tunnel."
        echo "  1. Start: Starts the tunnel service."
        echo "  2. Stop: Stops the tunnel service."
        echo "  3. Restart: Restarts the tunnel service."
        echo "  4. View Logs: Access logs for this tunnel (journalctl)."
        echo "  5. View Config: Display the tunnel's TOML configuration."
        echo "  6. Edit Config: Manually edit TOML (requires restart to apply)."
        echo "  7. Change Log Level: Modify 'log_level' in TOML (requires restart)."
        echo "  8. Hot Reload Config: Send SIGHUP (if binary supports it)."
        echo "  9. Test Connection: Basic reachability test."
        echo " 10. Manage Watcher: Configure coordinated restart watcher." # Changed from Validate
        echo " 11. Validate Config: Check TOML syntax and parameters."   # Changed from Show Info
        echo " 12. Delete Tunnel: Permanently remove this tunnel."
        press_any_key
    }

    local menu_options=(
        "1. Start Tunnel"
        "2. Stop Tunnel"
        "3. Restart Tunnel"
        "4. View Logs (journalctl)"
        "5. View Configuration"
        "6. Edit Configuration (nano/vi)"
        "7. Change Log Level"
        "8. Hot Reload Config (SIGHUP)"
        "9. Test Connection"
        "10. Manage Restart Watcher" # Updated
        "11. Validate Configuration" # Updated
        "12. Delete Tunnel"
    )
    local exit_options=("0. Back to Tunnel List")
    local user_choice menu_rc

    while true; do
        local current_status_str="Unknown"
        local current_status_color="$COLOR_YELLOW"
        if systemctl is-active --quiet "$service_name" 2>/dev/null; then
            current_status_str="Running"
            current_status_color="$COLOR_GREEN"
        elif systemctl is-failed --quiet "$service_name" 2>/dev/null; then
            current_status_str="Failed"
            current_status_color="$COLOR_RED"
        else # Not active and not failed -> stopped or not found
            if systemctl list-units --full --all --type=service --no-legend "$service_name" | grep -q "$service_name"; then
                 current_status_str="Stopped"
            else
                 current_status_str="No Service" # Service file might be missing
                 current_status_color="$COLOR_RED"
            fi
        fi
        
        print_menu_header "secondary" "Managing Tunnel: $tunnel_suffix" "Service: $service_name" "Status: ${current_status_color}${current_status_str}${COLOR_RESET}"
        
        menu_loop "Select action" menu_options exit_options "_specific_tunnel_menu_help"
        user_choice="$MENU_CHOICE"
        menu_rc=$?

        local action_performed_and_continue=false

        case "$menu_rc" in
            0) # Numeric choice or "0"
                case "$user_choice" in
                    "1") _mng_start_tunnel "$service_name" ;;
                    "2") _mng_stop_tunnel "$service_name" ;;
                    "3") _mng_restart_tunnel "$service_name" ;;
                    "4") view_system_log "journalctl" "$service_name" "Logs for $tunnel_suffix" ;;
                    "5") _mng_view_configuration "$config_file_path" "$tunnel_suffix" ;;
                    "6") _mng_edit_configuration "$config_file_path" "$service_name" ;;
                    "7") _mng_change_log_level "$config_file_path" "$service_name" ;; # This function has its own menu loop
                    "8") _mng_hot_reload_service "$service_name" ;;
                    "9") _mng_test_connection "$config_file_path" ;;
                    "10") # Manage Watcher
                         if type manage_tunnel_watcher &>/dev/null; then
                            navigate_to_menu "manage_tunnel_watcher \"$service_name\" \"$tunnel_suffix\" \"$config_file_path\""
                            return 0
                         else
                            handle_error "ERROR" "Watcher management module not loaded correctly."
                            press_any_key
                         fi
                         ;;
                    "11") # Validate Config
                        if type validate_specific_tunnel_config &>/dev/null; then
                            validate_specific_tunnel_config "$config_file_path"
                        else
                             # This function might not exist yet, or might be in validation.sh
                            handle_error "INFO" "Config validation function not yet available. (validate_specific_tunnel_config)"
                        fi
                        press_any_key # Assume validation prints output then waits
                        ;;
                    "12") # Delete Tunnel
                        if _mng_delete_tunnel "$service_name" "$tunnel_suffix" "$config_file_path"; then
                            # Deletion successful, return to previous menu (tunnel list)
                            return_from_menu
                            return 0
                        fi
                        # If deletion was cancelled, loop continues, press_any_key handled by _mng_delete_tunnel
                        action_performed_and_continue=true # Prevent double press_any_key
                        ;;
                    "0") return_from_menu; return 0 ;;
                    *) print_warning "Invalid option."; press_any_key ;;
                esac
                ;;
            1) # Default/Enter - Treat as invalid or re-prompt
                print_warning "Invalid action. Please select a number or navigation key."
                press_any_key
                ;;
            2) # Help
                continue ;;
            3) # Main Menu
                go_to_main_menu; return 0 ;;
            4) # Exit
                request_script_exit; return 0 ;;
            *)
                print_warning "Unexpected menu_loop return. Please try again."
                press_any_key
                ;;
        esac
        # Most _mng_ functions call press_any_key themselves.
        # If an action was taken that didn't (e.g. validation that just prints), and it's not a nav action
        # if [[ "$action_performed_and_continue" == "false" && "$menu_rc" -le 1 && "$user_choice" != "0" ]]; then
        #    # This logic is getting complex. Simpler to ensure all action handlers use press_any_key if they don't navigate.
        # fi
    done
}

_mng_start_tunnel() {
    local service_to_start="$1"
    log_message "INFO" "Attempting to start service: $service_to_start"
    if run_with_spinner "Starting $service_to_start..." systemctl start "$service_to_start"; then
        handle_success "Service $service_to_start started."
    else
        handle_error "ERROR" "Failed to start $service_to_start. Check logs: journalctl -u $service_to_start -n 50"
    fi
    press_any_key
}

_mng_stop_tunnel() {
    local service_to_stop="$1"
    log_message "INFO" "Attempting to stop service: $service_to_stop"
    if run_with_spinner "Stopping $service_to_stop..." systemctl stop "$service_to_stop"; then
        handle_success "Service $service_to_stop stopped."
    else
        handle_error "ERROR" "Failed to stop $service_to_stop."
    fi
    press_any_key
}

_mng_restart_tunnel() {
    local service_to_restart="$1"
    log_message "INFO" "Attempting to restart service: $service_to_restart"
    if run_with_spinner "Restarting $service_to_restart..." systemctl restart "$service_to_restart"; then
        handle_success "Service $service_to_restart restarted."
    else
        handle_error "ERROR" "Failed to restart $service_to_restart. Check logs: journalctl -u $service_to_restart -n 50"
    fi
    press_any_key
}

_mng_view_configuration() {
    local cfg_file="$1"
    local suffix="$2"
    if [[ ! -f "$cfg_file" ]]; then
        handle_error "ERROR" "Configuration file not found for tunnel $suffix: $cfg_file"
        press_any_key; return 1;
    fi
    # Header is printed by calling menu. This function shows content then returns.
    # clear # Optional: if you want only the config shown.
    print_info "Displaying: $cfg_file (Press 'q' to quit 'less')"
    echo "----------------------------------------------------------------"
    if ! less "$cfg_file"; then
        # Even if less fails (e.g. redirected output), we might want a pause
        print_warning "Could not display configuration with 'less'. File might be empty or less is unavailable."
        press_any_key
    fi
    # No press_any_key here, less handles its own exit. If less fails, we might need one.
}

_mng_edit_configuration() {
    local cfg_file="$1"
    local service_to_restart="$2" # Tunnel suffix or service name
     if [[ ! -f "$cfg_file" ]]; then
        handle_error "ERROR" "Configuration file not found: $cfg_file"
        press_any_key; return 1;
    fi
    
    backup_configuration_path "$cfg_file" "tunnel-config-$(basename "$service_to_restart" .service)" # Use a clean name for backup

    if command -v nano &>/dev/null; then
        nano "$cfg_file"
    elif command -v vi &>/dev/null; then
        vi "$cfg_file"
    else
        handle_error "ERROR" "Neither 'nano' nor 'vi' found. Cannot edit configuration."
        press_any_key; return 1;
    fi

    print_info "Configuration file edit complete."
    if prompt_yes_no "Restart tunnel $service_to_restart to apply changes?" "y"; then
        _mng_restart_tunnel "$service_to_restart"
    else
        press_any_key # Pause if not restarting
    fi
}

_mng_change_log_level() {
    local cfg_file="$1"
    local service_to_restart="$2" # Tunnel suffix or service name
    
    if [[ ! -f "$cfg_file" ]]; then
        handle_error "ERROR" "Configuration file not found: $cfg_file"
        press_any_key; return 1;
    fi

    # This function now acts as its own sub-menu loop
    _log_level_help() {
        # Header printed by the loop
        print_info "Log Level Help:"
        echo " - debug: Verbose, for troubleshooting."
        echo " - info: Standard operational messages (default)."
        echo " - warn: Important warnings only."
        echo " - error: Only critical errors."
        press_any_key
    }

    while true; do
        print_menu_header "tertiary" "Change Log Level" "Service: $service_to_restart" # Or secondary

        local current_level="info"
        if grep -q 'log_level[[:space:]]*=' "$cfg_file"; then
            current_level=$(grep 'log_level[[:space:]]*=' "$cfg_file" | head -n1 | sed 's/.*=[[:space:]]*"\(.*\)"/\1/')
        fi
        print_info "Current log level in $(basename "$cfg_file"): ${COLOR_CYAN}$current_level${COLOR_RESET}"

        local log_level_options=("1. debug" "2. info" "3. warn" "4. error")
        local log_level_exit_options=("0. Cancel and Back") # Changed for clarity
        local user_choice menu_rc

        menu_loop "Select new log level" log_level_options log_level_exit_options "_log_level_help"
        user_choice="$MENU_CHOICE"
        menu_rc=$?

        local new_level=""
        case "$menu_rc" in
            0) # Numeric or "0"
                case "$user_choice" in
                    "1") new_level="debug" ;;
                    "2") new_level="info" ;;
                    "3") new_level="warn" ;;
                    "4") new_level="error" ;;
                    "0") print_info "Log level change cancelled."; press_any_key; return ;; # Return to specific tunnel menu
                    *) print_warning "Invalid selection."; press_any_key; continue ;; # Re-loop this sub-menu
                esac
                ;;
            1) print_warning "Invalid selection."; press_any_key; continue ;; # Re-loop this sub-menu
            2) continue ;; # Help shown, re-loop this sub-menu
            3) go_to_main_menu; return ;; # Propagate main menu request
            4) request_script_exit; return ;; # Propagate exit request
            *) print_warning "Unexpected menu return."; press_any_key; continue ;; # Re-loop
        esac

        if [[ -n "$new_level" ]]; then
            # Use the unified backup function before modifying
            backup_configuration_path "$cfg_file" "log-level-change-$(basename "$service_to_restart" .service)"

            if update_toml_value "$cfg_file" "log_level" "$new_level" "string"; then
                handle_success "Log level set to '$new_level' in $cfg_file."
                if prompt_yes_no "Restart tunnel $service_to_restart to apply new log level?" "y"; then
                    _mng_restart_tunnel "$service_to_restart" # This calls press_any_key
                else
                    press_any_key # Pause if not restarting
                fi
                return # Successfully changed, return to specific tunnel menu
            else
                handle_error "ERROR" "Failed to update log level in $cfg_file."
                press_any_key # Pause on error
                # Loop again or return? For now, loop again.
            fi
        fi
    done
}

_mng_hot_reload_service() {
    local service_to_reload="$1"
    log_message "INFO" "Attempting to send SIGHUP to $service_to_reload for hot reload."
    if run_with_spinner "Sending SIGHUP to $service_to_reload..." systemctl kill -s HUP "$service_to_reload"; then
        handle_success "Hot reload signal (SIGHUP) sent to $service_to_reload."
        print_info "If the Backhaul binary supports hot reload, configuration changes should be applied."
    else
        handle_error "ERROR" "Failed to send SIGHUP to $service_to_reload. Binary or system may not support this."
    fi
    press_any_key
}

_mng_test_connection() {
    local cfg_file="$1"
    if [[ ! -f "$cfg_file" ]]; then handle_error "ERROR" "Config file not found: $cfg_file"; press_any_key; return 1; fi

    # Header is printed by the calling menu. This function shows info then returns.
    print_info "--- Connection Test for $(basename "$cfg_file") ---" # Simple sub-header
    
    local tunnel_mode listen_addr remote_addr target_ip target_port
    
    if grep -q 'mode[[:space:]]*=[[:space:]]*"server"' "$cfg_file"; then
        tunnel_mode="server"
    elif grep -q 'mode[[:space:]]*=[[:space:]]*"client"' "$cfg_file"; then
        tunnel_mode="client"
    else
        handle_error "ERROR" "Cannot determine tunnel mode from $cfg_file."
        press_any_key; return 1;
    fi

    log_message "INFO" "Testing connection for $tunnel_mode tunnel defined in $cfg_file"

    if [[ "$tunnel_mode" == "server" ]]; then
        listen_addr=$(grep 'listen[[:space:]]*=' "$cfg_file" | sed 's/.*=[[:space:]]*"\(.*\)"/\1/')
        if [[ "$listen_addr" == :* ]]; then
            target_ip="localhost" # Or 0.0.0.0 if you want to test external reachability to it
            target_port="${listen_addr#:}"
        else
            target_ip=$(echo "$listen_addr" | cut -d':' -f1)
            target_port=$(echo "$listen_addr" | cut -d':' -f2)
        fi
        if [[ -z "$target_ip" || "$target_ip" == "0.0.0.0" ]]; then target_ip="localhost"; fi
        print_info "Server mode: Testing listen address $target_ip on port $target_port..."
    else # client
        remote_addr=$(grep 'server[[:space:]]*=' "$cfg_file" | sed 's/.*=[[:space:]]*"\(.*\)"/\1/')
        target_ip=$(echo "$remote_addr" | cut -d':' -f1)
        target_port=$(echo "$remote_addr" | cut -d':' -f2)
        print_info "Client mode: Testing connection to remote server $target_ip on port $target_port..."
    fi

    if ! validate_ip "$target_ip" || ! validate_port "$target_port"; then
        handle_error "ERROR" "Invalid IP ($target_ip) or Port ($target_port) parsed from config."
        press_any_key; return 1;
    fi
    
    ensure_netcat_installed
    if [[ "${NC_COMPATIBLE:-false}" != "true" ]]; then
         handle_error "WARNING" "Netcat may not be fully compatible. Test result might be unreliable."
    fi

    if run_with_spinner "Testing connectivity to $target_ip:$target_port..." nc -z -w 5 "$target_ip" "$target_port"; then
        handle_success "Successfully connected to $target_ip:$target_port."
    else
        handle_error "ERROR" "Could not connect to $target_ip:$target_port. Check service status, firewall, and configuration."
    fi
    press_any_key
}

_mng_delete_tunnel() {
    local service_name="$1"
    local tunnel_suffix="$2"
    local config_file_path="$3"

    # Header printed by calling menu. This function provides specific prompts.
    print_warning "--- Delete Tunnel: $tunnel_suffix ---"
    print_warning "WARNING: This will PERMANENTLY delete the tunnel and all associated data!"
    echo "This includes:"
    echo "  - Systemd service: $service_name"
    echo "  - TOML Configuration: $config_file_path"
    echo "  - Associated UFW rules (comment: EasyBackhaul: tunnel-${tunnel_suffix})"
    echo "  - Associated watcher scripts, logs, and PID files in $EASYBACKHAUL_TMP_DIR and $LOG_DIR" # Use globals

    if ! prompt_yes_no "Are you ABSOLUTELY SURE you want to delete tunnel '$tunnel_suffix'?" "n"; then
        print_info "Tunnel deletion cancelled."
        press_any_key
        return 1 # Indicate cancellation, stay in specific tunnel menu
    fi
    
    local confirmation_text_expected="DELETE $tunnel_suffix"
    local user_confirmation
    read -r -p "To confirm, type exactly '$confirmation_text_expected': " user_confirmation
    if [[ "$user_confirmation" != "$confirmation_text_expected" ]]; then
        handle_error "ERROR" "Confirmation text did not match. Deletion aborted."
        press_any_key
        return 1 # Indicate cancellation
    fi

    log_message "WARN" "Proceeding with deletion of tunnel: $tunnel_suffix"

    # 1. Stop and disable the service
    if systemctl list-units --full --all --type=service --no-legend "$service_name" | grep -q "$service_name"; then
        run_with_spinner "Stopping service $service_name..." systemctl stop "$service_name"
        run_with_spinner "Disabling service $service_name..." systemctl disable "$service_name"
    else
        log_message "INFO" "Service $service_name not found or already removed."
    fi

    # 2. Remove systemd service file
    local systemd_service_file_path="$SERVICE_DIR/$service_name"
    if [[ -f "$systemd_service_file_path" ]]; then
        if secure_delete "$systemd_service_file_path"; then
            log_message "INFO" "Removed systemd service file: $systemd_service_file_path"
        else
            handle_error "ERROR" "Failed to remove systemd service file: $systemd_service_file_path"
        fi
    fi
    
    run_with_spinner "Reloading systemd daemon..." systemctl daemon-reload

    if [[ -f "$config_file_path" ]]; then
        if secure_delete "$config_file_path"; then
            log_message "INFO" "Removed configuration file: $config_file_path"
        else
            handle_error "ERROR" "Failed to remove configuration file: $config_file_path"
        fi
    fi

    if type delete_ufw_rules_for_tunnel &>/dev/null; then
        delete_ufw_rules_for_tunnel "$tunnel_suffix"
    else
        log_message "WARN" "delete_ufw_rules_for_tunnel function not found. Skipping UFW rule deletion."
    fi

    cleanup_watcher_files "$tunnel_suffix"

    handle_success "Tunnel '$tunnel_suffix' and its associated files/rules have been deleted."
    press_any_key
    return 0 # Indicate successful deletion, return from specific tunnel menu
}

# Decommissioned functions that created standalone scripts for tunnels.
# These are replaced by systemd services directly running the backhaul binary with a config file.
# create_tunnel() { log_message "WARN" "DEPRECATED: create_tunnel function called. Tunnel creation is now part of configure_tunnel."; }
# create_tunnel_impl() { log_message "WARN" "DEPRECATED: create_tunnel_impl function called."; }
# start_tunnel() { log_message "WARN" "DEPRECATED: start_tunnel function called. Use systemctl via _mng_start_tunnel."; }
# start_tunnel_impl() { log_message "WARN" "DEPRECATED: start_tunnel_impl function called."; }
# stop_tunnel() { log_message "WARN" "DEPRECATED: stop_tunnel function called. Use systemctl via _mng_stop_tunnel."; }
# stop_tunnel_impl() { log_message "WARN" "DEPRECATED: stop_tunnel_impl function called."; }

true # Ensure script is valid if sourced.
# --- MODULE: modules/menu.sh ---
# modules/menu.sh
# Main menu logic, script entry point, installation wizard, and uninstallation.

# --- Installation Wizard ---
# This function guides the user through installing the Backhaul binary.
# It calls functions from 'backhaul_core.sh' for the actual download/install steps.
_initial_installation_wizard() {
    _install_wizard_help() {
        print_menu_header "secondary" "Installation Wizard Help"
        echo "This wizard helps you install the Backhaul binary, which is required for EasyBackhaul to function."
        print_info "Options:"
        echo "  1. Automatic GitHub Download: Recommended. Fetches the latest release."
        echo "  2. Local File Installation: If you have already downloaded the .tar.gz archive."
        echo "  3. Alternative URL: Download from a custom URL you provide."
        echo "  4. Network Diagnostics: Test connectivity if downloads are failing."
        echo "  0. Exit Installer: You can try installing manually or run this wizard again later."
        press_any_key
    }

    local install_menu_options=(
        "1. Automatic GitHub Download (Recommended)"
        "2. Install from Local File"
        "3. Install from Alternative URL"
        "4. Run Network Diagnostics"
    )
    local install_exit_option_details=("0" "Exit Installer (EasyBackhaul may not function)") # Array: Key and Text
    local user_choice menu_rc

    while true; do
        # Header is now more consistently part of menu_loop, but for initial clarity:
        print_menu_header "primary" "EasyBackhaul Initial Setup" "Backhaul Binary Installation Required"
        print_warning "Backhaul binary not found at the configured path: $BIN_PATH"
        # print_info "Please choose an installation method:" # Covered by menu_loop prompt

        menu_loop "Choose installation method" install_menu_options install_exit_option_details "_install_wizard_help"
        user_choice="$MENU_CHOICE"
        menu_rc=$?

        local install_success=false # Reset for each loop iteration
        case "$menu_rc" in
            0) # Numeric choice or "0" (default exit)
                case "$user_choice" in
                    "1")
                        if download_backhaul_binary_workflow; then install_success=true; fi
                        ;;
                    "2")
                        local os_name arch_name
                        os_name=$(uname -s | tr '[:upper:]' '[:lower:]'); arch_name=$(uname -m)
                        case $arch_name in x86_64) arch_name="amd64";; aarch64) arch_name="arm64";; armv7l) arch_name="armv7";; esac
                        if _download_from_local_file "$os_name" "$arch_name"; then install_success=true; fi
                        ;;
                    "3")
                        local os_name arch_name
                        os_name=$(uname -s | tr '[:upper:]' '[:lower:]'); arch_name=$(uname -m)
                        case $arch_name in x86_64) arch_name="amd64";; aarch64) arch_name="arm64";; armv7l) arch_name="armv7";; esac
                        if _download_from_alternative_source "$os_name" "$arch_name"; then install_success=true; fi
                        ;;
                    "4")
                        if type run_network_diagnostics_menu &>/dev/null; then
                           run_network_diagnostics_menu
                        else
                            handle_error "WARNING" "Network diagnostics function not available."
                            press_any_key
                        fi
                        ;;
                    "0")
                        print_warning "Installation wizard exited. The Backhaul binary is required for EasyBackhaul to operate."
                        press_any_key
                        return 1
                        ;;
                    *)  print_warning "Invalid option selected in installation wizard."; press_any_key ;;
                esac
                ;;
            1) # Default/Enter with no input - treat as invalid for this menu
                print_warning "Invalid selection. Please choose a number or navigation key."
                press_any_key
                ;;
            2) # Help shown
                continue ;;
            3) # Main menu ('m')
                print_warning "Installation wizard exited. The Backhaul binary is required for EasyBackhaul to operate."
                press_any_key
                return 1 ;;
            4) # Exit script ('e' or 'x')
                request_script_exit; return 0 ;;
            5) # Return/Back ('r')
                print_warning "Installation wizard exited. The Backhaul binary is required for EasyBackhaul to operate."
                press_any_key
                return 1 ;;
            *) # Should not happen
                print_warning "Unexpected return from menu_loop in wizard."
                press_any_key
                ;;
        esac

        if $install_success && [[ -f "$BIN_PATH" ]] && verify_binary_installation; then
            handle_success "Backhaul binary installed successfully!"
            press_any_key
            return 0 # Successful installation
        elif $install_success; then
             handle_error "ERROR" "Installation seemed to complete, but binary verification failed."
             press_any_key # Allow user to see message then loop back to wizard options
        fi
        # If not install_success, loop continues to show wizard options again.
    done
}

system_health_monitor_menu() {
    _health_monitor_menu_help() {
        print_menu_header "secondary" "System Health Monitor Help" "System Overview"
        echo "This screen provides an overview of system resources, tunnel health, and performance."
        echo "Options:"
        echo "  1. Refresh: Reloads all the displayed health information."
        echo "  2. Clean Stale Processes & Temp Files: Attempts to remove known temporary files or orphaned processes."
        echo "  3. View System Logs: Access logs like easybackhaul.log or performance.log."
        # ... (full help text)
        press_any_key
    }
    
    local health_menu_options=(
        "1. Refresh Health Status"
        "2. Clean Stale Processes & Temp Files"
        "3. View System Logs (e.g., easybackhaul.log, performance.log)"
    )
    local health_exit_details=("0" "Back to Main Menu")
    local user_choice menu_rc

    while true; do
        print_menu_header "primary" "System Health & Performance Monitor" "Overview"
        display_system_resources; echo
        print_info "--- Tunnel Health Status ---"
        mapfile -t tunnel_config_files < <(find "$CONFIG_DIR" -maxdepth 1 -name "config-bh-*.toml" -type f 2>/dev/null | sort)
        if [[ ${#tunnel_config_files[@]} -eq 0 ]]; then print_warning "  No tunnels configured."; else
            local healthy_tunnels=0
            for cfg_file in "${tunnel_config_files[@]}"; do
                local suffix status_color status_text service
                suffix=$(basename "$cfg_file" .toml | sed 's/^config-//'); service="backhaul-${suffix}.service"
                if systemctl is-active --quiet "$service" 2>/dev/null; then status_text="Running"; status_color="$COLOR_GREEN"; ((healthy_tunnels++));
                elif systemctl is-failed --quiet "$service" 2>/dev/null; then status_text="Failed"; status_color="$COLOR_RED";
                else status_text="Stopped/Inactive"; status_color="$COLOR_YELLOW"; fi
                echo -e "  Tunnel: $suffix - Status: ${status_color}${status_text}${COLOR_RESET}"; done
            print_info "  Summary: $healthy_tunnels / ${#tunnel_config_files[@]} tunnels appear healthy."; fi; echo
        print_info "--- Recent Performance Log ---"
        if [[ -n "$PERFORMANCE_LOG_FILE" && -f "$PERFORMANCE_LOG_FILE" ]]; then tail -n 5 "$PERFORMANCE_LOG_FILE" | sed 's/^/    /' || print_warning "  Could not read performance log."; else print_warning "  Performance log file not configured or not found."; fi; echo
        print_info "--- Active Watcher Processes (Summary) ---" # Corrected from Chinese characters
        if pgrep -f "$EASYBACKHAUL_TMP_DIR/backhaul-watcher-.*\.sh" >/dev/null; then pgrep -af "$EASYBACKHAUL_TMP_DIR/backhaul-watcher-.*\.sh" | sed 's/^/    /'; else print_info "  No active watcher processes found."; fi

        menu_loop "Select action" health_menu_options health_exit_details "_health_monitor_menu_help"
        user_choice="$MENU_CHOICE"; menu_rc=$?
        
        case "$menu_rc" in
            0) # Numeric or "0"
                case "$user_choice" in
                    "1") continue ;; # Refresh by re-looping
                    "2") run_with_spinner "Cleaning stale processes and files..." cleanup_stale_processes_and_files; press_any_key ;;
                    "3")
                        if [[ -n "$LOG_DIR" ]]; then
                            # This should ideally be a navigable menu if there are multiple logs.
                            # For now, just view one. If view_system_log becomes a menu, use navigate_to_menu.
                            view_system_log "file" "$LOG_DIR/easybackhaul.log" "EasyBackhaul Main Log"
                        else
                            handle_error "WARNING" "LOG_DIR not defined."
                            press_any_key
                        fi
                        ;;
                    "0") return_from_menu; return 0 ;; # Back to Main Menu
                    *) print_warning "Invalid option."; press_any_key ;;
                esac
                ;;
            1) print_warning "Invalid selection."; press_any_key ;;
            2) continue ;; # Help shown
            3) go_to_main_menu; return 0 ;;
            4) request_script_exit; return 0 ;;
            5) return_from_menu; return 0 ;; # 'r' (Back) is same as "0" here
            *) print_warning "Unexpected menu_loop return."; press_any_key ;;
        esac
    done
}

_perform_full_uninstall() {
    print_menu_header "primary" "Uninstall EasyBackhaul" "Irreversible Action"
    print_warning "WARNING: This will PERMANENTLY REMOVE EasyBackhaul and ALL related data!"
    echo "This includes:"
    echo "  - The Backhaul binary ($BIN_PATH)"
    echo "  - All tunnel configurations ($CONFIG_DIR)"
    echo "  - All systemd services (e.g., backhaul-*.service in $SERVICE_DIR)"
    echo "  - All UFW rules managed by EasyBackhaul (if UFW is used)"
    echo "  - All EasyBackhaul-managed cron jobs."
    echo "  - Temporary files and watcher scripts (typically in $EASYBACKHAUL_TMP_DIR or /tmp)"
    echo "  - Backup files ($BACKUP_DIR)"
    echo "  - Potentially log files ($LOG_DIR) - you will be asked about this."

    if ! prompt_yes_no "Are you absolutely sure you want to proceed with uninstallation?" "n"; then
        print_info "Uninstallation cancelled."; press_any_key; return 1; fi

    local confirm_uninstall_text="UNINSTALL EASYBACKHAUL NOW"
    local user_confirmation
    read -r -p "To confirm, type '$confirm_uninstall_text': " user_confirmation
    if [[ "$user_confirmation" != "$confirm_uninstall_text" ]]; then
        handle_error "ERROR" "Confirmation text did not match. Uninstallation aborted."; press_any_key; return 1; fi

    log_message "WARN" "Starting full uninstallation of EasyBackhaul..."

    print_info "Stopping and disabling all Backhaul services..."
    mapfile -t service_files < <(systemctl list-unit-files --type=service "backhaul-bh-*.service" "backhaul-watcher-*.service" --no-legend --full --all | awk '{print $1}')
    if [[ ${#service_files[@]} -gt 0 ]]; then
        for service_name in "${service_files[@]}"; do
            run_with_spinner "Stopping $service_name..." systemctl stop "$service_name"
            run_with_spinner "Disabling $service_name..." systemctl disable "$service_name"
            local suffix_to_clean
            if [[ "$service_name" == backhaul-bh-*.service ]]; then
                suffix_to_clean=${service_name#backhaul-} # bh-server-tcp-xxxx.service
                suffix_to_clean=${suffix_to_clean%.service} # bh-server-tcp-xxxx
                 # Also clean up watcher files for this main tunnel suffix
                cleanup_watcher_files "$suffix_to_clean" "true" # Quietly
            elif [[ "$service_name" == backhaul-watcher-*.service ]]; then
                suffix_to_clean=${service_name#backhaul-watcher-} # server-tcp-xxxx.service (example)
                suffix_to_clean=${suffix_to_clean%.service} # server-tcp-xxxx
                cleanup_watcher_files "$suffix_to_clean" "true" # Quietly
            fi
        done
    else
        print_info "No 'backhaul-bh-*.service' or 'backhaul-watcher-*.service' services found."
    fi
    
    log_message "INFO" "Performing general watcher file cleanup from $EASYBACKHAUL_TMP_DIR (and /tmp for legacy)..."
    find "${EASYBACKHAUL_TMP_DIR:-/tmp}" -maxdepth 1 \( -name 'backhaul-watcher-*' -o -name 'restart_ack_*' \) -print -exec rm -rf {} \; &>/dev/null
    # Legacy /tmp cleanup if EASYBACKHAUL_TMP_DIR is different and not /tmp
    if [[ -n "$EASYBACKHAUL_TMP_DIR" && "$EASYBACKHAUL_TMP_DIR" != "/tmp" ]]; then
        find "/tmp" -maxdepth 1 \( -name 'backhaul-watcher-*' -o -name 'restart_ack_*' \) -print -exec rm -rf {} \; &>/dev/null
    fi

    print_info "Removing systemd service files..."
    if [[ -d "$SERVICE_DIR" ]]; then
        secure_delete "${SERVICE_DIR}/backhaul-bh-*.service"
        secure_delete "${SERVICE_DIR}/backhaul-watcher-*.service" # Remove watcher services too
        # General cleanup for any other backhaul service that might have been missed.
        secure_delete "${SERVICE_DIR}/backhaul-*.service"
    fi
    run_with_spinner "Reloading systemd daemon..." systemctl daemon-reload
    
    print_info "Removing UFW rules..."
    if type delete_all_easybackhaul_ufw_rules &>/dev/null; then
        delete_all_easybackhaul_ufw_rules
    else
        log_message "WARN" "'delete_all_easybackhaul_ufw_rules' not found. Attempting pattern based deletion."
        mapfile -t ufw_rules_to_delete < <(ufw status numbered 2>/dev/null | grep -iE "EasyBackhaul:|Backhaul-" | awk -F'[][]' '{print $2}' | sort -nr)
        if [[ ${#ufw_rules_to_delete[@]} -gt 0 ]]; then
            print_info "Found ${#ufw_rules_to_delete[@]} UFW rules to delete..."
            for rule_num in "${ufw_rules_to_delete[@]}"; do
                run_with_spinner "Deleting UFW rule #$rule_num..." sh -c "echo y | ufw delete $rule_num"
            done
            run_with_spinner "Reloading UFW..." ufw reload
        else
            print_info "No specific EasyBackhaul UFW rules found by common patterns."
        fi
    fi
    
    print_info "Removing EasyBackhaul cron jobs..."
    if command -v crontab &>/dev/null && [[ -n "$CRON_COMMENT_TAG" ]]; then
        (crontab -l 2>/dev/null | grep -vF "# $CRON_COMMENT_TAG") | crontab -
        log_message "INFO" "Removed cron jobs tagged with '$CRON_COMMENT_TAG'."
    else
        log_message "WARN" "Cannot remove cron jobs (crontab not found or CRON_COMMENT_TAG empty)."
    fi
    
    print_info "Removing files and directories..."
    if [[ -n "$BIN_PATH" && -f "$BIN_PATH" ]]; then secure_delete "$BIN_PATH"; fi
    if [[ -n "$CONFIG_DIR" && -d "$CONFIG_DIR" ]]; then secure_delete "$CONFIG_DIR"; fi
    if [[ -n "$BACKUP_DIR" && -d "$BACKUP_DIR" ]]; then secure_delete "$BACKUP_DIR"; fi
    # Remove EASYBACKHAUL_TMP_DIR if it was set and is a directory
    if [[ -n "$EASYBACKHAUL_TMP_DIR" && -d "$EASYBACKHAUL_TMP_DIR" && "$EASYBACKHAUL_TMP_DIR" != "/tmp" ]]; then
        secure_delete "$EASYBACKHAUL_TMP_DIR"
    fi


    if [[ -n "$LOG_DIR" && -d "$LOG_DIR" ]]; then
        if prompt_yes_no "Also delete the main log directory $LOG_DIR and its contents?" "n"; then
            secure_delete "$LOG_DIR"
            handle_success "Log directory $LOG_DIR deleted."
        else
            print_info "Log directory $LOG_DIR preserved."
        fi
    fi
    
    handle_success "EasyBackhaul uninstallation completed."
    print_info "Some manual cleanup of system logs (journalctl) might be desired."
    print_info "Exiting now."
    exit 0 # Successful exit after uninstallation
}

main_menu_entry() {
    local binary_status_msg="Binary Status: "
    if [[ -f "$BIN_PATH" ]]; then
        if [[ ! -x "$BIN_PATH" ]]; then binary_status_msg+="${COLOR_YELLOW}Found but NOT EXECUTABLE${COLOR_RESET} at $BIN_PATH"
        else
            local version_info; version_info=$("$BIN_PATH" --version 2>/dev/null || "$BIN_PATH" -v 2>/dev/null | head -n1)
            if [[ -n "$version_info" ]]; then binary_status_msg+="${COLOR_GREEN}OK ($version_info)${COLOR_RESET}"
            else binary_status_msg+="${COLOR_GREEN}OK (Version unknown)${COLOR_RESET}"; fi
        fi
    else binary_status_msg+="${COLOR_RED}NOT INSTALLED${COLOR_RESET} (Expected: $BIN_PATH)"; fi

    print_menu_header "primary" "EasyBackhaul Management Menu" "$binary_status_msg"

    local main_menu_options=(
        "1. Configure a New Tunnel"
        "2. Manage Existing Tunnels"
        "3. Update/Re-install Backhaul Binary"
        "4. Generate Self-Signed TLS Certificate"
        "5. System Health & Performance Monitor"
        "6. Clean Stale Processes & Temp Files"
        "7. Manage UFW Firewall (if installed)"
        "8. Uninstall EasyBackhaul"
    )
    local main_exit_details=("0" "Exit EasyBackhaul")
    local user_choice menu_rc

    # The help function "show_main_application_help" should be defined in helpers.sh or similar
    # and passed by name to menu_loop.
    local help_func_name="show_main_application_help"
    if ! type "$help_func_name" &>/dev/null; then
        # Fallback generic help if specific one isn't found
        _generic_main_menu_help() {
            print_menu_header "secondary" "Main Menu Help"
            echo "This is the main control panel for EasyBackhaul."
            echo "Use the number keys to select an option from the menu."
            echo "Follow prompts for each section."
            echo "The footer shows navigation keys: [?] Help, [r] Back, [m] Main Menu, [e] Exit."
            press_any_key
        }
        help_func_name="_generic_main_menu_help"
    fi

    menu_loop "Select option" main_menu_options main_exit_details "$help_func_name"
    user_choice="$MENU_CHOICE"; menu_rc=$?

    case "$menu_rc" in
        0) # Numeric or "0"
            case "$user_choice" in
                "1") navigate_to_menu "configure_tunnel" ;;
                "2") navigate_to_menu "manage_tunnels_menu" ;;
                "3")
                    # download_backhaul_binary_workflow is not a full menu, it's a procedure.
                    # Call it directly. If it needs to be a menu, it should be structured like one.
                    if download_backhaul_binary_workflow; then
                        handle_success "Backhaul binary update/re-install process completed."
                    else
                        handle_error "WARNING" "Backhaul binary update/re-install was cancelled or failed."
                    fi
                    press_any_key
                    ;;
                "4")
                    if generate_self_signed_tls_cert; then
                        handle_success "TLS certificate generation process completed."
                    else
                        handle_error "WARNING" "TLS certificate generation was cancelled or failed."
                    fi
                    press_any_key
                    ;;
                "5") navigate_to_menu "system_health_monitor_menu" ;;
                "6") run_with_spinner "Cleaning stale processes and temporary files..." cleanup_stale_processes_and_files; press_any_key ;;
                "7")
                    if command -v ufw &>/dev/null; then
                        navigate_to_menu "manage_ufw_main_menu"
                    else
                        handle_error "WARNING" "UFW is not installed or not found in PATH."
                        press_any_key
                    fi
                    ;;
                "8")
                    _perform_full_uninstall # This function exits the script on success
                    # If uninstall is cancelled, _perform_full_uninstall returns, and we loop main menu.
                    ;;
                "0") request_script_exit ;; # Default exit for main menu is full script exit
                 *) print_warning "Invalid selection from main_menu_entry."; press_any_key ;;
            esac
            ;;
        1) print_warning "Invalid selection."; press_any_key ;; # Default/Enter
        2) return 0 ;; # Help shown, re-render main menu by returning and letting loop call again
        3) go_to_main_menu; return 0 ;; # 'm' (Main Menu) - effectively a refresh
        4) request_script_exit; return 0 ;; # 'e' (Exit)
        5) request_script_exit; return 0 ;; # 'r' (Back) from main menu also means exit
        *) print_warning "Unexpected menu_loop return."; press_any_key ;;
    esac
    return 0 # Return 0 to allow the main script loop to call this function again
}

main_script_entry_point() {
    # Initialize logging as the very first step
    if type init_logging &>/dev/null; then
        init_logging # Sets up LOG_FILE, EASYBACKHAUL_TMP_DIR etc.
    else
        echo "FATAL ERROR: init_logging function not found. Cannot proceed." >&2
        exit 1
    fi

    log_message "INFO" "EasyBackhaul script started."

    # Default global variables (some might be overridden by init_logging or user config later)
    # These are fallbacks if not set by init_logging from a config file or defaults.
    : "${CONFIG_DIR:=$EASYBACKHAUL_APP_DIR/config}"
    : "${BACKUP_DIR:=$EASYBACKHAUL_APP_DIR/backup}"
    : "${BIN_PATH:=$EASYBACKHAUL_APP_DIR/bin/easybackhaul_binary}"
    : "${SERVICE_DIR:=/etc/systemd/system}" # Standard systemd location
    # LOG_DIR, LOG_LEVEL, LOG_FORMAT should be definitively set by init_logging
    : "${CRON_COMMENT_TAG:=EasyBackhaul}"
    # HEALTH_LOG_FILE and PERFORMANCE_LOG_FILE path depends on LOG_DIR
    : "${HEALTH_LOG_FILE:=${LOG_DIR:-/var/log/easybackhaul}/easybackhaul_health.log}"
    : "${PERFORMANCE_LOG_FILE:=${LOG_DIR:-/var/log/easybackhaul}/easybackhaul_performance.log}"

    # Ensure critical directories exist after globals are established
    # This needs to happen after init_logging which sets EASYBACKHAUL_APP_DIR
    # and potentially custom CONFIG_DIR, LOG_DIR.
    ensure_dir_wrapper() {
        local dir_path="$1"
        local permissions="${2:-700}" # Default permissions
        if [[ -z "$dir_path" ]]; then
            log_message "WARN" "ensure_dir_wrapper: Directory path is empty. Skipping."
            return
        fi
        if type ensure_dir &>/dev/null; then
            ensure_dir "$dir_path" "$permissions"
        else
            # Basic fallback if ensure_dir is missing (should not happen if helpers are sourced)
            mkdir -p "$dir_path" && chmod "$permissions" "$dir_path"
            log_message "WARN" "ensure_dir function not found. Used basic mkdir -p."
        fi
    }

    ensure_dir_wrapper "$EASYBACKHAUL_APP_DIR" "755" # Main app dir
    ensure_dir_wrapper "$(dirname "$BIN_PATH")" "755" # Binary directory
    ensure_dir_wrapper "$CONFIG_DIR" "700"
    ensure_dir_wrapper "$BACKUP_DIR" "700"
    ensure_dir_wrapper "$LOG_DIR" "700" # Log directory

    if [[ $EUID -ne 0 ]]; then handle_critical_error "This script must be run as root or with sudo."; fi # Exits
    
    if type check_dependencies &>/dev/null; then check_dependencies; # Exits on critical missing deps
    else handle_critical_error "check_dependencies function not found."; fi
    
    if type get_server_info &>/dev/null; then get_server_info; else log_message "WARN" "get_server_info not found."; fi

    # Binary installation check
    if [[ ! -f "$BIN_PATH" ]] || ! verify_binary_installation "quiet"; then
        log_message "WARN" "Backhaul binary not found or failed verification at $BIN_PATH. Starting installation wizard."
        # _initial_installation_wizard returns 0 on success, 1 on failure/cancel
        if ! _initial_installation_wizard; then
            # Check again, as user might have cancelled but binary exists from previous attempt
            if [[ ! -f "$BIN_PATH" ]] || ! verify_binary_installation "quiet"; then
                 handle_critical_error "Backhaul binary installation was not completed or is invalid. Exiting."
            else
                 log_message "INFO" "Binary found and verified after wizard exit. Proceeding."
            fi
        fi
    fi

    # Initialize menu navigation stack
    CURRENT_MENU_FUNCTION="main_menu_entry"
    MENU_STACK=("main_menu_entry") # Stack of menu function names

    log_message "DEBUG" "Menu system initialized. Starting main loop for $CURRENT_MENU_FUNCTION"

    # Main menu loop
    while [[ -n "$CURRENT_MENU_FUNCTION" ]]; do
        log_message "DEBUG" "Main loop - Current Menu: $CURRENT_MENU_FUNCTION, Stack: [${MENU_STACK[*]}]"
        if type "$CURRENT_MENU_FUNCTION" &>/dev/null; then
            "$CURRENT_MENU_FUNCTION" # Execute the current menu function
        else
            handle_critical_error "Menu function '$CURRENT_MENU_FUNCTION' not found. Stack: [${MENU_STACK[*]}]."
        fi

        # After a menu function returns, CURRENT_MENU_FUNCTION might have been changed by navigation functions
        # If MENU_STACK is empty, it means request_script_exit or similar was called.
        if [[ ${#MENU_STACK[@]} -eq 0 ]]; then
            log_message "DEBUG" "Menu stack is empty. Exiting main loop."
            CURRENT_MENU_FUNCTION="" # Ensure loop terminates
        fi
        # If CURRENT_MENU_FUNCTION was set by navigate_to_menu, loop continues with new function.
        # If it was cleared by return_from_menu and stack became empty, loop terminates.
        # If it was cleared by return_from_menu and stack is not empty, CURRENT_MENU_FUNCTION is already set to top of stack.
    done

    log_message "INFO" "EasyBackhaul script finished."
    if type print_info &>/dev/null; then
        print_info "Exiting EasyBackhaul."
    else
        echo "Exiting EasyBackhaul."
    fi
}

true # Ensure script is valid if sourced

# <<< START OF SCRIPT EXECUTION >>>
# This call should be the very last thing in the concatenated easybh.sh
# Ensure all necessary files are sourced before this point by build.sh
main_script_entry_point
