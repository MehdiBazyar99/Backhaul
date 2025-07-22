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
# Using /etc for persistent configurations and /var/log for logs.
# /tmp is still used for transient items like backups or temporary binary location.
CONFIG_DIR="/etc/easybackhaul/configs"
BACKUP_DIR="/tmp/easybackhaul_backups" # Backups can remain in /tmp or move to /var/backups/easybackhaul
BIN_PATH="/tmp/easybackhaul_bin/easybackhaul_binary"
SERVICE_DIR="/etc/systemd/system"
LOG_DIR="/var/log/easybackhaul" # Standard log location

CRON_COMMENT_TAG="EasyBackhaul"

# Generate a random secret for restart watcher if not already set
# This secret is a global default; per-tunnel secrets can also be used.
GLOBAL_WATCHER_SECRET_FILE="${CONFIG_DIR}/watcher_master.secret" # Path updated

# Helper function scoped to this file for early CONFIG_DIR creation if needed.
# This is because helpers.sh (with ensure_dir) isn't sourced yet.
_globals_ensure_config_dir_for_secret() {
    if [[ ! -d "$CONFIG_DIR" ]]; then
        # Create parent directory /etc/easybackhaul first, then the configs subdir
        # This ensures correct ownership and permissions are set progressively.
        local parent_dir
        parent_dir=$(dirname "$CONFIG_DIR") # /etc/easybackhaul

        if [[ ! -d "$parent_dir" ]]; then
            mkdir -p "$parent_dir"
            if [[ $? -ne 0 ]]; then
                echo "ERROR: [_globals_ensure_config_dir_for_secret] Failed to create parent directory: $parent_dir. Please check permissions." >&2
                return 1
            fi
            # Set ownership to root:nogroup and permissions to 0750 for the parent directory
            # This allows members of 'nogroup' (like 'nobody') to traverse into /etc/easybackhaul
            chown root:nogroup "$parent_dir"
            chmod 0750 "$parent_dir"
        fi

        mkdir -p "$CONFIG_DIR"
        if [[ $? -ne 0 ]]; then
            echo "ERROR: [_globals_ensure_config_dir_for_secret] Failed to create CONFIG_DIR: $CONFIG_DIR. Please check permissions." >&2
            return 1
        fi
        # Set ownership to root:nogroup and permissions to 0770 for the configs directory
        # This allows 'nogroup' to read/write/execute (list files) in this directory.
        # Individual config files will be 'nobody:nogroup' and '640'.
        chown root:nogroup "$CONFIG_DIR"
        chmod 0770 "$CONFIG_DIR"
        return 0
    fi

    # If directory already exists, ensure its permissions and ownership are correct.
    # This handles cases where the script might have run before with different settings.
    if [[ -d "$CONFIG_DIR" ]]; then
        # Ensure parent directory /etc/easybackhaul also has correct perms/owner
        local existing_parent_dir
        existing_parent_dir=$(dirname "$CONFIG_DIR")
        if [[ -d "$existing_parent_dir" ]]; then
            if [[ $(stat -c "%U:%G" "$existing_parent_dir") != "root:nogroup" ]]; then
                chown root:nogroup "$existing_parent_dir" || echo "WARNING: Failed to chown $existing_parent_dir to root:nogroup" >&2
            fi
            if [[ $(stat -c "%a" "$existing_parent_dir") != "750" ]]; then
                 # Check if current perms are more open, e.g. 755, if so, leave them. Otherwise set to 750.
                current_perms_parent=$(stat -c "%a" "$existing_parent_dir")
                if [[ "$current_perms_parent" -lt "750" && "$current_perms_parent" != "750" ]]; then # if less than 0750, set it
                    chmod 0750 "$existing_parent_dir" || echo "WARNING: Failed to chmod $existing_parent_dir to 0750" >&2
                fi
            fi
        fi

        # Check and set CONFIG_DIR permissions
        if [[ $(stat -c "%U:%G" "$CONFIG_DIR") != "root:nogroup" ]]; then
            chown root:nogroup "$CONFIG_DIR" || {
                echo "WARNING: [_globals_ensure_config_dir_for_secret] Failed to chown existing CONFIG_DIR $CONFIG_DIR to root:nogroup." >&2
            }
        fi
        # Current permissions for CONFIG_DIR should be 0770.
        # If they are more permissive (e.g., 775, 777), that's okay. If less, set to 0770.
        current_perms_config_dir=$(stat -c "%a" "$CONFIG_DIR")
        if [[ "$current_perms_config_dir" -lt "770" && "$current_perms_config_dir" != "770" ]]; then # if less than 0770, set it
            chmod 0770 "$CONFIG_DIR" || {
                echo "WARNING: [_globals_ensure_config_dir_for_secret] Failed to ensure 0770 permissions on existing CONFIG_DIR: $CONFIG_DIR." >&2
            }
        fi
    fi
    return 0 # Dir already exists and permissions checked/set
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

# --- Backhaul Binary Default Optional Parameters ---
# These are used by easybh.sh for "Advanced Setup" if the user doesn't override.
# "Quick Setup" will omit these, relying on Backhaul binary's internal defaults.

BH_DEFAULT_LOG_LEVEL="info"
BH_DEFAULT_SNIFFER="false"
# BH_DEFAULT_SNIFFER_LOG - Path is context-dependent, generated in configure_tunnel if sniffer enabled.
BH_DEFAULT_WEB_PORT=0         # 0 means disabled
BH_DEFAULT_NODELAY="true"     # For TCP-based transports
BH_DEFAULT_KEEPALIVE_PERIOD=75 # For TCP-based transports

# Server-specific defaults
BH_DEFAULT_HEARTBEAT=40
BH_DEFAULT_CHANNEL_SIZE=2048
BH_DEFAULT_ACCEPT_UDP="false" # For TCP/TCPMUX server

# Client-specific defaults
BH_DEFAULT_CONNECTION_POOL=8
BH_DEFAULT_AGGRESSIVE_POOL="false"
BH_DEFAULT_RETRY_INTERVAL=3
BH_DEFAULT_DIAL_TIMEOUT=10
# BH_DEFAULT_EDGE_IP - Typically empty or user-provided.

# MUX-specific defaults (common for client/server if mux is used)
BH_DEFAULT_MUX_CON=8
BH_DEFAULT_MUX_VERSION=1
BH_DEFAULT_MUX_FRAMESIZE=32768
BH_DEFAULT_MUX_RECEIVEBUFFER=4194304 # Using corrected spelling 'receive'
BH_DEFAULT_MUX_STREAMBUFFER=65536   # Was 256KB (262144) in README, using prior easybh.sh default

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
    # LOG_DIR is now defined in globals.sh as /var/log/easybackhaul
    # Ensure LOG_DIR exists and has appropriate permissions.
    # The user running easybh.sh (likely root) will create this.
    # Services running as 'nobody' will write to files here, so group writability might be needed
    # or files need specific 'nobody:nogroup' ownership.
    # For simplicity, we'll make LOG_DIR root:adm 0775 or root:nogroup 0775,
    # and log files root:adm 0664 or nobody:nogroup 0664.
    # 'adm' group is standard for log access. 'nogroup' if 'nobody' needs to write directly.

    if [[ -z "$LOG_DIR" ]]; then
        handle_critical_error "LOG_DIR global variable is not set. Logging cannot be initialized."
        return 1
    fi

    if [[ ! -d "$LOG_DIR" ]]; then
        mkdir -p "$LOG_DIR" || { handle_critical_error "Failed to create LOG_DIR: $LOG_DIR"; return 1; }
    fi

    # Set ownership and permissions for LOG_DIR
    # Try chown to root:adm, then root:nogroup as fallback, then root:root.
    # Permissions 0775 allow owner/group to write, others to read/execute.
    if id -g adm >/dev/null 2>&1; then
        chown root:adm "$LOG_DIR" && chmod 0775 "$LOG_DIR"
    elif id -g nogroup >/dev/null 2>&1; then
        chown root:nogroup "$LOG_DIR" && chmod 0775 "$LOG_DIR"
    else
        chown root:root "$LOG_DIR" && chmod 0755 "$LOG_DIR" # Fallback to root:root 0755
    fi
    
    # Main log file
    local main_log_file="$LOG_DIR/easybackhaul.log"
    touch "$main_log_file" || { handle_error "WARN" "Failed to touch main log file: $main_log_file"; }
    # Set permissions for the main log file. If services write here as 'nobody',
    # they'll need write permission. root:adm 664 or nobody:nogroup 664.
    if id -g adm >/dev/null 2>&1; then
        chown root:adm "$main_log_file" && chmod 0664 "$main_log_file"
    elif id -g nogroup >/dev/null 2>&1; then
        chown nobody:nogroup "$main_log_file" && chmod 0664 "$main_log_file" # Allow easybackhaul_binary to write if it runs as nobody
    else
        chown root:root "$main_log_file" && chmod 0640 "$main_log_file"
    fi


    # Specific log files (health, performance) - these are typically written by easybh.sh itself (root)
    if [[ -n "${HEALTH_LOG_FILE:-}" && "$HEALTH_LOG_FILE" != "$main_log_file" ]]; then
        touch "$HEALTH_LOG_FILE" && chmod 0640 "$HEALTH_LOG_FILE" && chown root:root "$HEALTH_LOG_FILE" 2>/dev/null
    fi
    if [[ -n "${PERFORMANCE_LOG_FILE:-}" && "$PERFORMANCE_LOG_FILE" != "$main_log_file" ]]; then
        touch "$PERFORMANCE_LOG_FILE" && chmod 0640 "$PERFORMANCE_LOG_FILE" && chown root:root "$PERFORMANCE_LOG_FILE" 2>/dev/null
    fi
    
    if command -v logrotate &>/dev/null; then
        setup_log_rotation
    fi
}

# Setup log rotation for easybackhaul logs
setup_log_rotation() {
    # LOG_DIR is now /var/log/easybackhaul
    local current_log_dir="$LOG_DIR"
    local logrotate_conf_target="/etc/logrotate.d/easybackhaul"
    # No longer using sandbox path for logrotate config, directly target /etc/logrotate.d
    local max_files_to_rotate="${LOG_MAX_FILES:-5}"

    # Determine user/group for created log files by logrotate.
    # Default to root:adm if adm group exists, else root:root or root:nogroup.
    local logrotate_create_user="root"
    local logrotate_create_group="root"
    if id -g adm >/dev/null 2>&1; then
        logrotate_create_group="adm"
    elif id -g nogroup >/dev/null 2>&1; then
         logrotate_create_group="nogroup" # If backhaul binary logs as nobody:nogroup
    fi

    log_message "INFO" "Attempting to create/update logrotate configuration at $logrotate_conf_target."

    # Check if we can write to /etc/logrotate.d (requires root)
    if [[ ! -w "$(dirname "$logrotate_conf_target")" && "$(id -u)" -ne 0 ]]; then
        print_warning "Cannot write to $(dirname "$logrotate_conf_target"). Logrotate setup skipped. Run as root or setup manually."
        log_message "WARN" "Logrotate setup skipped due to insufficient permissions for $logrotate_conf_target."
        return 1
    fi

    cat > "$logrotate_conf_target" << EOF
${current_log_dir}/*.log {
    daily
    missingok
    rotate ${max_files_to_rotate}
    compress
    delaycompress
    notifempty
    create 0640 ${logrotate_create_user} ${logrotate_create_group}
    postrotate
        # If services write to these logs, they might need a signal to reopen log files.
        # For simple file logs by backhaul binary, this is usually not needed unless it keeps file handle open.
        # Example: systemctl kill -s HUP backhaul-*.service >/dev/null 2>&1 || true
    endscript
}
EOF
    chmod 0644 "$logrotate_conf_target"
    log_message "DEBUG" "Logrotate configuration created/updated at $logrotate_conf_target."
}

# Unified logging function
log_message() {
    local level="$1"
    local message="$2"

    # LOG_DIR is now reliably set by globals.sh and init_logging ensures it exists.
    local log_file_to_use="${LOG_FILE_OVERRIDE:-$LOG_DIR/easybackhaul.log}"
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
    # Test for OpenBSD netcat compatibility.
    # The key features we need are '-l' for listen, '-p' for port, and '-w' for timeout.
    # Using a high, non-standard port to avoid conflicts.
    local test_port=49151 # A high, ephemeral port
    local nc_test_output=""
    local nc_command_successful=false

    # Ensure the test port is free before starting
    if ! check_port_availability "$test_port"; then
        log_message "WARN" "Netcat compatibility check: Test port $test_port is in use. Skipping check for now."
        # We can't be certain, so we cautiously assume it's compatible to not block functionality.
        # A more robust solution might try a different port.
        NC_COMPATIBLE="true"
        return 0
    fi

    # The test: listen on a port for 2 seconds, and send a message to it.
    # If the message is received, 'nc' is likely compatible.
    # We use a subshell and backgrounding to run listener and sender concurrently.
    (
        # Listener part
        # Redirect stderr to stdout to capture any error messages from 'nc -l'
        nc -l -p "$test_port" -w 3 2>&1
    ) > /tmp/nc_test_output.txt &
    local listener_pid=$!

    sleep 0.5 # Give the listener a moment to start

    # Sender part
    echo "test" | nc 127.0.0.1 "$test_port" -w 1 >/dev/null 2>&1

    # Wait for the listener to exit (it should after receiving data or timing out)
    wait "$listener_pid" 2>/dev/null

    nc_test_output=$(cat /tmp/nc_test_output.txt 2>/dev/null)
    rm -f /tmp/nc_test_output.txt

    # Check if the listener received the "test" message.
    if echo "$nc_test_output" | grep -q "test"; then
        nc_command_successful=true
    fi

    # Check for common error messages in the output of 'nc -l'.
    if ! $nc_command_successful || echo "$nc_test_output" | grep -qiE 'usage:|invalid option|requires an argument|refused'; then
        log_message "ERROR" "Netcat (nc) compatibility check failed. Output: $nc_test_output"
        print_error "Netcat (nc) is not compatible. The watcher feature will not work."
        print_info "Please install 'netcat-openbsd' (Debian/Ubuntu) or 'nmap-ncat' (CentOS/RHEL/Fedora)."
        if command -v ncat &>/dev/null; then
            print_info "Found 'ncat'. You might need to make it the default 'nc' via alternatives or symlink."
        fi
        NC_COMPATIBLE="false"
        return 1
    fi

    log_message "DEBUG" "Netcat compatibility check passed. Output: $nc_test_output"
    NC_COMPATIBLE="true"
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
    echo " [?] Help | [r] Return/Back/Cancel | [m] Main Menu | [x] Exit Script"
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
# Sets MENU_CHOICE globally.
# Returns:
#   0: Valid NUMERIC choice. MENU_CHOICE holds the number string.
#   2: '?' (Help) was pressed. MENU_CHOICE holds '?'. (Help function, if any, was called).
#   3: 'm' (Main Menu) was pressed. MENU_CHOICE holds 'm'.
#   4: 'x' (Exit Script) was pressed. MENU_CHOICE holds 'x'.
#   5: 'r' (Return/Back/Cancel) was pressed. MENU_CHOICE holds 'r'.
#   6: Invalid input (empty or non-matching). Warning printed by menu_loop for non-empty invalid. MENU_CHOICE holds the invalid input. Caller should redraw.
menu_loop() {
    local prompt_msg="$1"
    local -n options_ref=$2 # Array of menu options like "1. Do X"
    local custom_help_function_name="${3:-}"

    local min_numeric_opt=1
    local max_numeric_opt=${#options_ref[@]}
    
    local prompt_numeric_choices_str=""
    if (( max_numeric_opt > 0 )); then
        if (( max_numeric_opt == 1 )); then
            prompt_numeric_choices_str="1"
        else
            prompt_numeric_choices_str="${min_numeric_opt}-${max_numeric_opt}"
        fi
    fi
    
    # This loop is now only for re-prompting on truly empty input after processing.
    # All other paths (special keys, valid numeric, invalid non-empty) will RETURN from the function.
    while true; do
        for opt_str in "${options_ref[@]}"; do
            echo -e "  $opt_str" # Use -e to interpret escape sequences
        done

        print_menu_footer # Display updated footer

        local full_prompt_str="$prompt_msg"
        local available_choices_display=""
        if [[ -n "$prompt_numeric_choices_str" ]]; then
            available_choices_display="$prompt_numeric_choices_str, "
        fi
        available_choices_display+="?, r, m, x"

        full_prompt_str+=" [${available_choices_display}]: "

        local raw_choice
        read -r -p "$full_prompt_str" raw_choice

        local processed_choice
        processed_choice=$(echo "$raw_choice" | tr '[:upper:]' '[:lower:]' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        MENU_CHOICE="$processed_choice"

        if [[ "$processed_choice" == "?" ]]; then
            if [[ -n "$custom_help_function_name" ]] && type "$custom_help_function_name" &>/dev/null; then
                "$custom_help_function_name"
            else
                print_info "No specific help available for this menu."
                press_any_key
            fi
            return 2
        elif [[ "$processed_choice" == "m" ]]; then
            return 3
        elif [[ "$processed_choice" == "x" ]]; then
            return 4
        elif [[ "$processed_choice" == "r" ]]; then
            return 5
        fi

        if [[ "$processed_choice" =~ ^[0-9]+$ ]]; then
            if (( max_numeric_opt == 0 )); then
                 print_warning "Invalid option: '$processed_choice'. No numeric options available. Use navigation keys."
                 press_any_key
                 return 6
            elif (( processed_choice >= min_numeric_opt && processed_choice <= max_numeric_opt )); then
                return 0
            else
                 print_warning "Invalid numeric option: '$processed_choice'. Choose from ${prompt_numeric_choices_str} or navigation keys."
                 press_any_key
                 return 6
            fi
        else # Not numeric, and wasn't a special key
            if [[ -n "$processed_choice" ]]; then
                print_warning "Invalid option: '$processed_choice'. Please use numbers or navigation keys: ?, r, m, x."
                press_any_key
                return 6
            else
                # processed_choice IS empty (user just pressed Enter or entered only spaces)
                # Return 6 to allow caller to redraw the full screen.
                # No warning or press_any_key from menu_loop for this specific case.
                return 6
            fi
        fi
        # Unreachable code due to returns in all paths above, unless processed_choice was initially empty
        # and the "else" for empty choice didn't return 6.
        # The loop should only continue if processed_choice was empty AND the "else" above didn't return 6.
        # Corrected logic: empty input now also returns 6. So this loop should not be hit again unless error.
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
        local menu_return_code=$?       # Return code from menu_loop
        local user_choice="$MENU_CHOICE" # MENU_CHOICE is set by menu_loop, capture after $?

        case "$menu_return_code" in
            0) # Numeric choice
                case "$user_choice" in # user_choice is the number string ("1", "2", etc.)
                    "1") # Interactive view (less)
                        if [[ "$log_source_type" == "journalctl" ]]; then
                            journalctl -u "$log_identifier" --no-pager | less
                        elif [[ -f "$log_identifier" ]]; then
                            less "$log_identifier"
                        else print_error "Log source not found: $log_identifier"; press_any_key; fi
                        ;;
                    "2") # Live follow
                        print_info "Starting live log follow. Press Ctrl+C to stop."
                        local original_trap_INT; original_trap_INT=$(trap -p INT)
                        trap 'print_warning "\nLive log follow interrupted."; eval "$original_trap_INT" 2>/dev/null || trap - INT; return 130' INT

                        if [[ "$log_source_type" == "journalctl" ]]; then
                            journalctl -u "$log_identifier" -f
                        elif [[ -f "$log_identifier" ]]; then
                            tail -f "$log_identifier"
                        else print_error "Log source not found: $log_identifier"; fi

                        eval "$original_trap_INT" 2>/dev/null || trap - INT # Restore original trap
                        print_info "Live log follow stopped." # This might only be seen if tail -f exits normally
                        press_any_key
                        ;;
                    "3") # View last 100 lines
                        if [[ "$log_source_type" == "journalctl" ]]; then
                            journalctl -u "$log_identifier" --no-pager -n 100
                        elif [[ -f "$log_identifier" ]]; then
                            tail -n 100 "$log_identifier"
                        else print_error "Log source not found: $log_identifier"; fi
                        press_any_key
                        ;;
                    "4") # Search logs
                        local search_term # Define search_term locally
                        read -r -p "Enter search term: " search_term
                        if [[ -n "$search_term" ]]; then
                            print_info "Searching for '$search_term' (last 200 matching lines)..."
                            if [[ "$log_source_type" == "journalctl" ]]; then
                                journalctl -u "$log_identifier" --no-pager | grep -iE --color=always "$search_term" | tail -n 200
                            elif [[ -f "$log_identifier" ]]; then
                                grep -iE --color=always "$search_term" "$log_identifier" | tail -n 200
                            else print_error "Log source not found: $log_identifier"; fi
                            press_any_key
                        fi
                        ;;
                    *) print_warning "Invalid numeric choice in view_system_log: $user_choice"; press_any_key ;;
                esac
                ;;
            2)  # '?' Help
                # Help function already called by menu_loop. Loop again to show menu.
                continue ;;
            3)  # 'm' Main Menu
                go_to_main_menu
                return 0 ;; # Return to main script loop to process navigation
            4)  # 'x' Exit Script
                request_script_exit
                return 0 ;; # Return to main script loop
            5)  # 'r' Return/Back/Cancel
                return_from_menu # This pops the stack, current func should return to main script loop
                return 0 ;;
            6)  # Invalid input in menu_loop (warning and press_any_key handled by menu_loop)
                continue ;; # Re-display this menu
            *)
                print_warning "Unexpected menu_loop return code in view_system_log: $menu_return_code (Choice: $user_choice)"
                press_any_key
                continue ;; # Re-display this menu
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
        "2. Install from Local .tar.gz File"
        "3. Use Existing Local Binary File" # New option
        "4. Install from Alternative URL"
        "5. Run Network Diagnostics"
        "6. Skip Installation (Advanced)"
    )
    local user_choice menu_rc

    while true; do
        print_menu_header "primary" "Backhaul Binary Installation" "Choose Installation Method"
        menu_loop "Select option" menu_options "_download_menu_help"
        local menu_rc=$?
        local user_choice="$MENU_CHOICE" # Capture MENU_CHOICE after $?
        
        local install_attempted=false
        local install_succeeded=false

        case "$menu_rc" in
            0) # Numeric choice
                install_attempted=true # Assume an install attempt unless it's diagnostics/skip
                case "$user_choice" in
                    "1") # GitHub Download
                        if _download_from_github "$system_os" "$detected_arch_suffix"; then install_succeeded=true; fi
                        ;;
                    "2") # Local .tar.gz File
                        if _download_from_local_file "$system_os" "$detected_arch_suffix"; then install_succeeded=true; fi
                        ;;
                    "3") # Use Existing Local Binary File (New)
                        if _use_existing_local_binary; then install_succeeded=true; fi
                        ;;
                    "4") # Alternative URL
                        if _download_from_alternative_source "$system_os" "$detected_arch_suffix"; then install_succeeded=true; fi
                        ;;
                    "5") # Network Diagnostics
                        if type run_network_diagnostics_menu &>/dev/null; then
                            navigate_to_menu "run_network_diagnostics_menu"
                            return 0 # Let main loop call it; run_network_diagnostics_menu will return here
                        else
                            handle_error "ERROR" "Network diagnostics function not available."; press_any_key
                        fi
                        install_attempted=false # Not an install attempt
                        ;;
                    "6") # Skip
                        print_warning "Skipping binary installation."
                        print_info "You can install the binary later using the main menu."
                        print_info "Ensure it's placed at: $BIN_PATH"
                        press_any_key
                        return 0 # Successfully skipped
                        ;;
                    *)
                        print_warning "Invalid option selected in download workflow: $user_choice"; press_any_key
                        install_attempted=false
                        ;;
                esac
                ;;
            2) # '?' Help
                # Help function already called by menu_loop. Loop again to show menu.
                continue ;;
            3) # 'm' Main Menu
                # Treat 'm' as cancel for this specific workflow, as main menu might not be fully set up
                # if this is called during initial installation.
                print_info "Installation workflow cancelled via 'm' key (treated as return/cancel)."
                press_any_key
                return 1 ;; # Return 1 to indicate cancellation of the workflow
            4) # 'x' Exit script
                request_script_exit
                return 0 ;; # Return to main script loop to process exit
            5) # 'r' Return/Back/Cancel (cancel installation workflow)
               print_info "Installation workflow cancelled via 'r' key."
               press_any_key
               return 1 ;; # Return 1 to indicate cancellation
            6)  # Invalid input in menu_loop
                continue ;; # Re-display menu options
            *)
                print_warning "Unexpected menu_loop return code in download_backhaul_binary_workflow: $menu_rc (Choice: $user_choice)"
                press_any_key
                continue ;; # Re-display menu options
        esac

        if $install_attempted; then
            if $install_succeeded; then
                # install_downloaded_binary (called by _download_* helpers) already verifies.
                # If it returns success, we assume verification passed.
                return 0 # Overall success for download_backhaul_binary_workflow
            else
                # Error messages are handled within _download_* or install_downloaded_binary
                # Loop will continue to re-prompt installation method.
                # press_any_key is already called if install_succeeded is false by now
                # or if an invalid numeric choice was made.
                : # No additional press_any_key needed here, already handled.
            fi
        fi
        # If not an install attempt (like diagnostics or invalid option that didn't take action), loop continues.
        # The main case statement's default or specific error paths should call press_any_key if needed.
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
        read -e -r -p "Enter path to local .tar.gz file (or type 'cancel' to return): " local_file_path
        local lower_case_input
        lower_case_input=$(echo "$local_file_path" | tr '[:upper:]' '[:lower:]')

        if [[ "$lower_case_input" == "cancel" ]]; then
            print_info "Local file installation cancelled."
            return 1 # Indicate cancellation
        fi

        if [[ -z "$local_file_path" ]]; then
            if prompt_yes_no "Path cannot be empty. Cancel local file installation?" "y"; then return 1; fi
            continue
        fi
        if [[ ! -f "$local_file_path" ]]; then
            if prompt_yes_no "File not found: '$local_file_path'. Try again?" "y"; then continue; else return 1; fi
        fi
        # Relaxed check for .tar.gz, install_downloaded_binary will verify archive integrity.
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

_use_existing_local_binary() {
    print_menu_header "secondary" "Use Existing Local Binary" \
        "Point to an already extracted Backhaul binary file."

    local local_binary_path
    while true; do
        read -e -r -p "Enter full path to your local Backhaul binary file (or type 'cancel' to return): " local_binary_path
        local lower_case_input
        lower_case_input=$(echo "$local_binary_path" | tr '[:upper:]' '[:lower:]')

        if [[ "$lower_case_input" == "cancel" ]]; then
            print_info "Using existing local binary cancelled."
            return 1 # Indicate cancellation
        fi

        if [[ -z "$local_binary_path" ]]; then
            if prompt_yes_no "Path cannot be empty. Cancel providing local binary?" "y"; then return 1; fi
            continue
        fi
        if [[ ! -f "$local_binary_path" ]]; then
            if prompt_yes_no "File not found: '$local_binary_path'. Try again?" "y"; then continue; else return 1; fi
        fi
        if [[ ! -x "$local_binary_path" ]]; then
            print_warning "File '$local_binary_path' is not executable."
            if prompt_yes_no "Attempt to make it executable (chmod +x)?" "y"; then
                chmod +x "$local_binary_path"
                if [[ ! -x "$local_binary_path" ]]; then
                    handle_error "ERROR" "Failed to make '$local_binary_path' executable."
                    if prompt_yes_no "Try a different path?" "y"; then continue; else return 1; fi
                else
                    print_success "File '$local_binary_path' is now executable."
                fi
            else
                if prompt_yes_no "Try a different path?" "y"; then continue; else return 1; fi
            fi
        fi
        break # Path is valid, file exists, and is executable
    done

    local target_bin_dir
    target_bin_dir=$(dirname "$BIN_PATH")
    ensure_dir "$target_bin_dir" "755" # Ensure target directory exists (e.g., /tmp/easybackhaul_bin)

    log_message "INFO" "Copying user-provided binary '$local_binary_path' to '$BIN_PATH'"
    if cp "$local_binary_path" "$BIN_PATH"; then
        # Ensure the copied binary also has correct execute permissions
        chmod +x "$BIN_PATH"
        set_secure_file_permissions "$BIN_PATH" "755"

        if verify_binary_installation; then # verify_binary_installation uses global BIN_PATH
            handle_success "Backhaul binary copied from '$local_binary_path' and verified successfully!"
            print_info "Summary: 📁 $BIN_PATH | 🔒 $(stat -c %a "$BIN_PATH") | 📊 $(du -h "$BIN_PATH" | cut -f1)"
            return 0 # Success
        else
            handle_error "ERROR" "Binary copied to $BIN_PATH, but verification failed. It may be incompatible or corrupted."
            # Optionally, offer to remove the copied file from BIN_PATH
            secure_delete "$BIN_PATH" 2>/dev/null
            return 1 # Verification failed
        fi
    else
        handle_error "ERROR" "Failed to copy binary from '$local_binary_path' to '$BIN_PATH'."
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
    local user_choice diag_rc # Renamed from menu_rc to avoid conflict with outer scope

    while true; do
        print_menu_header "secondary" "Network Connectivity Diagnostics"
        menu_loop "Select option" diag_menu_options "_network_diag_help"
        local diag_rc=$? # Capture $? first
        local user_choice="$MENU_CHOICE" # Then MENU_CHOICE

        case "$diag_rc" in
            0) # Numeric choice
                case "$user_choice" in
                    "1")
                        print_info "--- Testing General Internet Connectivity ---"
                        check_basic_connectivity
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
                    *) print_warning "Invalid option in network diagnostics: $user_choice"; press_any_key;;
                esac
                ;;
            2) # '?' Help
                # Help function already called by menu_loop. Loop again to show menu.
                continue ;;
            3) # 'm' Main Menu
                go_to_main_menu
                return 0 ;; # Return to main script loop
            4) # 'x' Exit script
                request_script_exit
                return 0 ;; # Return to main script loop
            5) # 'r' Return/Back/Cancel (to previous menu - download_backhaul_binary_workflow)
                return_from_menu # This pops the stack
                return 0 ;; # Return to main script loop
            6)  # Invalid input in menu_loop
                continue ;; # Re-display this menu
            *)
                print_warning "Unexpected menu_loop return code in run_network_diagnostics_menu: $diag_rc (Choice: $user_choice)"
                press_any_key
                continue ;; # Re-display this menu
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

    while true; do # Loop for Setup Type, to allow 'back' from Mode selection
        print_menu_header "secondary" "Tunnel Setup Type" "Step 1a: Setup Type"
        local setup_options=("1. Quick Setup (Recommended)" "2. Advanced Setup")
        _setup_type_help() {
            print_info "Setup Type Help:"
            echo " - Quick Setup: Uses sensible defaults for most common scenarios."
            echo " - Advanced Setup: Allows manual configuration of all parameters."
            echo "Use 'r' to cancel wizard, 'm' for main menu, 'x' to exit script."
            press_any_key
        }
        menu_loop "Select setup type" setup_options "_setup_type_help"
        local menu_rc=$?
        case "$menu_rc" in
            0) # Numeric choice
                setup_type_choice_ref="$MENU_CHOICE"
                # Proceed to Mode selection
                ;;
            2) # '?' Help
                continue # Re-loop for Setup Type
                ;;
            3) # 'm' Main Menu
                print_info "Configuration cancelled: returning to Main Menu."
                return 1 ;; # Signal cancel wizard
            4) # 'x' Exit script
                request_script_exit # This function handles its own exit.
                return 1 # Should not be reached if request_script_exit works.
                ;;
            5) # 'r' Return/Back (from first step is cancel wizard)
                print_info "Configuration cancelled: 'Back' from first step."
                return 1 ;; # Signal cancel wizard
            6)  # Invalid input in menu_loop
                print_info "Invalid setup type selection, please try again." # Optional: more specific message
                # press_any_key already handled by menu_loop before returning 6
                continue ;; # Re-prompt Setup Type
            *)
                handle_error "ERROR" "Unhandled menu_loop code $menu_rc in _prompt_setup_type_and_mode (Setup Type)"
                return 1 ;; # Signal cancel wizard on error
        esac

        # --- Mode (Server/Client) ---
        while true; do # Inner loop for Mode selection
            print_menu_header "secondary" "Tunnel Mode" "Step 1b: Select Mode"
            local default_mode_val="2" # Default to client typically
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
        _mode_help_mode() { # Renamed to avoid conflict if _setup_type_help is somehow in scope
            print_info "Tunnel Mode Help:"
            echo " - Server Mode: This machine will act as the entry point for users."
            echo " - Client Mode: This machine will connect out to a Backhaul server."
            echo "Use 'r' to go back to Setup Type, 'm' for main menu, 'x' to exit script."
            press_any_key
        }

        menu_loop "Select tunnel mode (Default: $default_mode_val)" mode_options "_mode_help_mode"
        menu_rc=$?
        case "$menu_rc" in
            0) # Numeric choice
                if [[ "$MENU_CHOICE" == "1" ]]; then
                    tunnel_mode_ref="server"
                elif [[ "$MENU_CHOICE" == "2" ]]; then
                    tunnel_mode_ref="client"
                else
                    handle_error "ERROR" "Invalid mode choice '$MENU_CHOICE' from menu_loop."
                    print_warning "Please try selecting mode again."
                    press_any_key
                    # continue 2 was wrong, now just 'continue' for inner loop
                    continue # Re-prompt Mode selection
                fi
                # Mode selected successfully, break inner loop and then outer loop will be exited by return 0
                break
                ;;
            2) # '?' Help
                # continue 2 was wrong, now just 'continue' for inner loop
                continue # Re-prompt Mode selection (after help)
                ;;
            3) # 'm' Main Menu
                print_info "Configuration cancelled: returning to Main Menu."
                return 1 ;; # Signal cancel wizard (exits function)
            4) # 'x' Exit script
                request_script_exit
                return 1 ;; # Signal cancel wizard (exits function)
            5) # 'r' Return/Back (to Setup Type selection)
                print_info "Going back to Setup Type selection."
                break # Break inner Mode loop, outer Setup Type loop will 'continue 1' implicitly
                ;;
            6)  # Invalid input in menu_loop (including empty Enter)
                # menu_loop handles press_any_key for non-empty invalid input.
                # For empty input, no message from menu_loop, so we don't add one here either.
                # Simply re-prompt Mode.
                continue # Re-prompt Mode selection
                ;;
            *)
                handle_error "ERROR" "Unhandled menu_loop code $menu_rc in _prompt_setup_type_and_mode (Mode)"
                return 1 ;; # Signal cancel wizard (exits function)
        esac
        done # End of inner while true for Mode selection

        # If we broke from Mode selection due to 'r' (Return/Back),
        # we need to continue the outer loop to re-prompt Setup Type.
        if [[ "$menu_rc" == "5" ]]; then # 'r' was chosen for Mode
            continue # Continue outer loop (Setup Type)
        fi

        # If we reached here, it means Mode was successfully selected OR an exit/error occurred.
        # If Mode was successful (rc=0), the 'return 0' from that case already exited.
        # If an error/exit occurred (rc=1, 3, 4), 'return 1' already exited.
        # This part of the code should ideally only be reached if 'r' was selected in Mode,
        # and the outer loop needs to continue.
        # Or, if Mode selection succeeded, we'd have hit `return 0` already.

        # Fallback / Should not be reached if logic above is perfect
        # but as a safeguard, if mode was set, we can assume success.
        if [[ -n "$tunnel_mode_ref" ]]; then
             return 0 # Mode was set, assume overall success for the function
        fi
        # If mode wasn't set and 'r' wasn't the reason for breaking inner loop,
        # it implies an unhandled state or error, loop Setup Type again.
    done # End of outer while true for Setup Type
}

_prompt_transport_protocol() {
    local setup_type_choice=$1   # 1 for Quick, 2 for Advanced
    local -n transport_ref=$2    # Output: selected transport string (e.g., "tcp")

    # Initial header print for this step
    print_menu_header "secondary" "Transport Protocol" "Step 3 of N: Select Protocol"

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

    _transport_help() {
        print_info "Transport Protocol Help:"
        echo " - tcp: Standard, fast, and reliable."
        echo " - ws: WebSocket, useful for proxying through CDNs like Cloudflare."
        echo " - wss: Secure WebSocket (TLS/SSL encrypted), also good for CDNs."
        echo " - *mux: Multiplexed versions allow multiple streams over one connection."
        echo " - udp: For applications requiring UDP (e.g., some games, VoIP)."
        echo "Use 'r' to return to Mode selection, 'c' to cancel configuration."
        press_any_key
    }

    local show_all_options_now=false
    if [[ "$setup_type_choice" -ne 1 ]]; then # If not quick setup (i.e., advanced)
        show_all_options_now=true
    fi

    local previous_menu_rc_for_header_logic="" # Used to help decide if header needs re-print after help

    while true; do
        local current_options_array_name
        local current_prompt_msg="Select transport"
        local current_header_title="Transport Protocol"
        local current_header_subtitle="Step 2 of N: Select Protocol" # Adjusted step number

        if $show_all_options_now; then
            current_options_array_name="all_transport_choices"
            current_header_title="All Transport Protocols"
            current_header_subtitle="Step 2 of N (Detail)" # Adjusted step number
        else
            current_options_array_name="quick_transport_choices"
            current_prompt_msg="Select transport (Default: 1 for TCP)"
        fi

        # Re-print header if we just switched to "all options" or if we are re-looping after help.
        # Also, ensure the initial header for this function call is printed before the loop.
        # The logic below tries to avoid redundant prints inside the loop.
        if [[ -z "$previous_menu_rc_for_header_logic" ]]; then # First time in loop for this function call
            print_menu_header "secondary" "$current_header_title" "$current_header_subtitle"
        elif $show_all_options_now && [[ "$previous_menu_rc_for_header_logic" != "2" && "$previous_menu_rc_for_header_logic" != "0" ]]; then # Switched to all, and not coming from help or successful choice
             print_menu_header "secondary" "$current_header_title" "$current_header_subtitle"
        elif [[ "$previous_menu_rc_for_header_logic" == "2" ]]; then # Always re-print after help
             print_menu_header "secondary" "$current_header_title" "$current_header_subtitle"
        fi

        menu_loop "$current_prompt_msg" "$current_options_array_name" "_transport_help"
        local menu_rc=$?
        previous_menu_rc_for_header_logic="$menu_rc" # Store for next iteration's header logic

        case "$menu_rc" in
            0) # Numeric choice
                if $show_all_options_now; then
                    if [[ "$MENU_CHOICE" -ge 1 && "$MENU_CHOICE" -le ${#transport_options_arr[@]} ]]; then
                        transport_ref=$(echo "${transport_options_arr[$(($MENU_CHOICE-1))]}" | awk '{print $1}')
                        log_message "INFO" "Selected transport: $transport_ref"
                        return 0 # Success
                    else
                        print_warning "Invalid numeric choice from all options: $MENU_CHOICE"; press_any_key
                        previous_menu_rc_for_header_logic="error" # Force header re-print
                        continue
                    fi
                else # Quick setup options
                    case "$MENU_CHOICE" in
                        "1") transport_ref="tcp"; break ;; # Break from inner switch, then outer loop will be exited by return 0
                        "2") transport_ref="ws"; break ;;
                        "3") transport_ref="wss"; break ;;
                        "4")
                            show_all_options_now=true
                            previous_menu_rc_for_header_logic="" # Force header re-print for "all options" view
                            continue ;; # Re-loop to show all options
                        *)
                            print_warning "Invalid quick transport choice: $MENU_CHOICE."; press_any_key
                            previous_menu_rc_for_header_logic="error" # Force header re-print
                            continue;;
                    esac
                    log_message "INFO" "Selected transport: $transport_ref"
                    return 0 # Success
                fi
                ;;
            2) # '?' Help
                # Header will be re-printed due to previous_menu_rc_for_header_logic being 2
                continue ;;
            3) # 'm' Main Menu
                print_info "Configuration cancelled: returning to Main Menu."
                return 1 ;; # Signal cancel wizard
            4) # 'x' Exit script
                request_script_exit
                return 1 ;; # Should not be reached
            5) # 'r' Return/Back
                print_info "Going back to Setup Type/Mode selection."
                return 2 ;; # Signal go back one step
            6)  # Invalid input in menu_loop
                # press_any_key handled by menu_loop
                # previous_menu_rc_for_header_logic will be 6, so header might not reprint unless logic is adjusted.
                # Setting it to "error" or similar to force header reprint.
                previous_menu_rc_for_header_logic="error_redraw"
                continue ;; # Re-prompt transport protocol
            *)
                handle_error "ERROR" "Unhandled menu_loop code $menu_rc in _prompt_transport_protocol"
                return 1;; # Signal cancel wizard on error
        esac
    done # This while loop is technically now only exited by `return` statements.
         # The `break` statements in numeric choice (0) for quick options were for the inner switch,
         # but now directly lead to `return 0`.
}

_prompt_basic_config_params() {
    local tunnel_mode="$1"      # "server" or "client"
    local -n listen_port_ref=$2 # Output for server mode
    local -n remote_ip_ref=$3   # Output for client mode
    local -n remote_port_ref=$4 # Output for client mode
    local -n local_fwd_port_ref=$5 # Output for client mode (local port to forward from) - NO LONGER USED for prompting/saving
    local -n auth_token_ref=$6  # Output: auth token

    print_menu_header "secondary" "Basic Configuration" "Step 3: Mandatory Settings"

    if [[ "$tunnel_mode" == "server" ]]; then
        print_info "Server Mode: Configure listening address."
        if [[ -z "$SERVER_IP" || "$SERVER_IP" == "N/A" ]]; then get_server_info; fi # Ensure we have an IP for defaults if needed

        if ! prompt_for_port "Port for Backhaul server to listen on (e.g., 443)" "443" true listen_port_ref; then
            print_error "Failed to get a valid listen port for server."
            return 1 # Critical failure
        fi
    else # client mode
        print_info "Client Mode: Configure remote server details."
        if ! prompt_for_ip "Public IP address of the Backhaul SERVER" "" true remote_ip_ref; then
            print_error "Failed to get a valid remote server IP for client."
            return 1 # Critical failure
        fi
        
        if ! prompt_for_port "Port the Backhaul SERVER is listening on" "443" false remote_port_ref; then
            print_error "Failed to get a valid remote server port for client."
            return 1 # Critical failure
        fi
    fi

    local default_auth_token="EasyBackhaulSecretToken" # Example default
    print_info "Set an authentication token (must match on both server and client)."
    while true; do
        read -r -s -p "Enter token (min 8 chars, or type 'cancel'): " auth_token_val
        echo # Newline after secret input
        if [[ "$auth_token_val" == "cancel" ]]; then
            print_info "Token input cancelled by user."
            return 1 # Signal cancellation
        fi
        # Use default if input is empty AND a default is set (currently not using default_auth_token if empty)
        # Forcing user to enter something or explicitly cancel.
        # auth_token_val=${auth_token_val:-$default_auth_token}
        if [[ -z "$auth_token_val" ]]; then
             print_warning "Token cannot be empty."
             if ! prompt_yes_no "Try entering token again?" "y"; then print_error "Token setup aborted."; return 1; fi
        elif [[ "${#auth_token_val}" -lt 8 ]]; then
            print_warning "Token too short. Please use at least 8 characters for security."
            if ! prompt_yes_no "Try entering token again?" "y"; then print_error "Token setup aborted."; return 1; fi
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
        return 0 # Not applicable for this transport
    fi

    print_menu_header "secondary" "TLS Certificate Configuration" "Step 6: Secure Protocols (WSS/WSSMUX)" # Adjusted step
    print_info "Secure protocols (WSS/WSSMUX) require a TLS certificate and private key."

    local cert_dir_global="${CERT_DIR:-/etc/easybackhaul/certs}" # CERT_DIR from globals.sh
    ensure_dir "$cert_dir_global" "700" # Ensure it exists
    
    mapfile -t existing_certs < <(find "$cert_dir_global" -maxdepth 1 \( -name '*.pem' -o -name '*.crt' \) 2>/dev/null | sort)
    
    local tls_options=()
    local cert_map=() # Associative array to map choice number to paths

    if [[ ${#existing_certs[@]} -gt 0 ]]; then
        print_info "Existing certificates/keys found in $cert_dir_global:"
        local count=1
        for cert_file in "${existing_certs[@]}"; do
            # Try to find a matching .key file (more specific than just another .pem)
            local potential_key_file_key="${cert_file%.pem}.key"
            if [[ ! -f "$potential_key_file_key" ]]; then potential_key_file_key="${cert_file%.crt}.key"; fi

            # Fallback if .key not found, check for a .pem that could be a key (less ideal)
            local potential_key_file_pem="${cert_file%.crt}.pem" # if cert is .crt, key could be .pem
            if [[ "$cert_file" == *".pem" && -f "${cert_file%.pem}.pem" && "$cert_file" != "${cert_file%.pem}.pem" ]]; then
                 # This case is tricky, could be two .pem files. Assume cert is fullchain.pem, key is privkey.pem
                 # For simplicity, this heuristic might not be perfect.
                 : # Skip complex .pem + .pem logic for now, prefer .crt + .key or .pem + .key
            fi

            local final_key_file=""
            if [[ -f "$potential_key_file_key" ]]; then
                final_key_file="$potential_key_file_key"
            # Add more sophisticated pairing logic if needed, e.g. matching common names
            elif [[ -f "$potential_key_file_pem" && "$cert_file" != "$potential_key_file_pem" ]]; then
                 # Heuristic: if cert is fullchain.pem, key might be privkey.pem
                 if [[ "$(basename "$cert_file")" == "fullchain.pem" && "$(basename "$potential_key_file_pem")" == "privkey.pem" ]]; then
                    final_key_file="$potential_key_file_pem"
                 fi
            fi

            if [[ -n "$final_key_file" ]]; then
                 tls_options+=("$count. Use: $(basename "$cert_file") & $(basename "$final_key_file")")
                 cert_map[$count]="$cert_file;$final_key_file" # Store paths
                 ((count++))
            else
                # If only a single .pem or .crt is found without a clear pair, list it as possibly incomplete
                # For now, we only list clear pairs.
                # print_warning "Certificate $(basename "$cert_file") found without a clearly matching .key file, skipping for auto-pairing."
                :
            fi
        done
    fi
    tls_options+=("$((${#cert_map[@]} + 1)). Generate New Self-Signed Certificate")
    local generate_new_opt_num=$((${#cert_map[@]} + 1))
    tls_options+=("$((${#cert_map[@]} + 2)). Manually Enter Paths for Certificate and Key")
    local manual_paths_opt_num=$((${#cert_map[@]} + 2))
    tls_options+=("$((${#cert_map[@]} + 3)). Skip TLS configuration (NOT RECOMMENDED)")
    local skip_tls_opt_num=$((${#cert_map[@]} + 3))


    _tls_help() {
        print_info "TLS Configuration Help:"
        echo " - Select an existing certificate/key pair if found."
        echo " - Choose 'Generate New' to create a self-signed certificate."
        echo " - 'Manually Enter Paths' if your cert/key are elsewhere."
        echo " - 'Skip TLS' will proceed without TLS; WSS/WSSMUX will likely fail."
        echo " - Certificate paths are stored in the tunnel's TOML config file."
        echo "Use 'r' to return to previous step, 'm' for main menu."
        press_any_key
    }

    menu_loop "Select TLS certificate option" tls_options "_tls_help"
    local menu_rc=$?
    local user_choice="$MENU_CHOICE"

    case "$menu_rc" in
        0) # Numeric choice
            if (( user_choice == generate_new_opt_num )); then
                if generate_self_signed_tls_cert; then # This function handles its own output and sets paths
                    # It should output the paths it created, we need to capture them.
                    # For now, assume generate_self_signed_tls_cert updates some global vars or returns paths.
                    # This part needs refinement: generate_self_signed_tls_cert needs to return the paths.
                    # Let's assume it writes to last_cert.path and last_key.path files for simplicity here.
                    # This is a placeholder for better path communication.
                    if [[ -f "$cert_dir_global/last_generated_cert.path" && -f "$cert_dir_global/last_generated_key.path" ]]; then
                        tls_cert_path_ref=$(cat "$cert_dir_global/last_generated_cert.path")
                        tls_key_path_ref=$(cat "$cert_dir_global/last_generated_key.path")
                        rm -f "$cert_dir_global/last_generated_cert.path" "$cert_dir_global/last_generated_key.path"
                        print_success "Using newly generated cert: $tls_cert_path_ref and key: $tls_key_path_ref"
                    else
                        handle_error "ERROR" "Failed to retrieve paths of newly generated certificate/key. Please enter manually."
                        # Fallback to manual entry
                        read -e -r -p "Enter full path to TLS certificate file (.crt or .pem): " tls_cert_path_ref
                        read -e -r -p "Enter full path to TLS private key file (.key or .pem): " tls_key_path_ref
                        if [[ ! -f "$tls_cert_path_ref" || ! -f "$tls_key_path_ref" ]]; then
                            handle_error "ERROR" "One or both manually entered TLS file paths are invalid."; return 1;
                        fi
                    fi
                else
                    print_warning "Self-signed certificate generation failed or was cancelled."
                    if prompt_yes_no "Retry TLS configuration?" "y"; then _prompt_tls_config "$transport" tls_cert_path_ref tls_key_path_ref; return $?; else return 1; fi
                fi
            elif (( user_choice == manual_paths_opt_num )); then
                read -e -r -p "Enter full path to TLS certificate file (.crt or .pem): " tls_cert_path_ref
                read -e -r -p "Enter full path to TLS private key file (.key or .pem): " tls_key_path_ref
                if [[ ! -f "$tls_cert_path_ref" || ! -f "$tls_key_path_ref" ]]; then
                    handle_error "ERROR" "One or both manually entered TLS file paths are invalid."
                    if prompt_yes_no "Retry entering paths?" "y"; then _prompt_tls_config "$transport" tls_cert_path_ref tls_key_path_ref; return $?; else return 1; fi
                fi
                print_success "Using manually specified cert: $tls_cert_path_ref and key: $tls_key_path_ref"
            elif (( user_choice == skip_tls_opt_num )); then
                print_warning "Skipping TLS configuration. WSS/WSSMUX will likely not work without it."
                tls_cert_path_ref=""; tls_key_path_ref=""
            elif [[ -n "${cert_map[$user_choice]}" ]]; then
                IFS=';' read -r tls_cert_path_ref tls_key_path_ref <<< "${cert_map[$user_choice]}"
                print_success "Using selected cert: $tls_cert_path_ref and key: $tls_key_path_ref"
            else
                handle_error "ERROR" "Invalid TLS certificate selection: $user_choice."
                if prompt_yes_no "Retry TLS setup step?" "y"; then _prompt_tls_config "$transport" tls_cert_path_ref tls_key_path_ref; return $?; else return 1; fi
            fi
            return 0
            ;;
        2) _prompt_tls_config "$transport" tls_cert_path_ref tls_key_path_ref; return $? ;;
        3) print_info "Configuration cancelled: returning to Main Menu."; return 1 ;;
        4) request_script_exit; return 1 ;;
        5) print_info "Going back to previous step from TLS config."; return 2 ;;
        6) _prompt_tls_config "$transport" tls_cert_path_ref tls_key_path_ref; return $? ;;
        *)
            handle_error "ERROR" "Unhandled menu_loop code $menu_rc in _prompt_tls_config"
            if prompt_yes_no "Unexpected error in TLS config. Retry this step?" "y"; then _prompt_tls_config "$transport" tls_cert_path_ref tls_key_path_ref; return $?; else return 1; fi
    esac
    return 0
}

# Validates a single port or a port range (e.g., "80", "400-500").
# Also handles optional /udp suffix on the port/range string.
# Output: Sets global array _VALIDATED_PORT_RANGE_PARTS to (type, port1, port2, protocol_suffix) on success.
# Returns 0 if valid, 1 if invalid.
_VALIDATED_PORT_RANGE_PARTS=()
_validate_port_or_range_with_udp() {
    local port_spec_full="$1"
    local port_spec_no_udp="$port_spec_full"
    local protocol_suffix=""

    _VALIDATED_PORT_RANGE_PARTS=() # Reset

    if [[ "$port_spec_full" == */udp ]]; then
        protocol_suffix="/udp"
        port_spec_no_udp="${port_spec_full%/udp}"
    fi

    if [[ "$port_spec_no_udp" =~ ^[0-9]+$ ]]; then # Single port
        if validate_port "$port_spec_no_udp"; then # validate_port is from helpers.sh
            _VALIDATED_PORT_RANGE_PARTS=("single" "$port_spec_no_udp" "" "$protocol_suffix")
            return 0
        fi
        # validate_port prints its own error
        return 1
    elif [[ "$port_spec_no_udp" =~ ^([0-9]+)-([0-9]+)$ ]]; then # Port range
        local start_port="${BASH_REMATCH[1]}"
        local end_port="${BASH_REMATCH[2]}"
        if validate_port "$start_port" && validate_port "$end_port"; then
            if (( start_port <= end_port )); then # Allow start_port == end_port for single port range
                _VALIDATED_PORT_RANGE_PARTS=("range" "$start_port" "$end_port" "$protocol_suffix")
                return 0
            else
                print_warning "Invalid range: Start port $start_port must be less than or equal to end port $end_port."
                return 1
            fi
        fi
        # validate_port prints its own error
        return 1
    else
        print_warning "Invalid port/range format: '$port_spec_full'. Use 'port', 'port/udp', 'start-end', or 'start-end/udp'."
        return 1
    fi
}


# Prompts user for server port forwarding rules using a single comma-separated input.
# Arguments:
#   $1 (nameref): Output array for TOML-formatted rule strings.
#   $2 (nameref): Output flag (boolean string "true"/"false") indicating if any UDP rules were specified.
# Returns: 0 on success (rules processed, could be empty), 1 on unrecoverable input error or cancellation.
_configure_server_forwarding_rules() {
    local -n out_rules_array_ref=$1
    local -n out_any_udp_rules_ref=$2

    out_rules_array_ref=() # Initialize output array
    out_any_udp_rules_ref="false" # Initialize UDP flag

    print_menu_header "secondary" "Server Port Forwarding" "Step 4: Configure Forwarding Rules"
    echo "Enter server ports to forward traffic from."
    echo "Examples:"
    echo "  - Single port (TCP): 80 (forwards server's public port 80 to client's port 80)"
    echo "  - Single port (UDP): 53/udp (forwards server's 53/udp to client's 53/udp; requires 'accept_udp=true')"
    echo "  - Port to specific client port: 8080:80 (forwards server's 8080 to client's port 80)"
    echo "  - Port range: 7000-7010 (forwards server range 7000-7010 to client's range 7000-7010)"
    echo "  - Port range to single client port: 7000-7010:6000 (forwards server range 7000-7010 to client's single port 6000)"
    echo "  - To specific client IP & port: 2222=192.168.0.10:22 (forwards server's 2222 to 192.168.0.10:22 on client side)"
    echo "Separate multiple rules with a comma. Examples:"
    echo "  Ex 1: 80, 443:8443, 7000-7010, 53/udp"
    echo "  Ex 2: 2222=10.0.0.5:22, 8000-8010:9000, 999/udp"
    echo "Leave blank for no forwarding."
    echo

    local user_input_str
    read -r -p "Enter forwarding rules: " user_input_str

    if [[ -z "$user_input_str" ]]; then
        print_info "No port forwarding rules entered."
        return 0 # Success, but no rules
    fi

    local IFS=',' # Set Internal Field Separator to comma for splitting
    read -ra raw_rules <<< "$user_input_str" # Split into array
    local IFS=$' \t\n' # Reset IFS

    local rule_valid
    for rule_str_raw in "${raw_rules[@]}"; do
        local rule_str
        rule_str=$(echo "$rule_str_raw" | xargs) # Trim whitespace

        if [[ -z "$rule_str" ]]; then continue; fi # Skip empty rules if user entered ",,"

        local listen_spec listen_type listen_port1 listen_port2 listen_protocol_suffix
        local dest_ip dest_port
        local toml_rule=""
        rule_valid=false

        # Try to parse listen_spec=dest_ip:dest_port format
        if [[ "$rule_str" =~ ^([^=]+)=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):([0-9]+(/udp)?)$ ]]; then
            listen_spec="${BASH_REMATCH[1]}"
            dest_ip="${BASH_REMATCH[2]}"
            local dest_port_full="${BASH_REMATCH[3]}" # e.g., "22" or "22/udp"

            local dest_port_no_udp="$dest_port_full"
            local dest_protocol_suffix=""
            if [[ "$dest_port_full" == */udp ]]; then
                dest_protocol_suffix="/udp"
                dest_port_no_udp="${dest_port_full%/udp}"
            fi

            if _validate_port_or_range_with_udp "$listen_spec" && \
               validate_ip "$dest_ip" && \
               validate_port "$dest_port_no_udp"; then

                listen_type="${_VALIDATED_PORT_RANGE_PARTS[0]}"
                listen_port1="${_VALIDATED_PORT_RANGE_PARTS[1]}"
                listen_port2="${_VALIDATED_PORT_RANGE_PARTS[2]}"
                listen_protocol_suffix="${_VALIDATED_PORT_RANGE_PARTS[3]}"

                if [[ "$listen_protocol_suffix" == "/udp" || "$dest_protocol_suffix" == "/udp" ]]; then
                    out_any_udp_rules_ref="true"
                    # Backhaul's `ports` array does not seem to use /udp. `accept_udp=true` handles it.
                fi

                local toml_listen_part="$listen_port1"
                if [[ "$listen_type" == "range" ]]; then toml_listen_part="${listen_port1}-${listen_port2}"; fi

                toml_rule="${toml_listen_part}=${dest_ip}:${dest_port_no_udp}" # UDP suffix not part of TOML rule string
                rule_valid=true
            fi

        # Try to parse listen_spec:dest_port format
        elif [[ "$rule_str" =~ ^([^:]+):([0-9]+(/udp)?)$ ]]; then
            listen_spec="${BASH_REMATCH[1]}"
            local dest_port_full="${BASH_REMATCH[2]}"

            local dest_port_no_udp="$dest_port_full"
            local dest_protocol_suffix=""
            if [[ "$dest_port_full" == */udp ]]; then
                dest_protocol_suffix="/udp"
                dest_port_no_udp="${dest_port_full%/udp}"
            fi

            if _validate_port_or_range_with_udp "$listen_spec" && \
               validate_port "$dest_port_no_udp"; then

                listen_type="${_VALIDATED_PORT_RANGE_PARTS[0]}"
                listen_port1="${_VALIDATED_PORT_RANGE_PARTS[1]}"
                listen_port2="${_VALIDATED_PORT_RANGE_PARTS[2]}"
                listen_protocol_suffix="${_VALIDATED_PORT_RANGE_PARTS[3]}"

                if [[ "$listen_protocol_suffix" == "/udp" || "$dest_protocol_suffix" == "/udp" ]]; then
                    out_any_udp_rules_ref="true"
                fi

                local toml_listen_part="$listen_port1"
                if [[ "$listen_type" == "range" ]]; then toml_listen_part="${listen_port1}-${listen_port2}"; fi

                toml_rule="${toml_listen_part}:${dest_port_no_udp}" # UDP suffix not part of TOML rule string
                rule_valid=true
            fi

        # Try to parse listen_spec (single port or range, with optional /udp)
        elif _validate_port_or_range_with_udp "$rule_str"; then
            listen_type="${_VALIDATED_PORT_RANGE_PARTS[0]}"
            listen_port1="${_VALIDATED_PORT_RANGE_PARTS[1]}"
            listen_port2="${_VALIDATED_PORT_RANGE_PARTS[2]}"
            listen_protocol_suffix="${_VALIDATED_PORT_RANGE_PARTS[3]}"

            if [[ "$listen_protocol_suffix" == "/udp" ]]; then
                out_any_udp_rules_ref="true"
            fi

            # For 'local_port' or 'local_range' shorthand, Backhaul expects just the port/range.
            # Example: "443" implies "443:443". "443-600" implies "443-600:443-600" (effectively).
            if [[ "$listen_type" == "single" ]]; then
                toml_rule="$listen_port1"
            elif [[ "$listen_type" == "range" ]]; then
                toml_rule="${listen_port1}-${listen_port2}"
            fi
            rule_valid=true
        fi

        if $rule_valid; then
            out_rules_array_ref+=("$toml_rule")
            print_success "  Rule parsed: \"$rule_str\" -> TOML: \"$toml_rule\""
        else
            print_warning "  Invalid rule format or component: '$rule_str'. Skipping."
            # Optionally, ask user to retry this specific rule or continue?
            # For now, just skip invalid parts of the comma-separated string.
        fi
    done

    if [[ ${#out_rules_array_ref[@]} -eq 0 && -n "$user_input_str" ]]; then
        print_warning "No valid forwarding rules were extracted from the input."
        # No 'return 1' here, let it proceed with empty rules if all were invalid.
    elif [[ ${#out_rules_array_ref[@]} -gt 0 ]]; then
        print_success "All rules processed. Total valid rules: ${#out_rules_array_ref[@]}"
    fi

    if [[ "$out_any_udp_rules_ref" == "true" ]]; then
        print_info "Note: UDP rules specified. Ensure 'accept_udp = true' is set in server's advanced options if not using UDP transport directly."
    fi

    press_any_key # Allow user to see results before continuing wizard
    return 0
}

# Prompts user for advanced optional parameters
# Populates an associative array with chosen values.
# Usage: _prompt_advanced_parameters params_assoc_array "$tunnel_mode" "$transport_protocol" "$is_interactive"
_prompt_advanced_parameters() {
    local -n params_ref=$1 # Associative array passed by nameref
    local tunnel_mode="$2"
    local transport_protocol="$3"
    local is_interactive="${4:-true}" # Default to true for interactive prompting

    if [[ "$is_interactive" == "true" ]]; then
        print_menu_header "secondary" "Advanced Configuration" "Customize Optional Parameters"
        print_info "For each parameter, the default value will be shown."
        print_info "You can accept the default by pressing Enter, or provide a new value."
        echo
    else
        log_message "INFO" "Populating advanced parameters with defaults (Quick Setup)."
    fi

    # Helper to prompt for/set a single advanced parameter
    # Usage: _handle_single_adv_param "description" "toml_key" "default_value_var_name"
    _handle_single_adv_param() {
        local desc="$1" toml_key="$2" default_val_var_name="$3"
        # Default value can be pre-set in params_ref (e.g. accept_udp by configure_tunnel)
        # or fallback to BH_DEFAULT_* global.
        local current_default_val="${params_ref[$toml_key]:-${!default_val_var_name}}"
        local input_val

        if [[ "$is_interactive" == "true" ]]; then
            # Special handling for accept_udp prompt if it was pre-set
            if [[ "$toml_key" == "accept_udp" && "${params_ref[$toml_key]}" == "true" ]]; then
                print_info "Note: UDP port forwarding rules were specified, so 'accept_udp = true' is recommended."
            fi

            while true; do
                read -r -p "Configure '$desc' ($toml_key) [Default: $current_default_val]: " input_val
                input_val="${input_val:-$current_default_val}" # Apply default if empty

                # Basic validation
                if [[ "$toml_key" == "nodelay" || "$toml_key" == "sniffer" || "$toml_key" == "accept_udp" || "$toml_key" == "aggressive_pool" ]]; then
                    if [[ "$input_val" != "true" && "$input_val" != "false" ]]; then
                        print_warning "Invalid boolean. Must be 'true' or 'false'."
                        continue
                    fi
                elif [[ "$toml_key" =~ port$ || "$toml_key" =~ _period$ || "$toml_key" =~ _interval$ || "$toml_key" =~ _timeout$ || "$toml_key" =~ _size$ || "$toml_key" =~ _con$ || "$toml_key" =~ _version$ || "$toml_key" =~ buffer$ ]]; then
                     if ! [[ "$input_val" =~ ^[0-9]+$ ]]; then
                        print_warning "Invalid numeric value for $toml_key. Must be an integer."
                        continue
                     fi
                fi
                params_ref["$toml_key"]="$input_val"
                print_success "  $toml_key set to: ${params_ref[$toml_key]}"
                break
            done
            echo
        else # Not interactive
            # If params_ref[$toml_key] is already set (e.g. accept_udp from UDP rules), keep it.
            # Otherwise, set the BH_DEFAULT_* global.
            if [[ -z "${params_ref[$toml_key]}" ]]; then
                 params_ref["$toml_key"]="${!default_val_var_name}"
            fi
            log_message "DEBUG" "Advanced Param: $toml_key set to: ${params_ref[$toml_key]}"
        fi
    }

    # General Parameters
    _handle_single_adv_param "Log Level" "log_level" "BH_DEFAULT_LOG_LEVEL"
    _handle_single_adv_param "Enable Traffic Sniffer" "sniffer" "BH_DEFAULT_SNIFFER"
    # sniffer_log is handled during save config if sniffer is true

    if [[ "$transport_protocol" != "udp" ]]; then # These don't apply to raw UDP transport
        _handle_single_adv_param "TCP NoDelay" "nodelay" "BH_DEFAULT_NODELAY"
        _handle_single_adv_param "Keepalive Period (s)" "keepalive_period" "BH_DEFAULT_KEEPALIVE_PERIOD"
    fi
    _handle_single_adv_param "Web Interface Port (0 to disable)" "web_port" "BH_DEFAULT_WEB_PORT"

    if [[ "$tunnel_mode" == "server" ]]; then
        if [[ "$is_interactive" == "true" ]]; then print_info "--- Server-Specific Advanced Parameters ---"; fi
        if [[ "$transport_protocol" != "udp" ]]; then # Heartbeat not in UDP server example
             _handle_single_adv_param "Heartbeat Interval (s)" "heartbeat" "BH_DEFAULT_HEARTBEAT"
        fi
        _handle_single_adv_param "Channel Size" "channel_size" "BH_DEFAULT_CHANNEL_SIZE"

        # accept_udp is only relevant if the main transport is TCP-based (tcp, tcpmux, ws, wss, wsmux, wssmux)
        # If main transport is "udp", then accept_udp is not a valid parameter for backhaul server.
        if [[ "$transport_protocol" != "udp" ]]; then
            # `accept_udp` might have been pre-set to "true" by configure_tunnel if UDP port rules were added.
            # _handle_single_adv_param will use this pre-set value as the current_default_val.
            _handle_single_adv_param "Accept UDP over non-UDP transport" "accept_udp" "BH_DEFAULT_ACCEPT_UDP"
        elif [[ -n "${params_ref[accept_udp]}" ]]; then
            # If transport is UDP, but accept_udp was somehow set (e.g. by earlier UDP rules before transport change), unset it.
            unset params_ref["accept_udp"]
            log_message "DEBUG" "Removed accept_udp as transport is UDP."
        fi

    else # client mode
        if [[ "$is_interactive" == "true" ]]; then print_info "--- Client-Specific Advanced Parameters ---"; fi
        _handle_single_adv_param "Connection Pool Size" "connection_pool" "BH_DEFAULT_CONNECTION_POOL"
        _handle_single_adv_param "Aggressive Pool Mgmt" "aggressive_pool" "BH_DEFAULT_AGGRESSIVE_POOL"
        _handle_single_adv_param "Retry Interval (s)" "retry_interval" "BH_DEFAULT_RETRY_INTERVAL"
        _handle_single_adv_param "Dial Timeout (s)" "dial_timeout" "BH_DEFAULT_DIAL_TIMEOUT"

        if [[ "$transport_protocol" == "ws" || "$transport_protocol" == "wss" || "$transport_protocol" == "wsmux" || "$transport_protocol" == "wssmux" ]]; then
            if [[ "$is_interactive" == "true" ]]; then
                local current_edge_ip="" # Default to empty for prompt
                read -r -p "Configure 'Edge IP (for CDN/WebSocket routing)' (edge_ip) [Default: blank]: " input_val
                input_val="${input_val:-$current_edge_ip}"
                if [[ -n "$input_val" ]]; then
                    if validate_ip "$input_val"; then
                        params_ref["edge_ip"]="$input_val"
                        print_success "  edge_ip set to: ${params_ref[edge_ip]}"
                    else
                        print_warning "  Invalid Edge IP: $input_val. Not set."
                    fi
                else
                     print_info "  Edge IP not set (blank)."
                fi
                echo
            else
                # For Quick Setup, edge_ip is not automatically set unless a BH_DEFAULT_EDGE_IP was defined (it's not)
                log_message "DEBUG" "Quick Setup: edge_ip not set by default."
            fi
        fi
    fi

    if [[ "$transport_protocol" =~ mux$ ]]; then # MUX specific
        if [[ "$is_interactive" == "true" ]]; then print_info "--- Multiplexer (MUX) Advanced Parameters ---"; fi
        _handle_single_adv_param "Mux Concurrency" "mux_con" "BH_DEFAULT_MUX_CON"
        _handle_single_adv_param "Mux Version" "mux_version" "BH_DEFAULT_MUX_VERSION"
        _handle_single_adv_param "Mux Frame Size (bytes)" "mux_framesize" "BH_DEFAULT_MUX_FRAMESIZE"
        _handle_single_adv_param "Mux Receive Buffer (bytes)" "mux_receivebuffer" "BH_DEFAULT_MUX_RECEIVEBUFFER"
        _handle_single_adv_param "Mux Stream Buffer (bytes)" "mux_streambuffer" "BH_DEFAULT_MUX_STREAMBUFFER"
    fi

    if [[ "$is_interactive" == "true" ]]; then
        print_info "Advanced parameter configuration complete."
        press_any_key
    else
        log_message "INFO" "Finished populating advanced parameters with defaults for Quick Setup."
    fi
    return 0
}


# --- Main Configuration Wizard ---
# Manages the overall flow of tunnel configuration.
# Returns 0 if configuration is completed (even if not saved by user later),
# Returns 1 if user cancels mid-way using navigation keys that bubble up as failure.
configure_tunnel() {
    local current_wizard_step=1

    # Variables to store wizard state, passed by nameref or directly
    local setup_choice_val tunnel_mode transport_protocol
    local server_listen_port client_remote_ip client_remote_port client_local_fwd_port common_auth_token
    local server_port_rules=() # Array to store server port forwarding rules
    local cfg_tls_cert_path cfg_tls_key_path
    local setup_is_advanced=false
    declare -A advanced_params_map # Associative array for advanced parameters

    # NOTE: The old local cfg_* variables are no longer used for storing defaults here.
    # They will be sourced from BH_DEFAULT_* globals within _prompt_advanced_parameters
    # and results stored in advanced_params_map.

    # Wizard State Machine
    # Returns 0 if configuration is completed and saved.
    # Returns 1 if user cancels the wizard at any point.
    while true; do # Loop for wizard steps, allowing "back" functionality
        local step_rc=0 # Return code from the prompt functions

        case "$current_wizard_step" in
            1) # Step 1: Setup Type & Mode
                _prompt_setup_type_and_mode setup_choice_val tunnel_mode
                step_rc=$?
                case "$step_rc" in
                    0) # Success
                        [[ "$setup_choice_val" -eq 2 ]] && setup_is_advanced=true
                        log_message "INFO" "Setup type: $(if $setup_is_advanced; then echo "Advanced"; else echo "Quick"; fi), Mode: $tunnel_mode"
                        ((current_wizard_step++))
                        ;;
                    1) # Cancel wizard
                        print_info "Configuration wizard cancelled at Setup Type/Mode."
                        return_from_menu # Ensure menu stack is correct
                        return 1 ;;
                    2) # 'r' Back - from first step, this is equivalent to cancel
                        print_info "Configuration wizard cancelled (back from first step)."
                        return_from_menu
                        return 1 ;;
                    *) handle_error "CRITICAL" "Unknown return code $step_rc from _prompt_setup_type_and_mode." ; return 1 ;;
                esac
                ;;
            2) # Step 2: Transport Protocol
                _prompt_transport_protocol "$setup_is_advanced" transport_protocol # Pass setup_is_advanced status
                step_rc=$?
                case "$step_rc" in
                    0) ((current_wizard_step++));; # Success
                    1) print_info "Configuration wizard cancelled at Transport Protocol selection."; return_from_menu; return 1 ;;
                    2) ((current_wizard_step--)); continue ;; # Go back to Step 1
                    *) handle_error "CRITICAL" "Unknown return code $step_rc from _prompt_transport_protocol." ; return 1 ;;
                esac
                ;;
            3) # Step 3: Basic Configuration Parameters
                _prompt_basic_config_params "$tunnel_mode" \
                    server_listen_port client_remote_ip client_remote_port client_local_fwd_port \
                    common_auth_token
                step_rc=$?
                case "$step_rc" in
                    0) ((current_wizard_step++));; # Success
                    1) # Cancel from basic params (e.g. typed 'cancel')
                       # Decide if this should be "back" or "full cancel"
                       # For now, let's treat explicit 'cancel' within basic_params as full wizard cancel.
                       # 'r' key is not available in these prompts.
                        print_info "Configuration wizard cancelled at Basic Parameters."
                        return_from_menu; return 1 ;;
                    # No '2' (back) returned by _prompt_basic_config_params currently
                    *) handle_error "CRITICAL" "Unknown return code $step_rc from _prompt_basic_config_params." ; return 1 ;;
                esac
                ;;
            # NEW STEP for Server Port Forwarding Rules (Step 4)
            4)
                if [[ "$tunnel_mode" == "server" ]]; then
                    local any_udp_rules_specified="false" # Initialize local flag
                    # _configure_server_forwarding_rules now takes the rules array and the udp flag nameref
                    # It will prompt the user for a comma-separated string of rules.
                    _configure_server_forwarding_rules server_port_rules any_udp_rules_specified
                    step_rc=$? # This function now returns 0 for success (even if no rules), 1 for critical error.
                               # It handles its own user interaction including 'press_any_key'.

                    if [[ "$step_rc" -ne 0 ]]; then
                        print_error "Failed to configure server port forwarding rules. Aborting wizard."
                        return_from_menu; return 1
                    fi

                    # If UDP rules were specified, and transport is not UDP itself,
                    # pre-set accept_udp to true in advanced_params_map.
                    # This will be picked up by _prompt_advanced_parameters later.
                    if [[ "$any_udp_rules_specified" == "true" && "$transport_protocol" != "udp" ]]; then
                        print_info "UDP port rules detected. Setting 'accept_udp = true' as a recommended default."
                        advanced_params_map["accept_udp"]="true"
                        # This ensures that even in Quick Setup, if UDP rules are added, accept_udp is true.
                        # In Advanced Setup, _prompt_advanced_parameters will see this and can use it as default.
                    fi
                    ((current_wizard_step++))
                else
                    # Not a server, skip this step
                    ((current_wizard_step++))
                fi
                ;;
            5) # Step 5: Advanced Configuration Prompts / Default Population
                # For Quick Setup (is_interactive=false), this populates advanced_params_map with script defaults.
                # For Advanced Setup (is_interactive=true), this prompts user for each.
                # It needs to be aware of any pre-set values in advanced_params_map (like accept_udp).
                _prompt_advanced_parameters advanced_params_map "$tunnel_mode" "$transport_protocol" "$setup_is_advanced"
                step_rc=$?
                if [[ "$step_rc" -ne 0 ]]; then
                    print_info "Advanced parameter configuration cancelled or failed."
                    return_from_menu; return 1 # Exit wizard
                fi
                ((current_wizard_step++))
                ;;
            6) # Step 6: TLS Configuration
                cfg_tls_cert_path="" cfg_tls_key_path="" # Reset for this step
                if [[ "$transport_protocol" =~ ^(wss|wssmux)$ ]]; then
                    _prompt_tls_config "$transport_protocol" cfg_tls_cert_path cfg_tls_key_path
                    step_rc=$?
                    case "$step_rc" in
                        0) ((current_wizard_step++));; # Success (includes user skipping TLS)
                        1) print_info "Configuration wizard cancelled at TLS Configuration."; return_from_menu; return 1 ;;
                        2) ((current_wizard_step--)); current_wizard_step=$((current_wizard_step > 0 ? current_wizard_step : 1)); continue ;; # Go back
                        *) handle_error "CRITICAL" "Unknown return code $step_rc from _prompt_tls_config." ; return 1 ;;
                    esac
                else
                    ((current_wizard_step++)) # Skip if not WSS/WSSMUX
                fi
                ;;
            7) # Step 7 (Was 6): Configuration Summary & Confirmation
                print_menu_header "secondary" "Configuration Summary" "Review and Confirm"
                echo "  Mode: $tunnel_mode"
                echo "  Transport: $transport_protocol"
                if [[ "$tunnel_mode" == "server" ]]; then
                    echo "  Server Listen Address (bind_addr): :$server_listen_port" # Updated key name
                    if [[ ${#server_port_rules[@]} -gt 0 ]]; then
                        echo "  Port Forwarding Rules (ports):"
                        for rule in "${server_port_rules[@]}"; do
                            echo "    - \"$rule\""
                        done
                    else
                        echo "  Port Forwarding Rules (ports): [None defined - server will not forward traffic]"
                    fi
                else # client
                    echo "  Remote Server (remote_addr): $client_remote_ip:$client_remote_port" # Updated key name
                    # client_local_fwd_port has been removed from prompts and will be removed from TOML writing.
                fi
                echo "  Token: [set]"

                if [[ ${#advanced_params_map[@]} -gt 0 ]]; then # Check if map has entries, will be true for both Quick and Advanced
                    if $setup_is_advanced; then
                        echo "  --- Advanced Settings (User Customized/Confirmed Defaults) ---"
                    else # Quick Setup
                        echo "  --- Optional Settings (Using Script Defaults) ---"
                    fi
                    local key
                    for key in $(echo "${!advanced_params_map[@]}" | tr ' ' '\n' | sort); do
                        # Conditional display for sniffer_log and web_port=0
                        if [[ "$key" == "sniffer_log" && "${advanced_params_map[sniffer]}" != "true" ]]; then
                            # Only display sniffer_log if sniffer is true
                            continue
                        fi
                        if [[ "$key" == "web_port" && "${advanced_params_map[$key]}" == "0" ]]; then
                             echo "    $key = ${advanced_params_map[$key]} (Disabled)"
                             continue
                        fi
                        echo "    $key = ${advanced_params_map[$key]}"
                    done
                fi
                # Note: edge_ip is now part of advanced_params_map and will be displayed by the loop above if set.

                if [[ -n "$cfg_tls_cert_path" && -n "$cfg_tls_key_path" ]]; then
                    echo "  TLS Certificate: $cfg_tls_cert_path"
                    echo "  TLS Key: $cfg_tls_key_path"
                elif [[ "$transport_protocol" =~ ^(wss|wssmux)$ ]]; then
                    # Only show TLS: Skipped if it was applicable
                    echo "  TLS: Skipped/Not Configured"
                fi

                if ! prompt_yes_no "Proceed with this configuration?" "y"; then
                    # User does NOT want to proceed. Ask to edit from start or cancel wizard.
                    if prompt_yes_no "Edit configuration from the beginning, or cancel wizard? (Enter 'y' to Edit, 'n' to Cancel)" "y"; then
                        current_wizard_step=1 # Restart wizard from Step 1
                        log_message "INFO" "User chose to edit configuration from start."
                        # Consider resetting influential variables if they affect early steps.
                        # For now, assuming _prompt_ functions will correctly overwrite them.
                        # setup_is_advanced=false # Example, if needed for a clean restart.
                        continue # Re-loop the main wizard 'while true' to go to step 1
                    else
                        # User chose to cancel the wizard.
                        print_info "Configuration wizard cancelled at summary."
                        return_from_menu # Ensure menu stack is correct before returning
                        return 1 # Exit configure_tunnel with cancel status
                    fi
                else
                    # User wants to proceed with this configuration.
                    ((current_wizard_step++)) # Proceed to Save step
                fi
                ;;
            8) # Step 8 (Was 7): Generate Tunnel Name and Save Configuration
                local tunnel_name_suffix
                tunnel_name_suffix="${tunnel_mode}-${transport_protocol}-$(date +%s | tail -c 5)"
                local final_tunnel_name="bh-$tunnel_name_suffix"
                # cfg_sniffer_log is now populated in advanced_params_map if sniffer is true

                local config_file_path="$CONFIG_DIR/config-${final_tunnel_name}.toml"
                ensure_dir "$CONFIG_DIR" "755" # Ensure CONFIG_DIR is traversable
                : > "$config_file_path" # Create/truncate config file

                # Write [server] or [client] section header
                echo "[$tunnel_mode]" > "$config_file_path"

                # Common parameters (already corrected names)
                update_toml_value "$config_file_path" "transport" "$transport_protocol" "string"
                update_toml_value "$config_file_path" "token" "$common_auth_token" "string"

                if [[ "$tunnel_mode" == "server" ]]; then
                    update_toml_value "$config_file_path" "bind_addr" ":$server_listen_port" "string"
                    # Add the ports array
                    if [[ ${#server_port_rules[@]} -gt 0 ]]; then
                        echo "ports = [" >> "$config_file_path"
                        for rule in "${server_port_rules[@]}"; do
                            echo "  \"$rule\"," >> "$config_file_path"
                        done
                        echo "]" >> "$config_file_path"
                    else
                        echo "ports = [] # No forwarding rules defined" >> "$config_file_path"
                    fi
                else # client mode
                    update_toml_value "$config_file_path" "remote_addr" "${client_remote_ip}:${client_remote_port}" "string" # Name already corrected
                    # The line for `local = ":$client_local_fwd_port"` is now removed.
                fi

                # Write all parameters from advanced_params_map (populated for both Quick and Advanced)
                local param_key param_value param_type
                for param_key in "${!advanced_params_map[@]}"; do
                    param_value="${advanced_params_map[$param_key]}"
                    param_type="string" # Default
                    if [[ "$param_value" == "true" || "$param_value" == "false" ]]; then
                        param_type="boolean"
                    elif [[ "$param_value" =~ ^[0-9]+$ ]]; then
                        param_type="numeric"
                    fi

                    if [[ "$param_key" == "sniffer_log" && "${advanced_params_map[sniffer]}" != "true" ]]; then
                        continue # Skip sniffer_log if sniffer is not true
                    fi
                    if [[ "$param_key" == "sniffer_log" && "${advanced_params_map[sniffer]}" == "true" && -z "$param_value" ]]; then
                        # If sniffer is true but sniffer_log is empty in map (e.g. Quick setup didn't set it)
                        # then assign the generated default path.
                        param_value="/var/log/easybackhaul/${final_tunnel_name}-sniffer.json"
                    fi

                    if [[ "$param_key" == "web_port" && "$param_value" == "0" ]]; then
                        # Optional: Do not write 'web_port = 0' if backhaul binary defaults to disabled when key is absent.
                        # For explicitness, we are writing it. Backhaul should handle '0' as disabled.
                        # If it causes issues, this 'continue' can be un-commented.
                        # log_message "DEBUG" "Skipping web_port = 0 for $config_file_path"
                        # continue
                        : # Explicitly do nothing, will write web_port = 0
                    fi
                     # Skip empty edge_ip
                    if [[ "$param_key" == "edge_ip" && -z "$param_value" ]]; then
                        continue
                    fi

                    update_toml_value "$config_file_path" "$param_key" "$param_value" "$param_type"
                done

                if ! $setup_is_advanced; then
                    log_message "INFO" "Quick setup for $final_tunnel_name: All applicable optional parameters written with script defaults."
                fi

                if [[ -n "$cfg_tls_cert_path" && -n "$cfg_tls_key_path" ]]; then
                    update_toml_value "$config_file_path" "tls_cert" "$cfg_tls_cert_path" "string"
                    update_toml_value "$config_file_path" "tls_key" "$cfg_tls_key_path" "string"
                fi

                set_secure_file_permissions "$config_file_path" "600" # Will be chowned by create_systemd_service
                handle_success "Configuration saved: $config_file_path"
                ((current_wizard_step++))
                ;;
            9) # Step 9 (Was 8): Post-creation (Systemd, Start)
                if type create_systemd_service &>/dev/null; then
                    # create_systemd_service now handles enabling and the initial start attempt.
                    # It also prompts "Check service status now?".
                    # So, we just call it and report potential errors from it.
                    if ! create_systemd_service "$final_tunnel_name" "$config_file_path"; then
                         handle_error "ERROR" "Systemd service creation or initial start failed for '$final_tunnel_name'. Please check previous messages or use 'Manage Existing Tunnels' to check status and logs."
                         # No redundant start prompt here, create_systemd_service handles the attempt.
                    fi
                else
                    handle_error "WARNING" "Function 'create_systemd_service' not found. Cannot create service automatically."
                fi
                press_any_key
                return_from_menu # Return to the previous menu (likely main menu)
                return 0 # Exit configure_tunnel function
                ;;
            *)
                handle_error "CRITICAL" "Invalid wizard step in configure_tunnel: $current_wizard_step"
                return 1
                ;;
        esac
    done
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
        
        if prompt_yes_no "Would you like to create a backup before attempting fixes?" "y"; then
            backup_configuration_path "$config_file" "validation-error-backup"
            # print_success "Backup created" # backup_configuration_path handles its own success/failure messages
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
    # local ufw_exit_details=("0" "Back to Main Menu") # No longer needed
    local user_choice menu_rc

    while true; do
        local ufw_current_status="Inactive"
        if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
            ufw_current_status="Active"
        elif ! command -v ufw &>/dev/null; then
            ufw_current_status="Not Installed"
        fi
        print_menu_header "primary" "UFW Firewall Management" "Status: $ufw_current_status"
        
        menu_loop "Select UFW option" ufw_menu_options "_ufw_menu_help"
        local menu_rc=$?
        local user_choice="$MENU_CHOICE" # Capture MENU_CHOICE after $?
        
        case "$menu_rc" in
            0) # Numeric choice
                case "$user_choice" in
                    "1") _enable_ufw_with_ssh_allow ;;
                    "2") _disable_ufw ;;
                    "3") _view_ufw_status ;;
                    "4") _reset_ufw ;;
                    "5") _clean_orphaned_ufw_rules ;;
                    *) print_warning "Invalid option: $user_choice"; press_any_key ;;
                esac
                ;;
            2) # '?' Help
                # Help function already called by menu_loop. Loop again to show menu.
                continue ;;
            3) # 'm' Main Menu
                go_to_main_menu
                return 0 ;; # Return to main script loop
            4) # 'x' Exit script
                request_script_exit
                return 0 ;; # Return to main script loop
            5) # 'r' Return/Back/Cancel (to previous menu, likely main menu)
                return_from_menu # This pops the stack
                return 0 ;; # Return to main script loop
            6)  # Invalid input in menu_loop (warning and press_any_key handled by menu_loop)
                continue ;; # Re-display this menu
            *)
                print_warning "Unexpected menu_loop return code in manage_ufw_main_menu: $menu_rc (Choice: $user_choice)"
                press_any_key
                continue ;; # Re-display this menu
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

    # Ensure CONFIG_DIR and LOG_DIR are available (should be from globals.sh)
    # These are now needed for ReadWritePaths
    if [[ -z "$CONFIG_DIR" || -z "$LOG_DIR" ]]; then
        handle_error "CRITICAL" "CONFIG_DIR or LOG_DIR not defined. Cannot create systemd service with proper paths."
        return 1
    fi

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
    local effective_user="$service_user"
    local effective_group="$service_group"

    if [[ "$(id -u)" -eq 0 ]]; then # Running as root
        if [[ -z "$effective_user" ]]; then effective_user="nobody"; fi
        if [[ -z "$effective_group" ]]; then effective_group="nogroup"; fi

        if ! id -u "$effective_user" >/dev/null 2>&1; then
            log_message "WARN" "User '$effective_user' not found, service will run as root. Consider creating a dedicated user."
            effective_user="root"
            effective_group="root"
        elif ! getent group "$effective_group" >/dev/null 2>&1; then
             log_message "WARN" "Group '$effective_group' not found, service will run as root. Consider creating a dedicated group or using an existing one."
            effective_user="root" # Revert user to root too if group is invalid for nobody
            effective_group="root"
        fi
    elif [[ -n "$effective_user" ]]; then
         log_message "WARN" "Running as non-root. Service User/Group might not be applied effectively by systemd unless root manages it."
    fi

    # Ensure the service configuration file has correct ownership and permissions
    # The CONFIG_DIR (/etc/easybackhaul/configs) itself should be root:nogroup 0770 (set by globals.sh)
    # This allows 'nobody' (if in 'nogroup') to read files within it.
    if [[ -f "$config_path" ]] && [[ "$(id -u)" -eq 0 ]]; then
        log_message "DEBUG" "Setting ownership of $config_path to $effective_user:$effective_group"
        chown "${effective_user}:${effective_group}" "$config_path" || handle_error "WARN" "Failed to chown $config_path to $effective_user:$effective_group"

        log_message "DEBUG" "Setting permissions of $config_path to 0640"
        chmod 0640 "$config_path" || handle_error "WARN" "Failed to chmod $config_path to 0640"
    elif [[ ! -f "$config_path" ]]; then
        handle_error "ERROR" "Configuration file $config_path not found. Cannot set permissions or create service."
        return 1
    fi

    # Ensure the directory for systemd service files exists
    ensure_dir "$(dirname "$service_file_path")" "0755" # Systemd service dir usually root owned

    # Create the service file content
    # Added User and Group. Increased LimitNOFILE.
    # Added ReadWritePaths for the new CONFIG_DIR and LOG_DIR.
    # Set PrivateTmp=false explicitly.
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
# Security Hardening Options
ProtectSystem=strict
ProtectHome=true
PrivateTmp=false # Set to false as we are managing config access explicitly.
NoNewPrivileges=true
ReadWritePaths=${CONFIG_DIR} # Allow reading from the config directory
ReadWritePaths=${LOG_DIR}    # Allow writing to the log directory
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW # Adjust to minimum required

[Install]
WantedBy=multi-user.target
EOL

    if ! run_with_spinner "Reloading systemd daemon..." systemctl daemon-reload; then
        handle_error "ERROR" "Failed to reload systemd daemon. Service file might be invalid: $service_file_path. Check permissions and syntax."
        if [[ -f "$service_file_path" ]]; then
            cat "$service_file_path" # Show the generated service file for debugging
        fi
        return 1
    fi

    log_message "INFO" "Enabling service $service_name..."
    if ! run_with_spinner "Enabling service $service_name..." systemctl enable "$service_name"; then
        handle_error "ERROR" "Failed to enable service $service_name. Check systemd logs (journalctl -xe) and service file."
        journalctl -u "$service_name" -n 20 --no-pager
        return 1
    fi

    log_message "INFO" "Attempting to start service $service_name..."
    # Before starting, let's try to stat the config file as the service user to check access
    if [[ "$effective_user" != "root" ]] && command -v sudo &>/dev/null && command -v stat &>/dev/null; then
        log_message "DEBUG" "Pre-start check: Attempting to stat '$config_path' as user '$effective_user'..."
        if sudo -u "$effective_user" stat "$config_path" >/dev/null 2>&1; then
            log_message "INFO" "Pre-start check: User '$effective_user' can access '$config_path'."
        else
            log_message "WARN" "Pre-start check: User '$effective_user' may NOT be able to access '$config_path'. Stat command failed."
            # Log ls -ld output for the config directory and the file itself
            ls -ld "$CONFIG_DIR"
            ls -l "$config_path"
        fi
    fi

    if ! run_with_spinner "Starting service $service_name..." systemctl start "$service_name"; then
        handle_error "ERROR" "Failed to start service $service_name."
        print_info "Please check the service logs for details: journalctl -u $service_name -n 50 --no-pager"
        if prompt_yes_no "Show last 20 lines of the service log now?" "y"; then
            journalctl -u "$service_name" -n 20 --no-pager
        fi
        # Also show status which might include more direct error info
        systemctl status "$service_name" --no-pager
        return 1
    fi

    handle_success "Service $service_name created, enabled, and appears to be starting."
    print_info "It might take a few seconds for the service to fully initialize."

    if prompt_yes_no "Check service status now to confirm it's active (running)?" "y"; then
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
    # local cron_exit_details=("0" "Back to Tunnel Management") # No longer needed
    local user_choice menu_rc
    local action_taken=false

    while true; do
        action_taken=false # Reset for each loop iteration
        print_menu_header "secondary" "Cron Auto-Restart Management" "Service: $service_name"
        
        current_cron_job=$(crontab -l 2>/dev/null | grep -F "$service_name" | grep -F "# $CRON_COMMENT_TAG")
        if [[ -n "$current_cron_job" ]]; then
            print_success "Current Cron Job: $current_cron_job"
        else
            print_warning "No EasyBackhaul-managed cron job found for this service."
        fi
        echo

        menu_loop "Select option" cron_menu_options "_manage_cron_menu_help \"$service_name\""
        user_choice="$MENU_CHOICE"
        menu_rc=$?
        
        case "$menu_rc" in
            0) # Numeric choice
                action_taken=true
                case "$user_choice" in
                    "1") _set_service_cron_job "*/15 * * * *" "$service_name" ;;
                    "2") _set_service_cron_job "0 * * * *" "$service_name" ;;
                    "3") _set_service_cron_job "0 */6 * * *" "$service_name" ;;
                    "4") _set_service_cron_job "0 0 * * *" "$service_name" ;;
                    "5")
                        local custom_interval
                        print_info "Enter custom interval in minutes (1-1440, or 'c' to cancel this step)."
                        while true; do
                            read -r -p "Interval (minutes) or 'c': " custom_interval
                            custom_interval=$(echo "$custom_interval" | tr '[:upper:]' '[:lower:]')
                            if [[ "$custom_interval" == "c" ]]; then
                                print_info "Custom interval setup cancelled."
                                action_taken=false # Not a full action if cancelled here
                                break
                            elif [[ "$custom_interval" =~ ^[0-9]+$ ]] && (( custom_interval >= 1 && custom_interval <= 1440 )); then
                                _set_service_cron_job "*/${custom_interval} * * * *" "$service_name"
                                break
                            else
                                print_warning "Invalid interval. Please enter 1-1440, or 'c' to cancel."
                            fi
                        done
                        ;;
                    "6") _remove_service_cron_job "$service_name" ;;
                    *)
                        print_warning "Invalid option: $user_choice"; press_any_key
                        action_taken=false # Invalid choice is not an action
                        ;;
                esac
                if $action_taken; then break; fi # Break while true if a valid action was taken
                ;;
            2) # '?' Help shown
                continue ;;
            3) # 'm' Main Menu
                go_to_main_menu; return 0 ;;
            4) # 'x' Exit script
                request_script_exit; return 0 ;;
            5) # 'r' Return/Back (to tunnel management)
                return_from_menu; return 0 ;;
            6) # 'c' Cancel (acts like 'r' here)
                return_from_menu; return 0 ;;
            *)
                handle_error "ERROR" "Unhandled menu_loop code $menu_rc in manage_cron_job_for_service"; press_any_key; continue;;
        esac
    done

    if $action_taken; then
        press_any_key # After a cron job action
    fi
    return_from_menu
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
        # Filter out the specific job line.
        # The line is expected to be exactly: <schedule_expression> systemctl restart <service_name> # <CRON_COMMENT_TAG>
        # We need to match this pattern carefully. Since schedule_expression can vary,
        # we match the fixed parts: "systemctl restart ${service_to_manage} # ${CRON_COMMENT_TAG}"
        # The `grep -v` will remove lines containing this exact string.
        local line_to_remove_pattern="systemctl restart ${service_to_manage} # ${CRON_COMMENT_TAG}"
        echo "$current_crontab" | grep -vF "$line_to_remove_pattern" | crontab -

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
    # local current_exit_details=("0" "Back to Tunnel Management") # No longer needed
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

        menu_loop "Select watcher option" menu_options "_tunnel_watcher_menu_help \"$tunnel_short_suffix\""
        local menu_rc=$?
        local user_choice="$MENU_CHOICE" # Capture MENU_CHOICE after $?

        case "$menu_rc" in
            0) # Numeric choice
                case "$user_choice" in
                    "1") _enable_tunnel_watcher "$main_service_name" "$tunnel_short_suffix" "$tunnel_config_file" ;;
                    "2") _disable_tunnel_watcher "$tunnel_short_suffix" "$tunnel_config_file" ;;
                    "3") _show_tunnel_watcher_status "$tunnel_short_suffix" ;;
                    "4")
                        # _view_tunnel_watcher_log calls view_system_log which is a menu
                        navigate_to_menu "_view_tunnel_watcher_log \"$tunnel_short_suffix\""
                        return 0 ;;
                    "5") _edit_tunnel_watcher_config "$tunnel_short_suffix" "$tunnel_config_file" ;;
                    "6") _test_tunnel_watcher_comm "$tunnel_short_suffix" ;;
                    "7")
                        # _manage_watcher_shared_secret is a menu
                        navigate_to_menu "_manage_watcher_shared_secret \"$tunnel_config_file\""
                        return 0 ;;
                    *) print_warning "Invalid option: $user_choice"; press_any_key ;;
                esac
                ;;
            2) # '?' Help shown
                continue ;;
            3) # 'm' Main Menu
                go_to_main_menu; return 0 ;;
            4) # 'x' Exit script
                request_script_exit; return 0 ;;
            5) # 'r' Return/Back (to specific tunnel menu)
                return_from_menu; return 0 ;;
            6) # Invalid input in menu_loop (warning and press_any_key handled by menu_loop)
                continue ;; # Re-display this menu
            *)
                handle_error "ERROR" "Unhandled menu_loop code $menu_rc in manage_tunnel_watcher"; press_any_key
                continue;; # Ensure redraw on unexpected error
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
    # local secret_exit_details=("0" "Back") # No longer needed
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

    menu_loop "Select secret option" secret_menu_options "_secret_menu_help"
    local menu_rc=$?
    local user_choice="$MENU_CHOICE"

    case "$menu_rc" in
        0) # Numeric choice
            case "$user_choice" in
                "1") # View/Copy
                    local secret_to_show
                    secret_to_show=$(grep 'watcher_shared_secret' "$main_tunnel_config_file" | sed 's/.*=[[:space:]]*"\(.*\)"/\1/' 2>/dev/null || cat "$CONFIG_DIR/watcher_secret" 2>/dev/null || echo "${RESTART_WATCHER_SECRET}")
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
                    local role_for_set="client"
                    if grep -q 'mode[[:space:]]*=[[:space:]]*"server"' "$main_tunnel_config_file" 2>/dev/null; then role_for_set="server"; fi
                    local new_secret_val
                    new_secret_val=$(_get_or_set_watcher_secret "$main_tunnel_config_file" "$role_for_set")
                    if [[ -n "$new_secret_val" ]]; then
                        handle_success "Watcher secret process completed."
                    else
                        handle_warning "Watcher secret process cancelled or failed."
                    fi
                    ;;
                "3") # Generate new
                     if prompt_yes_no "Generate a new random secret? This will overwrite existing." "n"; then
                        local new_s
                        new_s=$(generate_random_secret 32)
                        print_info "New Generated Secret: $new_s"
                        print_warning "You MUST update the other side of the tunnel with this secret."
                        if prompt_yes_no "Use this new secret?" "y"; then
                            if [[ -z "$RESTART_WATCHER_SECRET" && -n "$GLOBAL_WATCHER_SECRET_FILE" ]]; then
                                echo "$new_s" > "$GLOBAL_WATCHER_SECRET_FILE"
                                set_secure_file_permissions "$GLOBAL_WATCHER_SECRET_FILE"
                            fi
                            update_toml_value "$main_tunnel_config_file" "watcher_shared_secret" "$new_s" "string"
                            handle_success "New secret set and saved."
                        else
                            print_info "New secret generation cancelled."
                        fi
                    fi
                    ;;
                *) print_warning "Invalid option: $user_choice";;
            esac
            ;;
        2) # '?' Help shown
            _manage_watcher_shared_secret "$main_tunnel_config_file"; return $? ;; # Re-call current function
        3) # 'm' Main Menu
            go_to_main_menu; return 0 ;;
        4) # 'x' Exit script
            request_script_exit; return 0 ;;
        5) # 'r' Return/Back (to manage_tunnel_watcher menu)
            return_from_menu; return 0 ;;
        6) # Invalid input
            _manage_watcher_shared_secret "$main_tunnel_config_file"; return $? ;;
        *)
            handle_error "ERROR" "Unhandled menu_loop code $menu_rc in _manage_watcher_shared_secret"; press_any_key;
            _manage_watcher_shared_secret "$main_tunnel_config_file"; return $? ;;
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
        echo "  - Navigation keys [?, c, r, m, x] function as described in the footer."
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

            # local no_tunnel_exit_options=("0. Back to Main Menu") # No longer needed
            local no_tunnel_choice no_tunnel_rc

            # Prompt is empty as options are self-explanatory or covered by footer
            # Pass empty options array, menu_loop handles it.
            menu_loop "" tunnel_options "_manage_tunnels_menu_help"
            local no_tunnel_rc=$?
            local no_tunnel_choice="$MENU_CHOICE" # Will be a nav key, capture after $?

            case "$no_tunnel_rc" in
                # Case 0 (numeric choice) is not possible if tunnel_options is empty.
                2) # '?' Help
                    # Help function already called by menu_loop. Loop again to show menu.
                    continue ;;
                3) # 'm' Main Menu
                    go_to_main_menu
                    return 0 ;; # Return to main script loop
                4) # 'x' Exit script
                    request_script_exit
                    return 0 ;; # Return to main script loop
                5) # 'r' Return/Back/Cancel (to previous menu, likely main menu)
                    return_from_menu # This pops the stack
                    return 0 ;; # Return to main script loop
                6) # Invalid input in menu_loop (warning and press_any_key handled by menu_loop)
                    continue ;; # Re-display this menu
                *)
                    print_warning "Unexpected menu_loop return code in manage_tunnels_menu (no tunnels): $no_tunnel_rc (Choice: $no_tunnel_choice)"
                    press_any_key
                    continue ;; # Re-display this menu
            esac
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

            local formatted_status="[ ${status_color}${status_str}${COLOR_RESET} ]"
            local formatted_line=$(printf "%-3s %-40s %-20s" "$idx." "$current_tunnel_suffix" "$formatted_status")
            tunnel_options+=("$formatted_line")
            service_name_map[$idx]="$current_service_name"
            tunnel_suffix_map[$idx]="$current_tunnel_suffix"
            ((idx++))
        done

        # local exit_options=("0. Back to Main Menu") # No longer needed
        local user_choice menu_rc # menu_rc declared here, user_choice will be local too

        menu_loop "Select tunnel to manage" tunnel_options "_manage_tunnels_menu_help"
        menu_rc=$? # Capture $? first
        user_choice="$MENU_CHOICE" # Then MENU_CHOICE

        case "$menu_rc" in
            0) # Numeric choice
                if [[ -n "${service_name_map[$user_choice]}" ]]; then
                    local selected_service="${service_name_map[$user_choice]}"
                    local selected_suffix="${tunnel_suffix_map[$user_choice]}"
                    navigate_to_menu "manage_specific_tunnel_menu \"$selected_service\" \"$selected_suffix\""
                    return 0 # Let main loop call the new menu function
                else
                    # This case should ideally not be reached if menu_loop validates numeric range
                    print_warning "Invalid numeric selection: $user_choice. Please try again."
                    press_any_key
                fi
                ;;
            2) # '?' Help
                # Help function already called by menu_loop. Loop again to show menu.
                continue ;;
            3) # 'm' Main Menu
                go_to_main_menu
                return 0 ;; # Return to main script loop
            4) # 'x' Exit script
                request_script_exit
                return 0 ;; # Return to main script loop
            5) # 'r' Return/Back/Cancel (to previous menu, likely main menu)
                return_from_menu # This pops the stack
                return 0 ;; # Return to main script loop
            6) # Invalid input in menu_loop (warning and press_any_key handled by menu_loop)
                continue ;; # Re-display this menu
            *)
                print_warning "Unexpected menu_loop return code in manage_tunnels_menu: $menu_rc (Choice: $user_choice)"
                press_any_key
                continue ;; # Re-display this menu
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
    # local exit_options=("0. Back to Tunnel List") # No longer needed
    local user_choice menu_rc # menu_rc declared here, user_choice will be local too

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
        
        menu_loop "Select action" menu_options "_specific_tunnel_menu_help"
        local menu_rc=$?
        local user_choice="$MENU_CHOICE" # Capture MENU_CHOICE after $? is captured

        # local action_performed_and_continue=false # May not be needed if all actions handle their own flow

        case "$menu_rc" in
            0) # Numeric choice
                case "$user_choice" in
                    "1") _mng_start_tunnel "$service_name" ;;
                    "2") _mng_stop_tunnel "$service_name" ;;
                    "3") _mng_restart_tunnel "$service_name" ;;
                    "4")
                        # view_system_log is a self-contained menu, use navigate_to_menu
                        navigate_to_menu "view_system_log \"journalctl\" \"$service_name\" \"Logs for $tunnel_suffix\""
                        return 0 ;;
                    "5") _mng_view_configuration "$config_file_path" "$tunnel_suffix" ;;
                    "6") _mng_edit_configuration "$config_file_path" "$service_name" ;;
                    "7")
                        # _mng_change_log_level is a self-contained menu, use navigate_to_menu
                        navigate_to_menu "_mng_change_log_level \"$config_file_path\" \"$service_name\""
                        return 0 ;;
                    "8") _mng_hot_reload_service "$service_name" ;;
                    "9") _mng_test_connection "$config_file_path" ;;
                    "10")
                         if type manage_tunnel_watcher &>/dev/null; then
                            navigate_to_menu "manage_tunnel_watcher \"$service_name\" \"$tunnel_suffix\" \"$config_file_path\""
                            return 0
                         else
                            handle_error "ERROR" "Watcher management module not loaded correctly."
                            press_any_key
                         fi
                         ;;
                    "11")
                        if type validate_tunnel_config &>/dev/null; then # Assuming this is the correct validation function
                            validate_tunnel_config "$config_file_path" # Or validate_specific_tunnel_config if it exists
                        else
                            handle_error "INFO" "Config validation function not available."
                        fi
                        press_any_key
                        ;;
                    "12")
                        if _mng_delete_tunnel "$service_name" "$tunnel_suffix" "$config_file_path"; then
                            return_from_menu # Deletion successful, return to tunnel list
                            return 0
                        fi
                        # If deletion cancelled, _mng_delete_tunnel handles press_any_key and returns 1
                        # The loop will continue to re-display this menu.
                        ;;
                    *) print_warning "Invalid option: $user_choice"; press_any_key ;;
                esac
                ;;
            2) # '?' Help
                # Help function already called by menu_loop. Loop again to show menu.
                continue ;;
            3) # 'm' Main Menu
                go_to_main_menu
                return 0 ;; # Return to main script loop
            4) # 'x' Exit script
                request_script_exit
                return 0 ;; # Return to main script loop
            5) # 'r' Return/Back/Cancel (to previous menu, tunnel list)
                return_from_menu # This pops the stack
                return 0 ;; # Return to main script loop
            6) # Invalid input in menu_loop (warning and press_any_key handled by menu_loop)
                continue ;; # Re-display this menu
            *)
                print_warning "Unexpected menu_loop return code in manage_specific_tunnel_menu: $menu_rc (Choice: $user_choice)"
                press_any_key
                continue ;; # Re-display this menu
        esac
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
        # local log_level_exit_options=("0. Cancel and Back") # No longer needed
        local user_choice menu_rc

        menu_loop "Select new log level" log_level_options "_log_level_help"
        local menu_rc=$?
        local user_choice="$MENU_CHOICE"

        local new_level=""
        case "$menu_rc" in
            0) # Numeric choice
                case "$user_choice" in
                    "1") new_level="debug" ;;
                    "2") new_level="info" ;;
                    "3") new_level="warn" ;;
                    "4") new_level="error" ;;
                    *) print_warning "Invalid numeric selection: $user_choice"; press_any_key; continue ;;
                esac
                ;;
            2) # '?' Help
                # Help function already called by menu_loop. Loop again to show menu.
                continue ;;
            3) # 'm' Main Menu
                go_to_main_menu
                return 0 ;; # Return to main script loop to process navigation
            4) # 'x' Exit script
                request_script_exit
                return 0 ;; # Return to main script loop
            5) # 'r' Return/Back/Cancel
                print_info "Log level change cancelled."
                press_any_key
                return_from_menu
                return 0 ;;
            6) # Invalid input in menu_loop (warning and press_any_key handled by menu_loop)
                continue ;;
            *)
                print_warning "Unexpected menu_loop return code in _mng_change_log_level: $menu_rc (Choice: $user_choice)"
                press_any_key; continue ;;
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

# End of tunnel management functions.

true # Ensure script is valid if sourced.
# --- MODULE: modules/menu.sh ---
# modules/menu.sh
# Main menu logic, script entry point, installation wizard, and uninstallation.

# --- Installation Wizard ---
# This function guides the user through installing the Backhaul binary.
# It now directly calls 'download_backhaul_binary_workflow'.
_initial_installation_wizard() {
    print_menu_header "primary" "EasyBackhaul Initial Setup" "Backhaul Binary Installation Required"
    print_warning "The Backhaul binary is not found or is invalid at the configured path: $BIN_PATH"
    print_info "The following workflow will guide you through the installation."
    press_any_key

    # Directly call the consolidated workflow function from backhaul_core.sh
    # download_backhaul_binary_workflow will handle its own menu and logic.
    # It returns 0 on success (binary installed and verified), 1 on failure/cancellation.
    if download_backhaul_binary_workflow; then
        # verify_binary_installation is called within install_downloaded_binary,
        # which is called by the helpers in download_backhaul_binary_workflow.
        # So, if download_backhaul_binary_workflow returns 0, it implies success.
        handle_success "Backhaul binary installed and verified successfully!"
        press_any_key
        return 0 # Successful installation
    else
        handle_error "ERROR" "Backhaul binary installation was cancelled or failed."
        print_warning "EasyBackhaul may not function correctly without the binary."
        press_any_key
        return 1 # Indicate failure/cancellation of initial setup step
    fi
}

system_health_monitor_menu() {
    _health_monitor_menu_help() {
        print_menu_header "secondary" "System Health Monitor Help" "System Overview"
        echo "This screen provides an overview of system resources, tunnel health, and performance."
        echo "Options:"
        echo "  1. Refresh: Reloads all the displayed health information."
        echo "  2. Clean Stale Processes & Temp Files: Attempts to remove known temporary files or orphaned processes."
        echo "  3. View System Logs: Access logs like easybackhaul.log or performance.log."
        press_any_key
    }

    local health_menu_options=(
        "1. Refresh Health Status"
        "2. Clean Stale Processes & Temp Files"
        "3. View System Logs (e.g., easybackhaul.log, performance.log)"
    )
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
        print_info "--- Active Watcher Processes (Summary) ---"
        if pgrep -f "${EASYBACKHAUL_TMP_DIR:-/tmp}/backhaul-watcher-.*\.sh" >/dev/null; then pgrep -af "${EASYBACKHAUL_TMP_DIR:-/tmp}/backhaul-watcher-.*\.sh" | sed 's/^/    /'; else print_info "  No active watcher processes found."; fi

        menu_loop "Select action" health_menu_options "_health_monitor_menu_help"
        local menu_rc=$?
        local user_choice="$MENU_CHOICE" # Capture MENU_CHOICE after $? is captured

        case "$menu_rc" in
            0) # Numeric choice
                case "$user_choice" in
                    "1") continue ;; # Refresh by re-looping
                    "2") run_with_spinner "Cleaning stale processes and files..." cleanup_stale_processes_and_files; press_any_key ;;
                    "3")
                        if [[ -n "$LOG_DIR" ]]; then
                            # navigate_to_menu will push to stack, then current function returns 0
                            # main loop will pick up the new function from stack.
                            navigate_to_menu "view_system_log \"file\" \"$LOG_DIR/easybackhaul.log\" \"EasyBackhaul Main Log\""
                            return 0 # Return to main script loop to process navigation
                        else
                            handle_error "WARNING" "LOG_DIR not defined."
                            press_any_key
                        fi
                        ;;
                    *) print_warning "Invalid option: $user_choice"; press_any_key ;;
                esac
                ;;
            2) # '?' Help
                # Help function already called by menu_loop. Loop again to show menu.
                continue ;;
            3) # 'm' Main Menu
                go_to_main_menu
                return 0 ;; # Return to main script loop
            4) # 'x' Exit script
                request_script_exit
                return 0 ;; # Return to main script loop
            5) # 'r' Return/Back/Cancel (to previous menu, likely main menu)
                return_from_menu
                return 0 ;; # Return to main script loop
            6) # Invalid input in menu_loop (warning already printed by menu_loop)
                # press_any_key was already handled by menu_loop before returning 6.
                # Loop again to show the health monitor menu.
                continue ;;
            *)
                print_warning "Unexpected menu_loop return code in system_health_monitor_menu: $menu_rc (Choice: $user_choice)"
                press_any_key
                continue ;; # Re-draw menu on unexpected code
        esac
    done
}

_perform_full_uninstall() {
    print_menu_header "primary" "Uninstall EasyBackhaul" "Irreversible Action"
    print_warning "WARNING: This will PERMANENTLY REMOVE EasyBackhaul and ALL related data!"
    echo "This includes:"
    echo "  - The Backhaul binary ($BIN_PATH)"
    echo "  - All tunnel configurations (from $CONFIG_DIR, likely /etc/easybackhaul/configs)"
    echo "  - The main configuration directory structure (e.g., /etc/easybackhaul)"
    echo "  - All systemd services (e.g., backhaul-*.service in $SERVICE_DIR)"
    echo "  - All UFW rules managed by EasyBackhaul (if UFW is used)"
    echo "  - All EasyBackhaul-managed cron jobs."
    echo "  - Temporary files and watcher scripts (typically in ${EASYBACKHAUL_TMP_DIR:-/tmp})"
    echo "  - Backup files ($BACKUP_DIR)"
    echo "  - Log files and directory (from $LOG_DIR, likely /var/log/easybackhaul) - you will be asked about this."
    echo "  - Logrotate configuration (/etc/logrotate.d/easybackhaul)"
    
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
                suffix_to_clean=${service_name#backhaul-}
                suffix_to_clean=${suffix_to_clean%.service}
                cleanup_watcher_files "$suffix_to_clean" "true"
            elif [[ "$service_name" == backhaul-watcher-*.service ]]; then
                suffix_to_clean=${service_name#backhaul-watcher-}
                suffix_to_clean=${suffix_to_clean%.service}
                cleanup_watcher_files "$suffix_to_clean" "true"
            fi
        done
    else
        print_info "No 'backhaul-bh-*.service' or 'backhaul-watcher-*.service' services found."
    fi
    
    log_message "INFO" "Performing general watcher file cleanup from ${EASYBACKHAUL_TMP_DIR:-/tmp}..."
    find "${EASYBACKHAUL_TMP_DIR:-/tmp}" -maxdepth 1 \( -name 'backhaul-watcher-*' -o -name 'restart_ack_*' \) -print -exec rm -rf {} \; &>/dev/null
    if [[ -n "$EASYBACKHAUL_TMP_DIR" && "$EASYBACKHAUL_TMP_DIR" != "/tmp" && "$EASYBACKHAUL_TMP_DIR" != "/tmp/" ]]; then # Check if it's a different dir
        find "/tmp" -maxdepth 1 \( -name 'backhaul-watcher-*' -o -name 'restart_ack_*' \) -print -exec rm -rf {} \; &>/dev/null
    fi

    print_info "Removing systemd service files..."
    if [[ -d "$SERVICE_DIR" ]]; then
        secure_delete "${SERVICE_DIR}/backhaul-bh-*.service"
        secure_delete "${SERVICE_DIR}/backhaul-watcher-*.service"
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
    # CONFIG_DIR is now /etc/easybackhaul/configs. Remove its parent /etc/easybackhaul as well.
    if [[ -n "$CONFIG_DIR" && -d "$(dirname "$CONFIG_DIR")" ]]; then # Check parent dir
        secure_delete "$(dirname "$CONFIG_DIR")" # This removes /etc/easybackhaul (and configs within)
        log_message "INFO" "Removed main config directory structure: $(dirname "$CONFIG_DIR")"
    elif [[ -n "$CONFIG_DIR" && -d "$CONFIG_DIR" ]]; then # Fallback if parent wasn't as expected
         secure_delete "$CONFIG_DIR"
         log_message "INFO" "Removed config directory: $CONFIG_DIR"
    fi

    if [[ -n "$BACKUP_DIR" && -d "$BACKUP_DIR" ]]; then secure_delete "$BACKUP_DIR"; fi
    if [[ -n "$EASYBACKHAUL_TMP_DIR" && -d "$EASYBACKHAUL_TMP_DIR" && "$EASYBACKHAUL_TMP_DIR" != "/tmp" && "$EASYBACKHAUL_TMP_DIR" != "/tmp/" ]]; then
        secure_delete "$EASYBACKHAUL_TMP_DIR"
    fi

    # Remove logrotate configuration
    local logrotate_conf_file="/etc/logrotate.d/easybackhaul"
    if [[ -f "$logrotate_conf_file" ]]; then
        secure_delete "$logrotate_conf_file"
        log_message "INFO" "Removed logrotate configuration file: $logrotate_conf_file"
    fi

    # LOG_DIR is now /var/log/easybackhaul
    if [[ -n "$LOG_DIR" && -d "$LOG_DIR" ]]; then
        if prompt_yes_no "Also delete the main log directory ($LOG_DIR) and all its contents?" "n"; then
            secure_delete "$LOG_DIR"
            handle_success "Log directory $LOG_DIR deleted."
        else
            print_info "Log directory $LOG_DIR preserved."
        fi
    fi
    
    handle_success "EasyBackhaul uninstallation completed."
    print_info "Some manual cleanup of system logs (journalctl) might be desired if services were problematic."
    print_info "Exiting now."
    exit 0
}

# --- Global Ctrl+C Handler ---
_global_ctrl_c_handler() {
    print_error "\n\nCtrl+C pressed. Exiting EasyBackhaul script."
    log_message "WARN" "Ctrl+C interrupt received. Exiting script."
    if type request_script_exit &>/dev/null; then
        request_script_exit
    fi
    exit 130
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
    local user_choice menu_rc

    local help_func_name="show_main_application_help"
    if ! type "$help_func_name" &>/dev/null; then
        _generic_main_menu_help() {
            print_menu_header "secondary" "Main Menu Help"
            echo "This is the main control panel for EasyBackhaul."
            echo "Use the number keys to select an option from the menu."
            echo "Follow prompts for each section."
            echo "The footer shows navigation keys: [?] Help | [c] Cancel Op | [r] Return/Back | [m] Main Menu | [x] Exit Script."
            press_any_key
        }
        help_func_name="_generic_main_menu_help"
    fi

    menu_loop "Select option" main_menu_options "$help_func_name"
    local menu_rc=$?
    local user_choice="$MENU_CHOICE" # Capture MENU_CHOICE after $? is captured
    
    case "$menu_rc" in
        0) # Numeric choice
            case "$user_choice" in
                "1") navigate_to_menu "configure_tunnel" ;;
                "2") navigate_to_menu "manage_tunnels_menu" ;;
                "3")
                    # download_backhaul_binary_workflow handles its own user feedback and press_any_key.
                    # It returns 0 for actual install success, 1 for failure/cancel,
                    # and will be updated to return 2 if only diagnostics were run then cancelled.
                    local workflow_rc
                    download_backhaul_binary_workflow
                    workflow_rc=$?
                    if [[ "$workflow_rc" -eq 0 ]]; then
                        # Optionally, a very brief confirmation here if needed, but primary feedback is in workflow.
                        log_message "INFO" "Backhaul binary workflow completed successfully (main_menu_entry)."
                    elif [[ "$workflow_rc" -eq 1 ]]; then
                        log_message "WARN" "Backhaul binary workflow cancelled or failed (main_menu_entry)."
                    # else # e.g. rc=2, diagnostics run then cancelled - no specific message here needed yet
                    fi
                    # No generic handle_success/error or press_any_key here.
                    ;;
                "4")
                    # generate_self_signed_tls_cert handles its own user feedback and press_any_key.
                    generate_self_signed_tls_cert
                    # No generic handle_success/error or press_any_key here.
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
                    _perform_full_uninstall
                    # If uninstallation was cancelled (returns 1), we want to stay in the main menu loop.
                    # main_menu_entry will be called again by the main script loop.
                    if [[ $? -eq 1 ]]; then return 0; fi
                    # If uninstallation happened (returns 0), script exits, so this path isn't critical.
                    ;;
                 *) print_warning "Invalid selection from main_menu_entry: $user_choice"; press_any_key ;;
            esac
            ;;
        2) # '?' Help
            # Help function was already called by menu_loop.
            # Loop again to show the main menu.
            return 0 ;;
        3) # 'm' Main Menu
            # Already in main menu, so just re-display.
            return 0 ;;
        4) # 'x' Exit Script
            request_script_exit
            return 0 ;;
        5) # 'r' Return/Back/Cancel
            # In main menu, 'r' acts as 'x' (exit).
            request_script_exit
            return 0 ;;
        6)  # Invalid input from menu_loop (warning and press_any_key already done by menu_loop)
            # Just need to ensure main_menu_entry is re-displayed.
            return 0 ;; # Fall through to the end of function's return 0 is fine.
        *)
            print_warning "Unexpected menu_loop return code in main_menu_entry: $menu_rc (Choice: $user_choice)"
            press_any_key ;; # Fall through to the end of function's return 0.
    esac
    return 0
}

main_script_entry_point() {
    # Initialize logging as the very first step
    if type init_logging &>/dev/null; then
        init_logging
    else
        echo "FATAL ERROR: init_logging function not found. Cannot proceed." >&2
        exit 1
    fi

    # Set up a global trap for Ctrl+C
    trap '_global_ctrl_c_handler' INT

    log_message "INFO" "EasyBackhaul script started."

    # --- Variable Definitions ---
    # Define the base application directory. Default to /usr/local/share/easybackhaul if not set.
    # This is a more appropriate default location for shared application data.
    : "${EASYBACKHAUL_APP_DIR:=/usr/local/share/easybackhaul}"

    # All other paths are derived from globals.sh defaults, which are now set early.
    # The : a=b syntax is a fallback, but globals.sh should have already set these.
    # We ensure they are not empty.
    : "${CONFIG_DIR:?CONFIG_DIR not set by globals.sh}"
    : "${BACKUP_DIR:?BACKUP_DIR not set by globals.sh}"
    : "${BIN_PATH:?BIN_PATH not set by globals.sh}"
    : "${LOG_DIR:?LOG_DIR not set by globals.sh}"
    : "${SERVICE_DIR:=/etc/systemd/system}" # This one is standard system path
    : "${CRON_COMMENT_TAG:=EasyBackhaul}"   # This is a script constant

    # --- Directory and Permission Setup ---
    # This wrapper is a temporary solution for ensuring directories exist.
    # It will be removed once the logic is fully integrated into init_logging and other setup functions.
    ensure_dir_wrapper() {
        local dir_path="$1"
        local permissions="${2:-750}" # Default to 750
        if [[ -z "$dir_path" ]]; then
            log_message "WARN" "ensure_dir_wrapper: Directory path is empty. Skipping."
            return
        fi

        # Use the robust ensure_dir from helpers.sh if available
        if type ensure_dir &>/dev/null; then
            ensure_dir "$dir_path" "$permissions"
        else
            # Fallback for unexpected cases where helpers.sh might not be sourced
            mkdir -p "$dir_path" && chmod "$permissions" "$dir_path"
            log_message "WARN" "ensure_dir function not found. Used basic mkdir -p."
        fi
    }

    # With variables now properly defined, create the necessary directories.
    # These calls are now safe from the "Directory path is empty" warning.
    ensure_dir_wrapper "$(dirname "$BIN_PATH")" "755"
    # Config, Backup, and Log directories are handled by their respective setup functions
    # (e.g., _globals_ensure_config_dir_for_secret, init_logging).
    # Explicit calls here can be removed if those functions are guaranteed to run first.
    # For safety during refactoring, we can leave them.
    ensure_dir_wrapper "$CONFIG_DIR" # Uses default 750
    ensure_dir_wrapper "$BACKUP_DIR" "700"
    ensure_dir_wrapper "$LOG_DIR"    # Uses default 750, init_logging will refine permissions

    # --- Prerequisite Checks ---
    if [[ $EUID -ne 0 ]]; then handle_critical_error "This script must be run as root or with sudo."; fi
    
    if type check_dependencies &>/dev/null; then check_dependencies;
    else handle_critical_error "check_dependencies function not found."; fi

    if type get_server_info &>/dev/null; then get_server_info; else log_message "WARN" "get_server_info not found."; fi

    if [[ ! -f "$BIN_PATH" ]] || ! verify_binary_installation "quiet"; then
        log_message "WARN" "Backhaul binary not found or failed verification at $BIN_PATH. Starting installation wizard."
        if ! _initial_installation_wizard; then
            if [[ ! -f "$BIN_PATH" ]] || ! verify_binary_installation "quiet"; then
                 handle_critical_error "Backhaul binary installation was not completed or is invalid. Exiting."
            else
                 log_message "INFO" "Binary found and verified after wizard exit. Proceeding."
            fi
        fi
    fi

    CURRENT_MENU_FUNCTION="main_menu_entry"
    MENU_STACK=("main_menu_entry")

    log_message "DEBUG" "Menu system initialized. Starting main loop for $CURRENT_MENU_FUNCTION"

    while [[ -n "$CURRENT_MENU_FUNCTION" ]]; do
        log_message "DEBUG" "Main loop - Current Menu: $CURRENT_MENU_FUNCTION, Stack: [${MENU_STACK[*]}]"

        local func_name_to_check
        # Extract the first word as the function name for 'type' command
        read -r func_name_to_check _ <<< "$CURRENT_MENU_FUNCTION"

        if type "$func_name_to_check" &>/dev/null; then
            eval "$CURRENT_MENU_FUNCTION" # Use eval to correctly parse function and its arguments
        else
            handle_critical_error "Menu function '$func_name_to_check' (from command string '$CURRENT_MENU_FUNCTION') not found. Stack: [${MENU_STACK[*]}]."
        fi

        if [[ ${#MENU_STACK[@]} -eq 0 ]]; then
            log_message "DEBUG" "Menu stack is empty. Exiting main loop."
            CURRENT_MENU_FUNCTION=""
        fi
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
