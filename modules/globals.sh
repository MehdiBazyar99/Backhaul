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
                printf "ERROR: [_globals_ensure_config_dir_for_secret] Failed to create parent directory: %s. Please check permissions.\n" "$parent_dir" >&2
                return 1
            fi
            # Set ownership to root:nogroup and permissions to 0750 for the parent directory
            # This allows members of 'nogroup' (like 'nobody') to traverse into /etc/easybackhaul
            chown root:nogroup "$parent_dir" || { printf "ERROR: Failed to chown %s\n" "$parent_dir"; return 1; }
            chmod 0750 "$parent_dir" || { printf "ERROR: Failed to chmod %s\n" "$parent_dir"; return 1; }
        fi

        mkdir -p "$CONFIG_DIR"
        if [[ $? -ne 0 ]]; then
            printf "ERROR: [_globals_ensure_config_dir_for_secret] Failed to create CONFIG_DIR: %s. Please check permissions.\n" "$CONFIG_DIR" >&2
            return 1
        fi
        # Set ownership to root:nogroup and permissions to 0770 for the configs directory
        # This allows 'nogroup' to read/write/execute (list files) in this directory.
        # Individual config files will be 'nobody:nogroup' and '640'.
        chown root:nogroup "$CONFIG_DIR" || { printf "ERROR: Failed to chown %s\n" "$CONFIG_DIR"; return 1; }
        chmod 0770 "$CONFIG_DIR" || { printf "ERROR: Failed to chmod %s\n" "$CONFIG_DIR"; return 1; }
        return 0
    fi

    # If directory already exists, ensure its permissions and ownership are correct.
    # This handles cases where the script might have run before with different settings.
    if [[ -d "$CONFIG_DIR" ]]; then
        # Ensure parent directory /etc/easybackhaul also has correct perms/owner
        local existing_parent_dir
        existing_parent_dir=$(dirname "$CONFIG_DIR")
        if [[ -d "$existing_parent_dir" ]]; then
            if [[ "$(stat -c "%U:%G" "$existing_parent_dir")" != "root:nogroup" ]]; then
                chown root:nogroup "$existing_parent_dir" || printf "WARNING: Failed to chown %s to root:nogroup\n" "$existing_parent_dir" >&2
            fi
            if [[ "$(stat -c "%a" "$existing_parent_dir")" != "750" ]]; then
                 # Check if current perms are more open, e.g. 755, if so, leave them. Otherwise set to 750.
                current_perms_parent=$(stat -c "%a" "$existing_parent_dir")
                if [[ "$current_perms_parent" -lt "750" && "$current_perms_parent" != "750" ]]; then # if less than 0750, set it
                    chmod 0750 "$existing_parent_dir" || printf "WARNING: Failed to chmod %s to 0750\n" "$existing_parent_dir" >&2
                fi
            fi
        fi

        # Check and set CONFIG_DIR permissions
        if [[ "$(stat -c "%U:%G" "$CONFIG_DIR")" != "root:nogroup" ]]; then
            chown root:nogroup "$CONFIG_DIR" || {
                printf "WARNING: [_globals_ensure_config_dir_for_secret] Failed to chown existing CONFIG_DIR %s to root:nogroup.\n" "$CONFIG_DIR" >&2
            }
        fi
        # Current permissions for CONFIG_DIR should be 0770.
        # If they are more permissive (e.g., 775, 777), that's okay. If less, set to 0770.
        current_perms_config_dir=$(stat -c "%a" "$CONFIG_DIR")
        if [[ "$current_perms_config_dir" -lt "770" && "$current_perms_config_dir" != "770" ]]; then # if less than 0770, set it
            chmod 0770 "$CONFIG_DIR" || {
                printf "WARNING: [_globals_ensure_config_dir_for_secret] Failed to ensure 0770 permissions on existing CONFIG_DIR: %s.\n" "$CONFIG_DIR" >&2
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
            RESTART_WATCHER_SECRET_VALUE=$(<"$GLOBAL_WATCHER_SECRET_FILE")
        fi
    fi
fi

# 3. If still no secret (neither from env nor file), generate, save, and set it.
if [[ -z "$RESTART_WATCHER_SECRET_VALUE" ]]; then
    if _globals_ensure_config_dir_for_secret; then # Ensure dir exists before writing
        # Use direct command as helpers.sh (where generate_random_secret is) isn't sourced yet.
        GENERATED_SECRET_FALLBACK=$(openssl rand -hex 32 2>/dev/null || tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 64)
        if [[ -n "$GENERATED_SECRET_FALLBACK" ]]; then
            printf "%s" "$GENERATED_SECRET_FALLBACK" > "$GLOBAL_WATCHER_SECRET_FILE"
            if [[ $? -eq 0 ]]; then # Check if write was successful
                chmod 600 "$GLOBAL_WATCHER_SECRET_FILE"
                RESTART_WATCHER_SECRET_VALUE="$GENERATED_SECRET_FALLBACK"
            else
                # Failed to write to file, don't use the generated secret if it couldn't be persisted.
                printf "ERROR: [_globals_ensure_config_dir_for_secret] Failed to write to %s. Watcher secret not set.\n" "$GLOBAL_WATCHER_SECRET_FILE" >&2
                RESTART_WATCHER_SECRET_VALUE="" # Ensure it remains empty
            fi
        else
            printf "WARNING: [_globals_ensure_config_dir_for_secret] Failed to generate random string for RESTART_WATCHER_SECRET.\n" >&2
        fi
    else
         printf "WARNING: [_globals_ensure_config_dir_for_secret] CONFIG_DIR '%s' not usable. Cannot generate/store global watcher secret.\n" "$CONFIG_DIR" >&2
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
