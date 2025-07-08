# globals.sh
# Contains global variables, constants, and paths for EasyBackhaul

# --- Global Variables ---
# All global variables use UPPER_SNAKE_CASE for consistency
# Using /tmp for paths to ensure writability in restricted environments/sandboxes
CONFIG_DIR="/tmp/easybackhaul_config"
BACKUP_DIR="/tmp/easybackhaul_backups"
BIN_PATH="/tmp/easybackhaul_bin/easybackhaul_binary" # Renamed to avoid conflict
SERVICE_DIR="/etc/systemd/system" # Standard systemd directory
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
