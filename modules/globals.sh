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

# --- Enhanced Logging System ---
LOG_DIR="/var/log/backhaul"
LOG_LEVEL="INFO"  # DEBUG, INFO, WARN, ERROR
LOG_MAX_FILES=5
LOG_FORMAT="json"  # json, text

# --- Health Monitoring ---
HEALTH_LOG_FILE="$LOG_DIR/health.log"
PERFORMANCE_LOG_FILE="$LOG_DIR/performance.log"

# --- Performance Settings ---
MAX_CONCURRENT_OPERATIONS=3

# --- Advanced Error Recovery ---
MAX_RESTART_ATTEMPTS=3
RESTART_COOLDOWN=10  # seconds

# --- Resource Management ---
PROCESS_PRIORITY=0  # nice value (-20 to 19)

# --- Configuration Validation ---
CONFIG_BACKUP_ON_CHANGE=true

# --- Security Enhancements ---
FILE_PERMISSIONS_STRICT=true
TEMP_FILE_SECURE_DELETE=true

