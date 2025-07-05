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

