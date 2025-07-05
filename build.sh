#!/bin/bash
# build.sh - Concatenate all modules into EasyBackhaul.sh for distribution

OUTFILE="easybackhaul.sh"
MODULES=(
  "modules/globals.sh"           # Global variables and constants
  "modules/helpers.sh"           # Core utility functions, validation, UI helpers
  "modules/prereqs.sh"           # System requirements and dependency checks
  "modules/backhaul_core.sh"     # Binary installation and core functionality
  "modules/config.sh"            # Configuration wizard and management
  "modules/validation.sh"        # Configuration validation functions
  "modules/ufw.sh"              # UFW firewall management
  "modules/systemd.sh"           # Systemd service management
  "modules/cron.sh"             # Cron job management (needed by tunnel_mgmt.sh)
  "modules/tunnel_mgmt.sh"       # Tunnel management and operations
  "modules/restart_watcher.sh"   # Restart watcher functionality
  "modules/menu.sh"             # Main menu and navigation
)

{
  echo "#!/bin/bash"
  echo "# ======================================================================"
  echo "# THIS FILE IS AUTO-GENERATED. DO NOT EDIT DIRECTLY."
  echo "# Edit the files in ./modules/ and run ./build.sh to regenerate."
  echo "# ======================================================================"
  echo "# Build order ensures proper function dependencies:"
  echo "# 1. globals.sh - Global variables"
  echo "# 2. helpers.sh - Core utilities and validation"
  echo "# 3. prereqs.sh - System checks"
  echo "# 4. backhaul_core.sh - Binary installation"
  echo "# 5. config.sh - Configuration wizard"
  echo "# 6. validation.sh - Config validation"
  echo "# 7. ufw.sh - Firewall management"
  echo "# 8. systemd.sh - Service management"
  echo "# 9. cron.sh - Cron job management"
  echo "# 10. tunnel_mgmt.sh - Tunnel operations"
  echo "# 11. restart_watcher.sh - Restart watcher"
  echo "# 12. menu.sh - Main interface"
  echo "# ======================================================================"
  for mod in "${MODULES[@]}"; do
    echo "# --- MODULE: $mod ---"
    cat "$mod"
    echo
  done
} > "$OUTFILE"

chmod +x "$OUTFILE"
echo "Build complete: $OUTFILE"
echo "Module order optimized for dependencies." 