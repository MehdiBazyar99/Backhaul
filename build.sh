#!/bin/bash
# build.sh - Concatenate all modules into EasyBackhaul.sh for distribution

OUTFILE="easybh.sh"
MODULES=(
  "modules/globals.sh"           # Global variables and constants
  "modules/helpers.sh"           # Core utility functions, validation, UI helpers (now includes dependency checks)
  "modules/backhaul_core.sh"     # Binary installation and core functionality
  "modules/config.sh"            # Configuration wizard and management
  "modules/validation.sh"        # Configuration validation functions
  "modules/ufw.sh"              # UFW firewall management
  "modules/systemd.sh"           # Systemd service management
  "modules/cron.sh"             # Cron job management
  "modules/restart_watcher.sh"   # Restart watcher functionality
  "modules/tunnel_mgmt.sh"       # Tunnel management and operations
  "modules/menu.sh"             # Main menu and navigation (now includes root check and calls dependency checks)
)

{
  echo "#!/bin/bash"
  echo "echo 'DEBUG: SCRIPT EXECUTION STARTED' >&2"
  # echo "exit 0" # Optional: to test if even this echo works before anything else
  echo "# ======================================================================"
  echo "# THIS FILE IS AUTO-GENERATED. DO NOT EDIT DIRECTLY."
  echo "# Edit the files in ./modules/ and run ./build.sh to regenerate."
  echo "# ======================================================================"
  echo "# Build order ensures proper function dependencies:"
  echo "# 1. globals.sh - Global variables"
  echo "# 2. helpers.sh - Core utilities, validation, dependency checks"
  echo "# 3. backhaul_core.sh - Binary installation"
  echo "# 4. config.sh - Configuration wizard"
  echo "# 5. validation.sh - Config validation"
  echo "# 6. ufw.sh - Firewall management"
  echo "# 7. systemd.sh - Service management"
  echo "# 8. cron.sh - Cron job management"
  echo "# 9. restart_watcher.sh - Restart watcher"
  echo "# 10. tunnel_mgmt.sh - Tunnel operations"
  echo "# 11. menu.sh - Main interface, root check, initial calls"
  echo "# ======================================================================"
  for mod in "${MODULES[@]}"; do
    echo "# --- MODULE: $mod ---"
    cat "$mod"
    echo
  done
} > "$OUTFILE"

# Workaround: Update version string directly in the built file due to tool issues with helpers.sh
echo "Applying version update to $OUTFILE..."
sed -i 's/EasyBackhaul Management Menu (v13.0-beta)/EasyBackhaul Management Menu (v14.0-dev)/g' "$OUTFILE"

chmod +x "$OUTFILE"
echo "Build complete: $OUTFILE"
echo "Module order optimized for dependencies." 