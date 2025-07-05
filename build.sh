#!/bin/bash
# build.sh - Concatenate all modules into EasyBackhaul.sh for distribution

OUTFILE="easybackhaul.sh"
MODULES=(
  "modules/globals.sh"
  "modules/helpers.sh"
  "modules/prereqs.sh"
  "modules/backhaul_core.sh"
  "modules/config.sh"
  "modules/validation.sh"
  "modules/ufw.sh"
  "modules/systemd.sh"
  "modules/tunnel_mgmt.sh"
  "modules/restart_watcher.sh"
  "modules/cron.sh"
  "modules/menu.sh"
)

{
  echo "#!/bin/bash"
  echo "# ======================================================================"
  echo "# THIS FILE IS AUTO-GENERATED. DO NOT EDIT DIRECTLY."
  echo "# Edit the files in ./modules/ and run ./build.sh to regenerate."
  echo "# ======================================================================"
  for mod in "${MODULES[@]}"; do
    echo "# --- MODULE: $mod ---"
    cat "$mod"
    echo
  done
} > "$OUTFILE"

chmod +x "$OUTFILE"
echo "Build complete: $OUTFILE" 