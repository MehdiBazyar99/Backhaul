#!/usr/bin/env bash
set -e
BASE_DIR="$(dirname "$0")"
if [ -f "$BASE_DIR/helpers.sh" ]; then
  source "$BASE_DIR/helpers.sh"
else
  source /usr/local/bin/backhaul-helpers.sh
fi
SERVICE=backhaul.service
CONFIG=/etc/backhaul/config.toml
BIN=/usr/local/bin/backhaul

banner() {
  clear
  echo "==== Backhaul Manager ===="
  echo "IP: $(geo_banner)"
  if grep -q "^\[server\]" "$CONFIG"; then
    mode="server"
  else
    mode="client"
  fi
  port=$(grep -oP 'web_port\s*=\s*\K[0-9]+' "$CONFIG")
  [[ -z $port || $port -eq 0 ]] && wui="disabled" || wui="http://$(public_ip):$port"
  echo "Mode: $mode | Web UI: $wui"
  echo "==========================="
}

preset_menu() {
  echo "Choose transport preset:"
  echo "1) tcp"
  echo "2) wss"
  echo "3) wsmux"
  read -rp "Choice: " p
  case $p in
    1) sed -i 's/^transport =.*/transport = "tcp"/' "$CONFIG";;
    2) sed -i 's/^transport =.*/transport = "wss"/' "$CONFIG";;
    3) sed -i 's/^transport =.*/transport = "wsmux"/' "$CONFIG";;
  esac
}

config_wizard() {
  echo "=== Configuration Wizard ==="
  read -rp "Run as server? [y/N]: " srv
  if [[ $srv =~ [Yy] ]]; then
    read -rp "Bind address [0.0.0.0:3080]: " bind
    bind=${bind:-0.0.0.0:3080}
    set_config server bind_addr "$bind"
    set_config server transport "$(get_config client transport || tcp)"
  fi
  read -rp "Run as client? [y/N]: " cl
  if [[ $cl =~ [Yy] ]]; then
    defaddr="$(public_ip):3080"
    read -rp "Server address [$defaddr]: " raddr
    raddr=${raddr:-$defaddr}
    set_config client remote_addr "$raddr"
    set_config client transport "$(get_config server transport || tcp)"
  fi
  read -rp "Shared token [backhaul]: " token
  token=${token:-backhaul}
  set_config server token "$token"
  set_config client token "$token"
  read -rp "Transport [$(get_config server transport || tcp)]: " trans
  trans=${trans:-$(get_config server transport || tcp)}
  set_config server transport "$trans"
  set_config client transport "$trans"
  read -rp "Web UI port (0 to disable) [$(get_config server web_port || 0)]: " wp
  wp=${wp:-$(get_config server web_port || 0)}
  set_config server web_port "$wp"
  echo "Config updated"
}

safe_upgrade() {
  read -rp "New binary path or URL: " src
  tmp=$(mktemp -d)
  if [[ $src =~ ^https?:// ]]; then
    curl -L "$src" -o "$tmp/backhaul.tar.gz"
    tar -xf "$tmp/backhaul.tar.gz" -C "$tmp"
    src=$(find "$tmp" -type f -name backhaul | head -n1)
  fi
  if [[ ! -x $src ]]; then
    echo "Binary not found"; rm -rf "$tmp"; return
  fi
  backup_config "$CONFIG"
  cp "$BIN" "$BIN.bak"
  cp "$src" "$BIN.new"
  systemctl stop $SERVICE
  mv "$BIN.new" "$BIN"
  systemctl start $SERVICE
  if ! systemctl is-active --quiet $SERVICE; then
    echo "Upgrade failed, rolling back"
    mv "$BIN.bak" "$BIN"
    systemctl start $SERVICE
  else
    rm "$BIN.bak"
    echo "Upgrade successful"
  fi
  rm -rf "$tmp"
}

setup_watchdog() {
  local line="* * * * * /usr/local/bin/cron-restart-check.sh"
  (crontab -l 2>/dev/null | grep -v cron-restart-check.sh; echo "$line") | crontab -
  echo "Watchdog cronjob installed"
}

advanced_menu() {
  while true; do
    echo "--- Advanced ---"
    echo "1) Backup config"
    echo "2) Restore config"
    echo "3) Apply recommended defaults"
    echo "4) Configuration wizard"
    echo "5) Return"
    read -rp "Select: " a
    case $a in
      1) backup_config "$CONFIG" && echo "Backup created";;
      2)
        ls /etc/backhaul/backup/*.toml 2>/dev/null || { echo "No backups"; continue; }
        read -rp "Path to backup file: " f
        restore_config "$f" && echo "Restored from $f";;
      3) apply_defaults "$CONFIG" && echo "Defaults applied";;
      4) config_wizard;;
      5) break;;
      *) echo "Invalid";;
    esac
  done
}

while true; do
  banner
  echo "1) Status"
  echo "2) Start"
  echo "3) Stop"
  echo "4) Restart"
  echo "5) Logs"
  echo "6) Edit config"
  echo "7) Regenerate TLS"
  echo "8) Transport presets"
  echo "9) Safe upgrade"
  echo "10) Setup watchdog"
  echo "11) Advanced"
  echo "0) Exit"
  read -rp "Select: " opt
  case $opt in
    1) systemctl status $SERVICE;;
    2) systemctl start $SERVICE;;
    3) systemctl stop $SERVICE;;
    4) systemctl restart $SERVICE;;
    5) journalctl -u $SERVICE -e;;
    6) ${EDITOR:-nano} "$CONFIG";;
    7) if [ -f "$BASE_DIR/generate-tls.sh" ]; then
         "$BASE_DIR/generate-tls.sh"
       else
         /usr/local/bin/generate-backhaul-tls.sh
       fi;;
    8) preset_menu;;
    9) safe_upgrade;;
    10) setup_watchdog;;
    11) advanced_menu;;
    0) exit 0;;
    *) echo "Invalid";;
  esac
  read -rp "Press Enter to continue..." dummy
done
