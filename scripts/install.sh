#!/usr/bin/env bash
set -e

install_pkg() {
  if command -v apt-get >/dev/null; then
    apt-get update -y && apt-get install -y "$@"
  elif command -v dnf >/dev/null; then
    dnf install -y "$@"
  elif command -v yum >/dev/null; then
    yum install -y "$@"
  elif command -v pacman >/dev/null; then
    pacman -Sy --noconfirm "$@"
  elif command -v zypper >/dev/null; then
    zypper --non-interactive install "$@"
  else
    return 1
  fi
}

ensure_tool() {
  local bin="$1" pkg="$2"
  if ! command -v "$bin" >/dev/null; then
    echo "Installing missing dependency: $bin"
    install_pkg "$pkg" || { echo "Failed to install $bin" >&2; exit 1; }
  fi
}

ensure_go() {
  if ! command -v go >/dev/null; then
    echo "Go compiler is required. Installing..."
    if command -v apt-get >/dev/null; then
      install_pkg golang-go
    else
      install_pkg go || install_pkg golang
    fi
  fi
}

ensure_git() {
  ensure_tool git git
}

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root" >&2
  exit 1
fi

ARCH=$(uname -m)
OS=$(uname -s)
if [[ $OS != "Linux" ]]; then
  echo "Only Linux is supported." >&2
  exit 1
fi

ensure_tool curl curl
ensure_tool tar tar
command -v systemctl >/dev/null || { echo "systemctl not found. Please install systemd." >&2; exit 1; }

echo "Detected architecture: $ARCH"

echo "Select binary source:"
echo "1) Build from source"
echo "2) Use existing local binary"
echo "3) Download .tar.gz from URL"
read -rp "Choice [1-3]: " CHOICE

tmpdir=$(mktemp -d)
BIN=""
case $CHOICE in
 1)
   ensure_git
   ensure_go
   git clone https://github.com/MehdiBazyar99/Backhaul "$tmpdir/src"
   cd "$tmpdir/src"
   go build -o backhaul
   BIN="$PWD/backhaul"
   ;;
 2)
   read -rp "Path to existing backhaul binary: " BIN
   if [[ ! -x $BIN ]]; then
     echo "Binary not executable: $BIN" >&2
     exit 1
   fi
   ;;
 3)
   read -rp "URL to .tar.gz archive: " URL
   curl -L "$URL" -o "$tmpdir/backhaul.tar.gz"
   tar -xf "$tmpdir/backhaul.tar.gz" -C "$tmpdir"
   BIN=$(find "$tmpdir" -type f -name backhaul | head -n1)
   if [[ -z $BIN ]]; then
     echo "Unable to locate backhaul binary in archive" >&2
     exit 1
   fi
   ;;
 *)
   echo "Invalid choice" >&2
   exit 1
   ;;
esac

install -m 755 "$BIN" /usr/local/bin/backhaul
BASE_URL="https://raw.githubusercontent.com/MehdiBazyar99/Backhaul/main/scripts"
curl -Ls "$BASE_URL/backhaul-manager.sh" -o /usr/local/bin/backhaul-manager.sh
curl -Ls "$BASE_URL/helpers.sh" -o /usr/local/bin/backhaul-helpers.sh
curl -Ls "$BASE_URL/generate-tls.sh" -o /usr/local/bin/generate-backhaul-tls.sh
curl -Ls "$BASE_URL/cron-restart-check.sh" -o /usr/local/bin/cron-restart-check.sh
chmod +x /usr/local/bin/backhaul-manager.sh /usr/local/bin/backhaul-helpers.sh /usr/local/bin/generate-backhaul-tls.sh /usr/local/bin/cron-restart-check.sh

mkdir -p /etc/backhaul/backup
if [[ ! -f /etc/backhaul/config.toml ]]; then
  read -rp "Run as (s)erver, (c)lient or (b)oth? [s/c/b]: " mode
  mode=${mode:-s}
  PUBIP=$(curl -s https://ipinfo.io/ip || echo "0.0.0.0")
  read -rp "Bind port [3080]: " port
  port=${port:-3080}
  read -rp "Shared token [backhaul]: " token
  token=${token:-backhaul}
  read -rp "Transport [tcp]: " trans
  trans=${trans:-tcp}
  read -rp "Web UI port (0 to disable) [0]: " wport
  wport=${wport:-0}
  case $mode in
    s|S)
      cat >/etc/backhaul/config.toml <<EOF
[server]
bind_addr = "0.0.0.0:$port"
transport = "$trans"
token = "$token"
web_port = $wport

[client]
#remote_addr = "${PUBIP}:$port"
transport = "$trans"
token = "$token"
EOF
      ;;
    c|C)
      read -rp "Server address [${PUBIP}:$port]: " srv
      srv=${srv:-${PUBIP}:$port}
      cat >/etc/backhaul/config.toml <<EOF
[client]
remote_addr = "$srv"
transport = "$trans"
token = "$token"

[server]
#bind_addr = "0.0.0.0:$port"
transport = "$trans"
token = "$token"
web_port = $wport
EOF
      ;;
    *)
      read -rp "Server address for client section [${PUBIP}:$port]: " srv
      srv=${srv:-${PUBIP}:$port}
      cat >/etc/backhaul/config.toml <<EOF
[server]
bind_addr = "0.0.0.0:$port"
transport = "$trans"
token = "$token"
web_port = $wport

[client]
remote_addr = "$srv"
transport = "$trans"
token = "$token"
EOF
      ;;
  esac
else
  source /usr/local/bin/backhaul-helpers.sh
  apply_defaults /etc/backhaul/config.toml
fi

read -rp "Edit configuration before enabling the service? [y/N]: " editcfg
if [[ $editcfg =~ [Yy] ]]; then
  ${EDITOR:-nano} /etc/backhaul/config.toml
fi

cat <<'SERVICE' >/etc/systemd/system/backhaul.service
[Unit]
Description=Backhaul Reverse Tunnel
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/backhaul -c /etc/backhaul/config.toml
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable --now backhaul.service

read -rp "Configure firewall rules for the bind port? [y/N]: " ans
if [[ $ans =~ [Yy] ]]; then
  PORT=$(grep -oP 'bind_addr\s*=\s*".*:\K[0-9]+' /etc/backhaul/config.toml)
  if command -v ufw >/dev/null; then
    ufw allow "$PORT"
  elif command -v firewall-cmd >/dev/null; then
    firewall-cmd --add-port=${PORT}/tcp --permanent
    firewall-cmd --reload
  else
    iptables -I INPUT -p tcp --dport "$PORT" -j ACCEPT
  fi
fi

IPINFO=$(curl -s https://ipinfo.io)
if command -v jq >/dev/null; then
  IP=$(echo "$IPINFO" | jq -r '.ip')
  CITY=$(echo "$IPINFO" | jq -r '.city')
  COUNTRY=$(echo "$IPINFO" | jq -r '.country')
else
  IP=$(echo "$IPINFO" | grep -oE '"ip":"[^"]+"' | cut -d'"' -f4)
  CITY=$(echo "$IPINFO" | grep -oE '"city":"[^"]*"' | cut -d'"' -f4)
  COUNTRY=$(echo "$IPINFO" | grep -oE '"country":"[^"]+"' | cut -d'"' -f4)
fi
WEBPORT=$(grep -oP 'web_port\s*=\s*\K[0-9]+' /etc/backhaul/config.toml)
[[ -z $WEBPORT || $WEBPORT -eq 0 ]] && WEB="disabled" || WEB="http://$IP:$WEBPORT"

echo "Installation complete"
echo "Public IP: $IP ($CITY, $COUNTRY)"
echo "Config: /etc/backhaul/config.toml"
echo "Logs: journalctl -u backhaul.service"
echo "Web UI: $WEB"

rm -rf "$tmpdir"
