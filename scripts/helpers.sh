#!/usr/bin/env bash

public_ip() {
  curl -s https://ipinfo.io/ip
}

geo_banner() {
  local data=$(curl -s https://ipinfo.io)
  if command -v jq >/dev/null; then
    local ip=$(echo "$data" | jq -r '.ip')
    local city=$(echo "$data" | jq -r '.city')
    local country=$(echo "$data" | jq -r '.country')
    echo "$ip ($city, $country)"
  else
    local ip=$(echo "$data" | grep -oE '"ip":"[^"]+"' | cut -d'"' -f4)
    echo "$ip"
  fi
}

backup_config() {
  local cfg="${1:-/etc/backhaul/config.toml}"
  local ts=$(date +%F_%H-%M-%S)
  cp "$cfg" "/etc/backhaul/backup/config_$ts.toml"
}

restore_config() {
  local file="$1"
  [[ -f $file ]] || { echo "Backup not found" >&2; return 1; }
  cp "$file" /etc/backhaul/config.toml
}

apply_defaults() {
  local cfg="${1:-/etc/backhaul/config.toml}"
  local ip=$(public_ip || echo "0.0.0.0")
  grep -q "\[server\]" "$cfg" || echo "[server]" >>"$cfg"
  grep -q "bind_addr" "$cfg" || printf 'bind_addr = "0.0.0.0:3080"\n' >>"$cfg"
  grep -q "transport" "$cfg" || printf 'transport = "tcp"\n' >>"$cfg"
  grep -q "token" "$cfg" || printf 'token = "backhaul"\n' >>"$cfg"
  grep -q "\[client\]" "$cfg" || echo -e "\n[client]" >>"$cfg"
  if ! grep -q "remote_addr" "$cfg"; then
    printf 'remote_addr = "%s:3080"\n' "$ip" >>"$cfg"
    printf 'transport = "tcp"\n' >>"$cfg"
    printf 'token = "backhaul"\n' >>"$cfg"
  fi
}

get_config() {
  local section=$1 key=$2 file=${3:-/etc/backhaul/config.toml}
  awk -v section="$section" -v key="$key" '
    /^\[/{cur=substr($0,2,length($0)-2)}
    cur==section && $1==key {gsub(/"/,"",$3); print $3; exit}
  ' "$file"
}

set_config() {
  local section=$1 key=$2 value=$3 file=${4:-/etc/backhaul/config.toml}
  grep -q "\[$section\]" "$file" || echo "[$section]" >>"$file"
  if grep -q "^$key" <(grep -A0 -n "\[$section\]" -n "$file" | tail -n +2); then
    sed -i "/\[$section\]/,/^\[/ s|^$key =.*|$key = \"$value\"|" "$file"
  else
    sed -i "/\[$section\]/a$key = \"$value\"" "$file"
  fi
}
