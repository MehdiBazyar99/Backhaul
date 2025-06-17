#!/usr/bin/env bash
set -e

OUT_DIR=/etc/backhaul
mkdir -p "$OUT_DIR"
openssl req -x509 -nodes -newkey rsa:2048 -keyout "$OUT_DIR/server.key" \
  -out "$OUT_DIR/server.crt" -days 365 -subj "/CN=backhaul"

echo "TLS certificate generated at $OUT_DIR/server.crt"
