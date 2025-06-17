#!/usr/bin/env bash
SERVICE=backhaul.service
if ! systemctl is-active --quiet $SERVICE; then
  systemctl restart $SERVICE
fi
