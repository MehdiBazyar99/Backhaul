#!/bin/bash
# restart_watcher.sh - Per-tunnel coordinated restart watcher for EasyBackhaul
# This script is intended to be sourced or built into the main script, or run as a systemd service.

# Required environment/config variables (set by main script or systemd):
#   SERVICE_NAME         - systemd service name (e.g. backhaul-client-xxx.service)
#   LOG_PATTERN          - regex for error detection (e.g. 'ERROR|FATAL')
#   REMOTE_HOST          - IP or hostname of the remote side
#   REMOTE_PORT          - netcat port on remote (default: 45678)
#   RESTART_SECRET       - shared secret for authentication
#   RESTART_DELAY_LOCAL  - seconds to wait before local restart (default: 10)
#   RESTART_DELAY_REMOTE - seconds to wait before remote restart (default: 10)
#   MAX_RETRIES          - max restart request attempts (default: 3)
#   ROLE                 - 'client' or 'server' (for logging)
#   LISTEN_PORT          - local port to listen for restart requests (default: 45678)

# --- Defaults ---
RESTART_DELAY_LOCAL=${RESTART_DELAY_LOCAL:-10}
RESTART_DELAY_REMOTE=${RESTART_DELAY_REMOTE:-10}
MAX_RETRIES=${MAX_RETRIES:-3}
LISTEN_PORT=${LISTEN_PORT:-45679}
REMOTE_PORT=${REMOTE_PORT:-45680}
RESTART_SECRET=${RESTART_SECRET:-$RESTART_WATCHER_SECRET}
ROLE=${ROLE:-unknown}

# --- Helper: Log ---
log() { echo "[RestartWatcher][$ROLE][$(date +'%F %T')] $1"; }

# --- Main Entrypoint ---
restart_watcher_main() {
    # Set defaults if not provided
    RESTART_DELAY_LOCAL=${RESTART_DELAY_LOCAL:-10}
    RESTART_DELAY_REMOTE=${RESTART_DELAY_REMOTE:-10}
    MAX_RETRIES=${MAX_RETRIES:-3}
    LISTEN_PORT=${LISTEN_PORT:-45679}
    REMOTE_PORT=${REMOTE_PORT:-45680}
    RESTART_SECRET=${RESTART_SECRET:-$RESTART_WATCHER_SECRET}
    ROLE=${ROLE:-unknown}
    
    # Validate required environment variables
    if [[ -z "$SERVICE_NAME" ]]; then
        log "ERROR: SERVICE_NAME environment variable is required"
        exit 1
    fi
    
    if [[ -z "$REMOTE_HOST" || "$REMOTE_HOST" == "0.0.0.0" ]]; then
        log "ERROR: REMOTE_HOST environment variable is required and cannot be 0.0.0.0"
        exit 1
    fi
    
    log "Starting restart watcher for service: $SERVICE_NAME"
    log "Remote host: $REMOTE_HOST:$REMOTE_PORT"
    log "Listen port: $LISTEN_PORT"
    log "Role: $ROLE"
    
    # Start listener in background
    restart_listener &
    LISTENER_PID=$!
    
    # Set up signal handlers for clean shutdown
    trap 'log "Received shutdown signal. Cleaning up..."; kill $LISTENER_PID 2>/dev/null; exit 0' SIGTERM SIGINT
    
    # Start log monitor
    monitor_and_restart
    
    # Cleanup
    kill $LISTENER_PID 2>/dev/null
}

# --- Function: Listen for restart requests (in background) ---
restart_listener() {
    while true; do
        # Listen for a single line (timeout 60s to allow clean exit)
        local msg
        msg=$(nc -l -p "$LISTEN_PORT" -w 60 2>/dev/null)
        if [[ "$msg" =~ ^RESTART_REQUEST:(.+):(.+)$ ]]; then
            local secret=${BASH_REMATCH[1]}
            local sender_role=${BASH_REMATCH[2]}
            if [[ "$secret" == "$RESTART_SECRET" ]]; then
                log "Received RESTART_REQUEST from $sender_role. Sending ACK and scheduling restart."
                # Send ACK back to sender
                echo "RESTART_ACK:$RESTART_SECRET:$ROLE" | nc "$REMOTE_HOST" "$REMOTE_PORT" -w 2
                # Schedule restart after delay
                (sleep "$RESTART_DELAY_REMOTE"; systemctl restart "$SERVICE_NAME"; log "Service restarted (listener)") &
            else
                log "Received RESTART_REQUEST with invalid secret. Ignoring."
            fi
        elif [[ "$msg" =~ ^RESTART_ACK:(.+):(.+)$ ]]; then
            # This is an ACK for a request we sent
            local secret=${BASH_REMATCH[1]}
            local ack_role=${BASH_REMATCH[2]}
            if [[ "$secret" == "$RESTART_SECRET" ]]; then
                log "Received RESTART_ACK from $ack_role."
                # Touch a file to signal ACK received
                touch "/tmp/restart_ack_${SERVICE_NAME}"
            fi
        fi
    done
}

# --- Function: Monitor logs and trigger coordinated restart ---
monitor_and_restart() {
    log "Starting log monitor for $SERVICE_NAME (pattern: $LOG_PATTERN)"
    journalctl -u "$SERVICE_NAME" -f --no-pager | while read -r line; do
        if [[ "$line" =~ $LOG_PATTERN ]]; then
            log "Error detected in logs. Initiating coordinated restart."
            # Try to send restart request and wait for ACK
            local attempt=1
            while (( attempt <= MAX_RETRIES )); do
                log "Sending RESTART_REQUEST to $REMOTE_HOST:$REMOTE_PORT (attempt $attempt)"
                echo "RESTART_REQUEST:$RESTART_SECRET:$ROLE" | nc "$REMOTE_HOST" "$REMOTE_PORT" -w 2
                # Wait for ACK (up to 10s)
                for i in {1..10}; do
                    if [ -f "/tmp/restart_ack_${SERVICE_NAME}" ]; then
                        rm -f "/tmp/restart_ack_${SERVICE_NAME}"
                        log "ACK received. Scheduling local restart in $RESTART_DELAY_LOCAL seconds."
                        sleep "$RESTART_DELAY_LOCAL"
                        systemctl restart "$SERVICE_NAME"
                        log "Service restarted (initiator)"
                        return
                    fi
                    sleep 1
                done
                log "No ACK received. Retrying..."
                ((attempt++))
            done
            log "Failed to coordinate restart after $MAX_RETRIES attempts. Local restart only."
            sleep "$RESTART_DELAY_LOCAL"
            systemctl restart "$SERVICE_NAME"
            log "Service restarted (local only)"
            return
        fi
    done
} 