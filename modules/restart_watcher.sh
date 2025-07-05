#!/bin/bash
# restart_watcher.sh - Per-tunnel coordinated restart watcher for EasyBackhaul
# This script is intended to be sourced or built into the main script, or run as a systemd service.

# WARNING: This script requires a version of netcat (nc) that supports '-l -p'.
#          Some distributions (e.g., Debian/Ubuntu) may require installing netcat-openbsd.

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

# --- Watcher Management Functions ---

# Enable watcher for a tunnel
enable_watcher() {
    local service="$1"
    local suffix="$2"
    local config_file="$3"
    local role remote_host local_ip

    clear
    print_info "=== Watcher Setup ==="
    echo
    print_info "The watcher coordinates restarts between both sides."
    echo
    
    # Determine role for better guidance
    if grep -q '^\[server\]' "$config_file"; then
        role="server"
        print_info "This is a SERVER tunnel"
        echo
        read -p "Enter client IP address: " remote_host
        if [[ -z "$remote_host" ]]; then
            print_error "Client IP is required."
            press_any_key
            return
        fi
    else
        role="client"
        print_info "This is a CLIENT tunnel"
        # For client, remote host is the server IP from tunnel config
        remote_host=$(grep '^remote_addr' "$config_file" | cut -d'"' -f2 | cut -d':' -f1)
        if [[ -z "$remote_host" ]]; then
            print_error "Could not find server IP in tunnel config."
            press_any_key
            return
        fi
        print_info "Server IP: $remote_host"
        
        # Get client's own IPv4 IP for server configuration
        local_ip=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 ipinfo.io/ip 2>/dev/null || echo "unknown")
        if [[ "$local_ip" != "unknown" ]]; then
            echo
            print_info "Your IPv4 address: $local_ip"
            print_info "Use this IP when configuring the server side watcher."
        fi
    fi

    # Simple port setup - server uses higher ports, client uses lower ports
    echo
    local listen_port remote_port
    if [[ "$role" == "server" ]]; then
        listen_port=45690  # Server receives on higher port
        remote_port=45680  # Server sends to lower port
    else
        listen_port=45680  # Client receives on lower port  
        remote_port=45690  # Client sends to higher port
    fi
    
    print_info "Checking port availability..."
    
    # Check if listen port is available using unified port checking
    if ! check_port_availability "$listen_port"; then
        read -p "Enter different receive port: " listen_port
        if [[ -z "$listen_port" ]]; then
            print_error "Port is required."
            press_any_key
            return 1
        fi
        # Re-check the new port
        if ! check_port_availability "$listen_port"; then
            print_error "Selected port is also in use."
            press_any_key
            return 1
        fi
    fi
    
    # Check if remote port is available (for local testing)
    if ! check_port_availability "$remote_port"; then
        print_warning "Port $remote_port is in use locally. This might cause issues."
    fi
    
    # Check for conflicts with main tunnel ports
    local tunnel_port
    tunnel_port=$(grep '^bind_addr\|^remote_addr' "$config_file" | cut -d'"' -f2 | cut -d':' -f2 | head -1)
    if [[ -n "$tunnel_port" ]]; then
        if [[ "$listen_port" == "$tunnel_port" || "$remote_port" == "$tunnel_port" ]]; then
            print_warning "Watcher port ($listen_port or $remote_port) conflicts with tunnel port ($tunnel_port)."
            print_info "This is not recommended but will work."
        fi
    fi
    
    # Check for conflicts with other watchers
    for existing_pid in /tmp/backhaul-watcher-*.pid; do
        if [[ -f "$existing_pid" ]]; then
            local existing_suffix=$(basename "$existing_pid" .pid | sed 's/backhaul-watcher-//')
            if [[ "$existing_suffix" != "$suffix" ]]; then
                local existing_config="$CONFIG_DIR/config-${existing_suffix}.toml"
                if [[ -f "$existing_config" ]]; then
                    local existing_listen=$(grep '^restart_watcher_listen_port' "$existing_config" | awk -F'=' '{print $2}' | tr -d ' "')
                    local existing_remote=$(grep '^restart_watcher_remote_port' "$existing_config" | awk -F'=' '{print $2}' | tr -d ' "')
                    if [[ "$listen_port" == "$existing_listen" || "$listen_port" == "$existing_remote" || "$remote_port" == "$existing_listen" || "$remote_port" == "$existing_remote" ]]; then
                        print_warning "Port conflict detected with existing watcher for tunnel: $existing_suffix"
                        print_info "This might cause communication issues between watchers."
                    fi
                fi
            fi
        fi
    done
    
    print_success "Ports are available."

    # Handle watcher secret - must be the same on both sides
    local secret
    if [[ "$role" == "server" ]]; then
        # Server generates or uses existing secret
        if [[ -f "$CONFIG_DIR/watcher_secret" ]]; then
            secret=$(cat "$CONFIG_DIR/watcher_secret")
            print_info "Using existing watcher secret"
        else
            # Generate a new secret for this tunnel pair
            secret=$(openssl rand -hex 16 2>/dev/null || tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32)
            echo "$secret" > "$CONFIG_DIR/watcher_secret"
            chmod 600 "$CONFIG_DIR/watcher_secret"
            print_info "Generated new watcher secret"
        fi
        print_info "Secret: $secret"
        print_info "Share this secret with the client side."
    else
        # Client needs to enter the secret from server
        echo
        print_info "You need the watcher secret from the server side."
        print_info "Ask the server administrator for the watcher secret."
        echo
        while true; do
            read -p "Enter the watcher secret from server: " secret
            if [[ -n "$secret" ]]; then
                # Validate secret format (should be hex or alphanumeric)
                if [[ "$secret" =~ ^[A-Za-z0-9]+$ ]]; then
                    break
                else
                    print_warning "Secret should contain only letters and numbers"
                fi
            else
                print_warning "Secret cannot be empty"
            fi
        done
    fi

    # Add UFW rule for listen port
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
        print_info "--> UFW is active. Adding rule for port ${listen_port}/tcp..."
        if ufw allow ${listen_port}/tcp >/dev/null 2>&1; then
            print_success "UFW rule added successfully."
        else
            print_warning "Failed to add UFW rule. You may need to add it manually."
        fi
    fi

    # Create watcher configuration file
    local watcher_config="/tmp/backhaul-watcher-${suffix}.conf"
    cat > "$watcher_config" <<EOL
SERVICE_NAME="$service"
REMOTE_HOST="$remote_host"
REMOTE_PORT="$remote_port"
LISTEN_PORT="$listen_port"
RESTART_SECRET="$secret"
ROLE="$role"
LOG_PATTERN="ERROR|FATAL|connection.*failed|timeout"
RESTART_DELAY_LOCAL=10
RESTART_DELAY_REMOTE=10
MAX_RETRIES=3
EOL

    # Create simple launcher script that uses the centralized restart watcher
    local watcher_script="/tmp/backhaul-watcher-${suffix}.sh"
    cat > "$watcher_script" <<EOL
#!/bin/bash
# Watcher launcher for $service
# This script loads configuration and launches the centralized restart watcher

# Load configuration
source "/tmp/backhaul-watcher-${suffix}.conf"

# Set up signal handlers for clean shutdown
trap 'echo "[Watcher][\$ROLE][\$(date +"%F %T")] Received shutdown signal. Cleaning up..."; exit 0' SIGTERM SIGINT

# Launch the centralized restart watcher
restart_watcher_main
EOL

    chmod +x "$watcher_script"
    
    # Start the watcher in background
    # Log rotation: keep last 5 logs
    for i in 5 4 3 2 1; do
        if [[ -f "/tmp/backhaul-watcher-${suffix}.log.$i" ]]; then
            mv "/tmp/backhaul-watcher-${suffix}.log.$i" "/tmp/backhaul-watcher-${suffix}.log.$((i+1))"
        fi
    done
    if [[ -f "/tmp/backhaul-watcher-${suffix}.log" ]]; then
        mv "/tmp/backhaul-watcher-${suffix}.log" "/tmp/backhaul-watcher-${suffix}.log.1"
    fi
    nohup "$watcher_script" > "/tmp/backhaul-watcher-${suffix}.log" 2>&1 &
    local watcher_pid=$!
    
    # Wait a moment to ensure process started
    sleep 1
    
    # Verify process is still running before saving PID
    if kill -0 "$watcher_pid" 2>/dev/null; then
        # Save PID for later management
        echo "$watcher_pid" > "/tmp/backhaul-watcher-${suffix}.pid"
    else
        print_error "Watcher process failed to start properly"
        press_any_key
        return 1
    fi
    
    # Update config file using unified functions
    update_config_value "$config_file" "restart_watcher_enabled" "y"
    update_config_numeric "$config_file" "restart_watcher_listen_port" "$listen_port"
    update_config_numeric "$config_file" "restart_watcher_remote_port" "$remote_port"
    update_config_value "$config_file" "restart_watcher_secret" "$secret"
    update_config_numeric "$config_file" "restart_watcher_pid" "$watcher_pid"
    
    print_success "Watcher enabled and started."
    echo
    print_info "--- Configuration ---"
    echo "Secret: $secret"
    echo "Receive port: $listen_port"
    echo "Send port: $remote_port"
    echo
    if [[ "$role" == "server" ]]; then
        print_info "IMPORTANT: Share this secret with the client side:"
        print_info "Secret: $secret"
        echo
        print_info "The client will need this secret to enable their watcher."
    elif [[ "$role" == "client" && "$local_ip" != "unknown" ]]; then
        print_info "Use your IPv4 address ($local_ip) when configuring the server side."
        print_info "Make sure the server uses the same secret: $secret"
    fi
    press_any_key
}

# Disable watcher for a tunnel
disable_watcher() {
    local service="$1"
    local suffix="$2"
    local config_file="$3"
    
    clear
    print_info "=== Disable Watcher ==="
    echo
    
    local pid_file="/tmp/backhaul-watcher-${suffix}.pid"
    local log_file="/tmp/backhaul-watcher-${suffix}.log"
    local config_file_watcher="/tmp/backhaul-watcher-${suffix}.conf"
    local script_file="/tmp/backhaul-watcher-${suffix}.sh"
    
    if [[ ! -f "$pid_file" ]]; then
        print_warning "Watcher is not running for this tunnel."
        press_any_key
        return
    fi
    
    local pid=$(cat "$pid_file" 2>/dev/null)
    
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        print_info "Stopping watcher process (PID: $pid)..."
        kill -TERM "$pid" 2>/dev/null
        
        # Wait for graceful shutdown
        local count=0
        while kill -0 "$pid" 2>/dev/null && [[ $count -lt 10 ]]; do
            sleep 1
            ((count++))
        done
        
        # Force kill if still running
        if kill -0 "$pid" 2>/dev/null; then
            print_warning "Force killing watcher process..."
            kill -KILL "$pid" 2>/dev/null
        fi
        
        print_success "Watcher stopped successfully."
    else
        print_warning "Watcher process not found or already stopped."
    fi
    
    # Clean up files
    rm -f "$pid_file" "$config_file_watcher" "$script_file"
    
    # Update config file
    update_config_value "$config_file" "restart_watcher_enabled" "n"
    update_config_numeric "$config_file" "restart_watcher_pid" "0"
    
    print_success "Watcher disabled and cleaned up."
    echo
    print_info "Log file preserved: $log_file"
    press_any_key
}

# Edit watcher configuration
edit_watcher_config() {
    local service="$1"
    local suffix="$2"
    local config_file="$3"
    
    clear
    print_info "=== Edit Watcher Configuration ==="
    echo
    
    local watcher_config="/tmp/backhaul-watcher-${suffix}.conf"
    
    if [[ ! -f "$watcher_config" ]]; then
        print_error "Watcher configuration not found. Enable watcher first."
        press_any_key
        return
    fi
    
    # Load current configuration
    source "$watcher_config"
    
    echo "Current configuration:"
    echo "  Log pattern: $LOG_PATTERN"
    echo "  Local restart delay: $RESTART_DELAY_LOCAL seconds"
    echo "  Remote restart delay: $RESTART_DELAY_REMOTE seconds"
    echo "  Max retries: $MAX_RETRIES"
    echo "  Listen port: $LISTEN_PORT"
    echo "  Remote port: $REMOTE_PORT"
    echo
    
    print_info "Options:"
    echo "  1. Edit log pattern"
    echo "  2. Edit restart delays"
    echo "  3. Edit max retries"
    echo "  4. Edit ports"
    print_menu_footer
    
    local choice
    read -p "Select an option [0-4]: " choice
    
    case "$choice" in
        1)
            echo
            print_info "Current log pattern: $LOG_PATTERN"
            print_info "Enter new log pattern (regex for error detection):"
            read -p "New pattern: " new_pattern
            if [[ -n "$new_pattern" ]]; then
                LOG_PATTERN="$new_pattern"
                print_success "Log pattern updated"
            fi
            ;;
        2)
            echo
            print_info "Current delays: Local=$RESTART_DELAY_LOCAL, Remote=$RESTART_DELAY_REMOTE"
            read -p "Enter local restart delay (seconds): " new_local_delay
            read -p "Enter remote restart delay (seconds): " new_remote_delay
            if [[ -n "$new_local_delay" ]] && [[ "$new_local_delay" =~ ^[0-9]+$ ]]; then
                RESTART_DELAY_LOCAL="$new_local_delay"
            fi
            if [[ -n "$new_remote_delay" ]] && [[ "$new_remote_delay" =~ ^[0-9]+$ ]]; then
                RESTART_DELAY_REMOTE="$new_remote_delay"
            fi
            print_success "Restart delays updated"
            ;;
        3)
            echo
            print_info "Current max retries: $MAX_RETRIES"
            read -p "Enter new max retries: " new_retries
            if [[ -n "$new_retries" ]] && [[ "$new_retries" =~ ^[0-9]+$ ]]; then
                MAX_RETRIES="$new_retries"
                print_success "Max retries updated"
            fi
            ;;
        4)
            echo
            print_info "Current ports: Listen=$LISTEN_PORT, Remote=$REMOTE_PORT"
            read -p "Enter new listen port: " new_listen_port
            read -p "Enter new remote port: " new_remote_port
            if [[ -n "$new_listen_port" ]] && [[ "$new_listen_port" =~ ^[0-9]+$ ]]; then
                LISTEN_PORT="$new_listen_port"
            fi
            if [[ -n "$new_remote_port" ]] && [[ "$new_remote_port" =~ ^[0-9]+$ ]]; then
                REMOTE_PORT="$new_remote_port"
            fi
            print_success "Ports updated"
            ;;
        0)
            return
            ;;
        *)
            print_warning "Invalid option"
            ;;
    esac
    
    # Save updated configuration
    cat > "$watcher_config" <<EOL
SERVICE_NAME="$SERVICE_NAME"
REMOTE_HOST="$REMOTE_HOST"
REMOTE_PORT="$REMOTE_PORT"
LISTEN_PORT="$LISTEN_PORT"
RESTART_SECRET="$RESTART_SECRET"
ROLE="$ROLE"
LOG_PATTERN="$LOG_PATTERN"
RESTART_DELAY_LOCAL="$RESTART_DELAY_LOCAL"
RESTART_DELAY_REMOTE="$RESTART_DELAY_REMOTE"
MAX_RETRIES="$MAX_RETRIES"
EOL
    
    # Update main config file
    update_config_numeric "$config_file" "restart_watcher_listen_port" "$LISTEN_PORT"
    update_config_numeric "$config_file" "restart_watcher_remote_port" "$REMOTE_PORT"
    
    print_success "Configuration saved. Restart watcher to apply changes."
    press_any_key
}

# Test watcher communication
test_watcher() {
    local service="$1"
    local suffix="$2"
    local config_file="$3"
    
    clear
    print_info "=== Test Watcher Communication ==="
    echo
    
    local watcher_config="/tmp/backhaul-watcher-${suffix}.conf"
    
    if [[ ! -f "$watcher_config" ]]; then
        print_error "Watcher configuration not found. Enable watcher first."
        press_any_key
        return
    fi
    
    # Load configuration
    source "$watcher_config"
    
    echo "Testing communication with $REMOTE_HOST:$REMOTE_PORT"
    echo "Using secret: ${RESTART_SECRET:0:8}..."
    echo
    
    # Test basic connectivity
    print_info "Testing basic connectivity..."
    if nc -z "$REMOTE_HOST" "$REMOTE_PORT" 2>/dev/null; then
        print_success "✓ Port $REMOTE_PORT is reachable on $REMOTE_HOST"
    else
        print_error "✗ Cannot reach $REMOTE_HOST:$REMOTE_PORT"
        print_info "Check firewall rules and ensure remote watcher is running."
        press_any_key
        return
    fi
    
    # Test secret authentication
    print_info "Testing secret authentication..."
    echo "RESTART_REQUEST:$RESTART_SECRET:$ROLE" | nc "$REMOTE_HOST" "$REMOTE_PORT" -w 5
    
    # Wait for ACK
    local ack_received=false
    for i in {1..10}; do
        if [[ -f "/tmp/restart_ack_${SERVICE_NAME}" ]]; then
            rm -f "/tmp/restart_ack_${SERVICE_NAME}"
            ack_received=true
            break
        fi
        sleep 1
    done
    
    if [[ "$ack_received" == "true" ]]; then
        print_success "✓ Secret authentication successful"
        print_success "✓ Watcher communication working properly"
    else
        print_warning "⚠ No ACK received. Possible issues:"
        print_info "  - Remote watcher not running"
        print_info "  - Different secret on remote side"
        print_info "  - Network connectivity issues"
    fi
    
    echo
    print_info "Test completed."
    press_any_key
}

# Show watcher status
show_watcher_status() {
    local service="$1"
    local suffix="$2"
    local config_file="$3"
    
    clear
    print_info "=== Watcher Status ==="
    echo
    
    local pid_file="/tmp/backhaul-watcher-${suffix}.pid"
    local watcher_config="/tmp/backhaul-watcher-${suffix}.conf"
    
    if [[ ! -f "$pid_file" ]]; then
        print_warning "Watcher is not running for this tunnel."
        echo
        print_info "To enable watcher:"
        echo "  1. Go to tunnel management"
        echo "  2. Select 'Manage watcher'"
        echo "  3. Choose 'Enable watcher'"
        press_any_key
        return
    fi
    
    local pid=$(cat "$pid_file" 2>/dev/null)
    
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        print_success "✓ Watcher is running (PID: $pid)"
        
        # Show process info
        echo
        print_info "Process information:"
        ps -p "$pid" -o pid,ppid,cmd,etime --no-headers 2>/dev/null || echo "  Process info unavailable"
        
        # Show configuration if available
        if [[ -f "$watcher_config" ]]; then
            source "$watcher_config"
            echo
            print_info "Configuration:"
            echo "  Service: $SERVICE_NAME"
            echo "  Remote host: $REMOTE_HOST"
            echo "  Remote port: $REMOTE_PORT"
            echo "  Listen port: $LISTEN_PORT"
            echo "  Role: $ROLE"
            echo "  Log pattern: $LOG_PATTERN"
            echo "  Local delay: $RESTART_DELAY_LOCAL seconds"
            echo "  Remote delay: $RESTART_DELAY_REMOTE seconds"
            echo "  Max retries: $MAX_RETRIES"
        fi
        
        # Show recent log entries
        local log_file="/tmp/backhaul-watcher-${suffix}.log"
        if [[ -f "$log_file" ]]; then
            echo
            print_info "Recent log entries:"
            tail -10 "$log_file" | sed 's/^/  /'
        fi
        
    else
        print_error "✗ Watcher process not found or not responding"
        print_info "The PID file exists but the process is not running."
        print_info "This might indicate a crash or improper shutdown."
    fi
    
    echo
    press_any_key
}

# Show watcher logs
show_watcher_logs() {
    local service="$1"
    local suffix="$2"
    local config_file="$3"
    
    clear
    print_info "=== Watcher Logs ==="
    echo
    
    local log_file="/tmp/backhaul-watcher-${suffix}.log"
    
    if [[ ! -f "$log_file" ]]; then
        print_warning "No log file found for this watcher."
        press_any_key
        return
    fi
    
    print_info "Log file: $log_file"
    echo "Press 'q' to exit, 'f' to follow, 'r' to refresh"
    echo
    
    while true; do
        # Show last 20 lines
        tail -20 "$log_file" 2>/dev/null || echo "No log content available"
        echo
        echo "Options: [q]uit [f]ollow [r]efresh [c]lear"
        read -p "Select option: " log_choice
        
        case "$log_choice" in
            q|Q)
                break
                ;;
            f|F)
                clear
                print_info "Following logs (Ctrl+C to stop)..."
                tail -f "$log_file"
                break
                ;;
            r|R)
                clear
                print_info "=== Watcher Logs (Refreshed) ==="
                echo
                ;;
            c|C)
                if confirm_action "Clear log file?" "n"; then
                    > "$log_file"
                    print_success "Log file cleared"
                fi
                ;;
            *)
                print_warning "Invalid option"
                ;;
        esac
    done
}

# Show and manage watcher secret
show_watcher_secret() {
    local config_file="$1"
    local secret
    
    clear
    print_secondary_menu_header "Watcher Secret Management" "Tunnel Configuration"
    
    # Try to get secret from config file first
    if [[ -f "$config_file" ]]; then
        secret=$(grep '^restart_watcher_secret' "$config_file" | cut -d'"' -f2)
    fi
    
    # If not in config, try global secret file
    if [[ -z "$secret" ]] && [[ -f "$CONFIG_DIR/watcher_secret" ]]; then
        secret=$(cat "$CONFIG_DIR/watcher_secret")
    fi
    
    if [[ -n "$secret" ]]; then
        print_success "Current watcher secret:"
        echo "  $secret"
        echo
        print_info "This secret must be shared between client and server."
        print_info "Both sides must use the same secret for coordination."
        echo
        print_info "Options:"
        echo "  1. Copy secret to clipboard (if available)"
        echo "  2. Generate new secret"
        echo "  3. Enter secret manually"
        print_menu_footer
        
        local choice
        read -p "Select an option [0-3]: " choice
        
        case "$choice" in
            1)
                if command -v xclip >/dev/null 2>&1; then
                    echo "$secret" | xclip -selection clipboard
                    print_success "Secret copied to clipboard"
                elif command -v pbcopy >/dev/null 2>&1; then
                    echo "$secret" | pbcopy
                    print_success "Secret copied to clipboard"
                else
                    print_warning "Clipboard not available. Copy manually:"
                    echo "$secret"
                fi
                press_any_key
                ;;
            2)
                if confirm_action "Generate new secret? This will break existing watcher coordination." "n"; then
                    local new_secret
                    new_secret=$(openssl rand -hex 16 2>/dev/null || tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32)
                    echo "$new_secret" > "$CONFIG_DIR/watcher_secret"
                    chmod 600 "$CONFIG_DIR/watcher_secret"
                    if [[ -f "$config_file" ]]; then
                        update_config_value "$config_file" "restart_watcher_secret" "$new_secret"
                    fi
                    print_success "New secret generated: $new_secret"
                    print_warning "You must update the secret on the other side as well."
                fi
                press_any_key
                ;;
            3)
                print_info "Enter the new secret (letters and numbers only):"
                read -p "New secret: " new_secret
                if [[ -n "$new_secret" ]] && [[ "$new_secret" =~ ^[A-Za-z0-9]+$ ]]; then
                    echo "$new_secret" > "$CONFIG_DIR/watcher_secret"
                    chmod 600 "$CONFIG_DIR/watcher_secret"
                    if [[ -f "$config_file" ]]; then
                        update_config_value "$config_file" "restart_watcher_secret" "$new_secret"
                    fi
                    print_success "Secret updated successfully"
                else
                    print_error "Invalid secret format"
                fi
                press_any_key
                ;;
            0)
                return
                ;;
            *)
                print_warning "Invalid option"
                press_any_key
                ;;
        esac
    else
        print_warning "No watcher secret found"
        echo
        print_info "To enable watcher coordination, you need to:"
        echo "  1. Generate a secret on the server side"
        echo "  2. Share that secret with the client side"
        echo "  3. Both sides must use the same secret"
        echo
        if confirm_action "Generate a new secret now?" "y"; then
            local new_secret
            new_secret=$(openssl rand -hex 16 2>/dev/null || tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32)
            echo "$new_secret" > "$CONFIG_DIR/watcher_secret"
            chmod 600 "$CONFIG_DIR/watcher_secret"
            if [[ -f "$config_file" ]]; then
                update_config_value "$config_file" "restart_watcher_secret" "$new_secret"
            fi
            print_success "New secret generated: $new_secret"
            print_info "Share this secret with the other side."
        fi
        press_any_key
    fi
}

# Show watcher menu
show_watcher_menu() {
    local service="$1"
    local suffix="$2"
    local config_file="$3"
    
    clear
    print_secondary_menu_header "Watcher Management" "Tunnel Configuration"
    
    echo " 1. Enable watcher (create/start background process)"
    echo " 2. Disable watcher (stop/remove background process)"
    echo " 3. Edit watcher config (pattern, delays, secret, ports)"
    echo " 4. Show watcher status"
    echo " 5. Show watcher logs"
    echo " 6. Test watcher (send/receive signal)"
    echo " 7. Show watcher secret"
    echo
    echo " 0. Back"
    
    local choice
    read -p "Select an option [0-7]: " choice
    
    case "$choice" in
        1)
            enable_watcher "$service" "$suffix" "$config_file"
            ;;
        2)
            disable_watcher "$service" "$suffix" "$config_file"
            ;;
        3)
            edit_watcher_config "$service" "$suffix" "$config_file"
            ;;
        4)
            show_watcher_status "$service" "$suffix" "$config_file"
            ;;
        5)
            show_watcher_logs "$service" "$suffix" "$config_file"
            ;;
        6)
            test_watcher "$service" "$suffix" "$config_file"
            ;;
        7)
            show_watcher_secret "$config_file"
            ;;
        0)
            return
            ;;
        *)
            print_warning "Invalid option"
            ;;
    esac
    
    show_watcher_menu "$service" "$suffix" "$config_file"
} 