#!/bin/bash
# tunnel_mgmt.sh
# List/manage tunnels, single tunnel management, connection test 

# Ensure helpers.sh is sourced for logging and restart helpers
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}" )" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

# --- Tunnel Management ---
manage_tunnels() {
    while true; do
        clear
        print_server_info_banner
        print_info "--- Available Backhaul Services ---"
        mapfile -t services < <(systemctl list-unit-files --type=service 'backhaul-*.service' --no-legend | awk '{print $1}' | grep -v 'backhaul-watcher-')

        if [ ${#services[@]} -eq 0 ]; then
            print_warning "No Backhaul services found. Use 'Configure a New Tunnel' first."
            press_any_key
            return
        fi

        local i=1
        for s in "${services[@]}"; do
            if systemctl is-active --quiet "$s"; then
                echo -e " $i. \e[32m$s (Active)\e[0m"
            else
                echo -e " $i. \e[31m$s (Inactive)\e[0m"
            fi
            ((i++))
        done
        echo " 0. Back to Main Menu"
        
        local choice
        read -p "Select a service to manage [0-$((${#services[@]}))]: " choice

        if [[ "$choice" == "0" ]]; then
            return
        elif [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#services[@]} ]; then
            local service_name=${services[$((choice-1))]}
            manage_single_tunnel "$service_name"
        else
            print_warning "Invalid selection."
            press_any_key
        fi
    done
}

manage_single_tunnel() {
    local service=$1
    local suffix
    suffix=$(echo "$service" | sed 's/backhaul-\(.*\)\.service/\1/')
    local config_file="$CONFIG_DIR/config-${suffix}.toml"
    local service_file="$SERVICE_DIR/$service"
    local certs_to_delete=""
    if [[ "$suffix" == server-wss* || "$suffix" == server-wssmux* ]]; then
        # Try to find certs referenced in config
        if [ -f "$config_file" ]; then
            local cert_path key_path
            cert_path=$(grep '^tls_cert' "$config_file" | cut -d'"' -f2)
            key_path=$(grep '^tls_key' "$config_file" | cut -d'"' -f2)
            if [ -n "$cert_path" ] && [ -f "$cert_path" ]; then
                certs_to_delete+="$cert_path\n"
            fi
            if [ -n "$key_path" ] && [ -f "$key_path" ]; then
                certs_to_delete+="$key_path\n"
            fi
        fi
    fi

    while true; do
        clear
        print_server_info_banner
        local status
        status=$(systemctl is-active "$service")
        local status_text
        if [[ "$status" == "active" ]]; then
             status_text="\e[32mActive\e[0m"
        else
             status_text="\e[31mInactive\e[0m"
        fi
        print_info "--- Managing: $service (Status: $status_text) ---"
        print_info "Tip: Press '?' for help about tunnel features."

        # Show service status
        local service_status
        if systemctl is-active --quiet "$service"; then
            service_status="\e[32mRunning\e[0m"
        else
            service_status="\e[31mStopped\e[0m"
        fi
        print_info "Service Status: $service_status"
        # Show watcher status
        local watcher_pid_file="/tmp/backhaul-watcher-${suffix}.pid"
        if [[ -f "$watcher_pid_file" ]]; then
            print_info "Watcher: \e[32mEnabled\e[0m (PID: $(cat $watcher_pid_file))"
        else
            print_info "Watcher: \e[31mDisabled\e[0m"
        fi

        echo " 1. Start"
        echo " 2. Stop"
        echo " 3. Restart"
        echo " 4. View Service Status (summary + last logs)"
        echo " 5. View Full Logs (scroll/search/live)"
        echo " 6. View Configuration"
        echo " 7. Edit Configuration (nano)"
        echo " 8. Change Log Level"
        echo " 9. Test Connection"
        echo "10. Hot Reload Config"
        echo "11. Manage Cron Auto-Restart"
        echo "12. Manage Coordinated Restart Watcher"
        echo "13. Health Check & Performance"
        echo "14. Validate Configuration"
        echo "15. Graceful Restart"
        echo "16. Delete Service"
        echo " ?. Help"
        echo " 0. Back to Service List"

        local choice
        read -p "Enter choice [0-16, ? for help]: " choice
        
        case $choice in
            1) with_spinner "Starting service" systemctl start "$service"; print_success "Service started successfully. You can now connect to this tunnel."; press_any_key;;
            2) with_spinner "Stopping service" systemctl stop "$service"; print_success "Service stopped. Connections will be refused until restarted."; press_any_key;;
            3) with_spinner "Restarting service" systemctl restart "$service"; print_success "Service restarted. Check logs if you encounter issues."; press_any_key;;
            \?) 
                print_info "================= Tunnel Management Help ================="
                echo
                echo "Tunnel Management Options:"
                echo " 1. Start - Start the tunnel service"
                echo " 2. Stop - Stop the tunnel service"
                echo " 3. Restart - Restart the tunnel service"
                echo " 4. View Service Status - Show service status and recent logs"
                echo " 5. View Full Logs - Interactive log viewing with search/follow"
                echo " 6. View Configuration - Display current tunnel configuration"
                echo " 7. Edit Configuration - Edit config file with nano editor"
                echo " 8. Change Log Level - Modify logging verbosity"
                echo " 9. Test Connection - Test tunnel connectivity"
                echo "10. Hot Reload Config - Reload config without restart"
                echo "11. Manage Cron Auto-Restart - Set up automatic restarts"
                echo "12. Manage Coordinated Restart Watcher - Advanced restart coordination"
                echo "13. Health Check & Performance - Monitor tunnel health"
                echo "14. Validate Configuration - Check config for errors"
                echo "15. Graceful Restart - Coordinated restart with remote side"
                echo "16. Delete Service - Remove the tunnel, config, and related files."
                echo
                echo "- For more details, see the main help from the main menu."
                echo "================================================================"
                press_any_key
                ;;
            4)
                systemctl status "$service" --no-pager
                echo
                print_info "Tip: For full logs, including scrolling/searching, use option 5 in this menu."
                press_any_key
                ;;
            5)
                print_info "Choose log viewing mode:"
                echo " 1) Live follow (Ctrl+C to exit log view and return to menu)"
                echo " 2) Interactive (scroll/search, press q to quit, F to follow live, Ctrl+C to exit log view and return to menu)"
                read -p "Select [1-2, default 2]: " log_mode
                log_mode=${log_mode:-2}
                if [[ "$log_mode" == "1" ]]; then
                    print_warning "You are about to enter live log view. Press Ctrl+C to exit log view and return to the menu."
                    sleep 2
                    # Save current SIGINT trap
                    old_trap=$(trap -p SIGINT)
                    # Ignore SIGINT in parent
                    trap '' SIGINT
                    # Run log viewer in subshell with default SIGINT
                    (
                        trap - SIGINT
                        journalctl -u "$service" -f --no-pager
                    )
                    # Restore old SIGINT trap
                    eval "$old_trap"
                else
                    print_info "Interactive log view: Use arrow keys to scroll, / to search, F to follow live, q to quit. Press Ctrl+C to exit log view and return to the menu."
                    sleep 2
                    old_trap=$(trap -p SIGINT)
                    trap '' SIGINT
                    (
                        trap - SIGINT
                        journalctl -u "$service" --no-pager | less +F
                    )
                    eval "$old_trap"
                fi
                ;;
            6)
                print_info "Viewing configuration. Press 'q' to exit and return to the menu."
                sleep 1
                less "$config_file"
                ;;
            7) 
                if [ ! -f "$config_file" ]; then print_error "Config file not found for this tunnel. Please check your configuration and try again."; press_any_key; continue; fi
                backup_config "$config_file"
                nano "$config_file"
                if confirm_action "Restart service to apply changes?" "y"; then 
                    systemctl restart "$service"
                    print_success "Service restarted."
                fi
                ;;
            8)
                # Change log level submenu
                print_info "--- Change Log Level ---"
                echo "Log levels control the verbosity of logs:"
                echo "  debug: Most detailed, for troubleshooting."
                echo "  info:  Normal operation messages (default)."
                echo "  warn:  Only warnings and errors."
                echo "  error: Only errors."
                echo
                current_level=$(grep -E '^\s*log_level\s*=\s*"' "$config_file" | head -n1 | cut -d'"' -f2)
                print_info "Current log level: ${current_level:-info}"
                echo "Select new log level:"
                select new_level in debug info warn error cancel; do
                    case $new_level in
                        debug|info|warn|error)
                                # Update log_level in config file using unified function
                                update_config_value "$config_file" "log_level" "$new_level"
                            print_success "Log level updated to $new_level."
                                if confirm_action "Restart service to apply new log level?" "y"; then
                                systemctl restart "$service"
                                print_success "Service restarted."
                            fi
                            break
                            ;;
                        cancel)
                            print_info "Log level change cancelled."
                            break
                            ;;
                        *)
                            print_warning "Invalid selection."
                            ;;
                    esac
                done
                ;;
            9) test_connection "$config_file"; press_any_key;;
            10) hot_reload_service "$service"; press_any_key;;
            11) manage_cron_menu "$service";;
            12)
                manage_watcher_submenu "$service" "$suffix" "$config_file" ;;
            13)
                show_health_and_performance "$suffix" "$service" ;;
            14)
                validate_tunnel_config "$config_file" ;;
            15)
                graceful_restart_with_ui "$suffix" ;;
            16)
                print_warning "You are about to delete the following:"
                echo "  - Service: $service_file"
                echo "  - Config: $config_file"
                
                # Check for watcher files
                local watcher_script="/tmp/backhaul-watcher-${suffix}.sh"
                local watcher_pid_file="/tmp/backhaul-watcher-${suffix}.pid"
                local watcher_log="/tmp/backhaul-watcher-${suffix}.log"
                
                if [[ -f "$watcher_script" ]]; then
                    echo "  - Watcher script: $watcher_script"
                fi
                if [[ -f "$watcher_pid_file" ]]; then
                    echo "  - Watcher process file: $watcher_pid_file"
                fi
                if [[ -f "$watcher_log" ]]; then
                    echo "  - Watcher logs: $watcher_log"
                fi
                
                if [ -n "$certs_to_delete" ]; then
                    echo -e "  - TLS Cert/Key(s):\n$certs_to_delete"
                fi
                if grep -q "^$suffix:" "$UFW_METADATA_FILE" 2>/dev/null; then
                    echo "  - UFW rule: $(grep "^$suffix:" "$UFW_METADATA_FILE" | cut -d':' -f2)"
                fi
                if crontab -l 2>/dev/null | grep -q "$service"; then
                    echo "  - Cron job for $service"
                fi
                read -p "Are you sure you want to PERMANENTLY delete all of the above? (y/n): " confirm_delete
                if [[ "${confirm_delete,,}" == "y" ]]; then
                    print_warning "Stopping and disabling service..."
                    with_spinner "Stopping service" systemctl stop "$service" &>/dev/null
                    with_spinner "Disabling service" systemctl disable "$service" &>/dev/null
                    
                    # Clean up watcher if it exists with robust process termination
                    if [[ -f "$watcher_pid_file" ]]; then
                        local watcher_pid=$(cat "$watcher_pid_file")
                        if [[ -n "$watcher_pid" ]]; then
                            print_info "Stopping watcher process (PID: $watcher_pid)..."
                            
                            # Try graceful termination first
                            kill "$watcher_pid" 2>/dev/null
                            
                            # Wait up to 5 seconds for graceful shutdown
                            local count=0
                            while kill -0 "$watcher_pid" 2>/dev/null && [[ $count -lt 5 ]]; do
                                sleep 1
                                ((count++))
                            done
                            
                            # If still running, force kill
                            if kill -0 "$watcher_pid" 2>/dev/null; then
                                print_warning "Process not responding to SIGTERM, forcing termination..."
                                kill -9 "$watcher_pid" 2>/dev/null
                                sleep 1
                            fi
                            
                            # Verify process is dead
                            if kill -0 "$watcher_pid" 2>/dev/null; then
                                print_error "Failed to terminate watcher process (PID: $watcher_pid)"
                            else
                                print_success "Watcher process terminated successfully"
                            fi
                        fi
                        rm -f "$watcher_pid_file"
                    fi
                    
                    # Kill any remaining child processes of the watcher
                    pkill -f "backhaul-watcher-${suffix}" 2>/dev/null
                    
                    if [[ -f "$watcher_script" ]]; then
                        rm -f "$watcher_script"
                        print_info "Removed watcher script"
                    fi
                    if [[ -f "$watcher_log" ]]; then
                        rm -f "$watcher_log"
                        print_info "Removed watcher logs"
                    fi
                    
                    # Remove any temporary ACK files
                    rm -f "/tmp/restart_ack_${service}"
                    
                    print_warning "Removing files..."
                    rm -f "$config_file" "$service_file"
                    if [ -n "$certs_to_delete" ]; then
                        echo -e "$certs_to_delete" | xargs rm -f
                    fi
                    manage_ufw_delete "$suffix"
                    remove_cron_job "$service"
                    systemctl daemon-reload
                    # Run zombie cleanup
                    cleanup_zombie_processes
                    
                    print_success "Service $service and all associated files (including watcher) have been deleted. You may now create a new tunnel or exit.";
                    press_any_key
                    return
                fi
                ;;
            0) return ;;
            \?)
                clear
                print_info "================= Tunnel Management Help ================="
                echo "This menu lets you manage a specific Backhaul tunnel/service."
                echo
                echo " 1. Start: Start the selected tunnel service."
                echo " 2. Stop: Stop the tunnel service."
                echo " 3. Restart: Restart the tunnel service."
                echo " 4. View Service Status: Show summary and last logs."
                echo " 5. View Full Logs: Scroll/search or follow logs live."
                echo " 6. View Configuration: View the TOML config (press q to exit)."
                echo " 7. Edit Configuration: Edit config in nano, then optionally restart."
                echo " 8. Change Log Level: Adjust log verbosity (debug/info/warn/error)."
                echo " 9. Test Connection: Test if the tunnel is reachable."
                echo "10. Hot Reload Config: Reload config without restart (if supported)."
                echo "11. Manage Cron Auto-Restart: Set up or remove auto-restart jobs."
                echo "12. Manage Coordinated Restart Watcher: All watcher options (enable/disable, config, status, logs, test) in a dedicated submenu."
                echo "    - The watcher coordinates restarts between client and server on error."
                echo "    - You must set the same secret and compatible ports on both sides."
                echo "    - Use the watcher submenu for config, status, logs, and testing."
                echo "13. Health Check & Performance: Monitor tunnel health, resource usage, and performance metrics."
                echo "14. Validate Configuration: Check config file syntax and validate settings."
                echo "15. Graceful Restart: Restart with health checks and error recovery."
                echo "16. Delete Service: Remove the tunnel, config, and related files."
                echo " 0. Back to Service List: Return to the previous menu."
                echo
                echo "Tips:"
                echo "- Use Ctrl+C to exit log views and return to this menu."
                echo "- Use 'q' to exit configuration view."
                echo "- For more details, see the main help from the main menu."
                press_any_key
                ;;
            *) print_warning "Invalid option."; press_any_key;;
        esac
    done
}

hot_reload_service() {
    local service=$1
    print_info "Sending SIGHUP to $service for hot reload..."
    if systemctl kill -s HUP "$service" 2>/dev/null; then
        print_success "Hot reload signal sent to $service."
        print_info "If the Backhaul binary supports hot reload, config changes should now be applied."
    else
        print_error "Failed to send hot reload signal. Your system or Backhaul version may not support this."
    fi
}

test_connection() {
    local config_file=$1
    if [ ! -f "$config_file" ]; then print_error "Config file not found."; return 1; fi

    print_info "--- Running Connection Test ---"
    local mode
    mode=$(grep -E '^\s*\[(server|client)\]' "$config_file" | tr -d '[]')
    
    if [[ "$mode" == "server" ]]; then
        local listen_addr
        listen_addr=$(grep -E '^\s*bind_addr\s*=' "$config_file" | cut -d'"' -f2)
        local port
        port=$(echo "$listen_addr" | cut -d':' -f2)
        print_info "Testing server listen port $port..."
        if nc -z localhost "$port"; then
            print_success "Port $port is open and listening locally."
        else
            print_error "Port $port is NOT open. The service might be down or misconfigured."
        fi
    elif [[ "$mode" == "client" ]]; then
        local remote_addr
        remote_addr=$(grep -E '^\s*remote_addr\s*=' "$config_file" | cut -d'"' -f2)
        local ip
        ip=$(echo "$remote_addr" | cut -d':' -f1)
        local port
        port=$(echo "$remote_addr" | cut -d':' -f2)
        print_info "Testing connection to remote server $ip on port $port..."
        if nc -z -w 5 "$ip" "$port"; then
            print_success "Successfully connected to $ip:$port."
        else
            print_error "Could not connect to $ip:$port. Check server status, firewall, and config."
        fi
    else
        print_warning "Could not determine mode from config file."
    fi
}

# --- Watcher Submenu ---
manage_watcher_submenu() {
    local service="$1"
    local suffix="$2"
    local config_file="$3"
    while true; do
        clear
        print_info "--- Coordinated Restart Watcher Submenu ---"
        print_info "Tip: Press '?' for help about watcher features."
        echo "1. Enable watcher (create/start background process)"
        echo "2. Disable watcher (stop/remove background process)"
        echo "3. Edit watcher config (pattern, delays, secret, ports)"
        echo "4. Show watcher status"
        echo "5. Show watcher logs"
        echo "6. Test watcher (send/receive signal)"
        echo "?. Help"
        echo "0. Back"
        read -p "Select [0-6, ? for help]: " wopt
        case $wopt in
            1) enable_watcher "$service" "$suffix" "$config_file" ;;
            2) disable_watcher "$service" "$suffix" "$config_file" ;;
            3) edit_watcher_config "$service" "$suffix" "$config_file" ;;
            4) show_watcher_status "$service" "$suffix" "$config_file" ;;
            5) show_watcher_logs "$service" "$suffix" "$config_file" ;;
            6) test_watcher "$service" "$suffix" "$config_file" ;;
            \?) watcher_submenu_help ;;
            0) return ;;
            *) print_warning "Invalid option."; press_any_key ;;
        esac
    done
}

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

    # Use default secret
    local secret="backhaul-watcher-naxon"

    # Add UFW rule for listen port
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
        print_info "--> UFW is active. Adding rule for port ${listen_port}/tcp..."
        ufw allow ${listen_port}/tcp >/dev/null 2>&1
        if [[ $? -eq 0 ]]; then
            print_success "UFW rule added successfully."
        else
            print_warning "Failed to add UFW rule. You may need to add it manually."
        fi
    fi

    # Create simple background watcher script with proper signal handling
    local watcher_script="/tmp/backhaul-watcher-${suffix}.sh"
    cat > "$watcher_script" <<EOL
#!/bin/bash
# Simple watcher for $service
# This script runs in background and coordinates restarts

SERVICE_NAME="$service"
REMOTE_HOST="$remote_host"
REMOTE_PORT="$remote_port"
LISTEN_PORT="$listen_port"
SECRET="$secret"
ROLE="$role"

log() { echo "[Watcher][\$ROLE][\$(date +'%F %T')] \$1"; }

# Global variables for cleanup
LISTENER_PID=""
JOURNAL_PID=""

# Cleanup function
cleanup() {
    log "Cleaning up watcher processes..."
    
    # Kill listener process
    if [[ -n "\$LISTENER_PID" ]]; then
        kill "\$LISTENER_PID" 2>/dev/null
        # Wait for graceful termination
        local count=0
        while kill -0 "\$LISTENER_PID" 2>/dev/null && [[ \$count -lt 3 ]]; do
            sleep 1
            ((count++))
        done
        # Force kill if still running
        if kill -0 "\$LISTENER_PID" 2>/dev/null; then
            kill -9 "\$LISTENER_PID" 2>/dev/null
        fi
    fi
    
    # Kill journalctl process
    if [[ -n "\$JOURNAL_PID" ]]; then
        kill "\$JOURNAL_PID" 2>/dev/null
        # Wait for graceful termination
        local count=0
        while kill -0 "\$JOURNAL_PID" 2>/dev/null && [[ \$count -lt 3 ]]; do
            sleep 1
            ((count++))
        done
        # Force kill if still running
        if kill -0 "\$JOURNAL_PID" 2>/dev/null; then
            kill -9 "\$JOURNAL_PID" 2>/dev/null
        fi
    fi
    
    # Clean up temporary files
    rm -f "/tmp/restart_ack_\${SERVICE_NAME}"
    
    log "Cleanup completed"
    exit 0
}

# Set up signal handlers
trap cleanup SIGTERM SIGINT SIGQUIT

# Function to send restart request and wait for ACK
send_restart_request() {
    log "Sending restart request to \$REMOTE_HOST:\$REMOTE_PORT"
    echo "RESTART_REQUEST:\$SECRET:\$ROLE" | nc "\$REMOTE_HOST" "\$REMOTE_PORT" -w 2 2>/dev/null
    
    # Wait for ACK (up to 10 seconds)
    log "Waiting for ACK from remote side..."
    for i in {1..10}; do
        # Check for ACK file (created by listener)
        if [[ -f "/tmp/restart_ack_\${SERVICE_NAME}" ]]; then
            rm -f "/tmp/restart_ack_\${SERVICE_NAME}"
            log "ACK received. Coordinated restart will proceed."
            return 0
        fi
        sleep 1
    done
    log "No ACK received. Proceeding with local restart only."
    return 1
}

# Function to listen for restart requests
listen_for_requests() {
    while true; do
        # Use timeout to prevent hanging
        msg=\$(timeout 30 nc -l -p "\$LISTEN_PORT" 2>/dev/null)
        if [[ "\$msg" =~ ^RESTART_REQUEST:\$SECRET: ]]; then
            local sender_role=\${msg##*:}
            log "Received restart request from \$sender_role. Sending ACK and restarting service."
            
            # Send ACK back to sender
            echo "RESTART_ACK:\$SECRET:\$ROLE" | nc "\$REMOTE_HOST" "\$REMOTE_PORT" -w 2 2>/dev/null
            
            # Create ACK file for local coordination
            touch "/tmp/restart_ack_\${SERVICE_NAME}"
            
            # Wait a bit then restart
            sleep 5
            if systemctl list-unit-files | grep -q "\$SERVICE_NAME"; then
                systemctl restart "\$SERVICE_NAME"
                log "Service restarted (coordinated)"
            else
                log "ERROR: Service \$SERVICE_NAME not found"
            fi
        elif [[ "\$msg" =~ ^RESTART_ACK:\$SECRET: ]]; then
            # This is an ACK for a request we sent
            local ack_role=\${msg##*:}
            log "Received ACK from \$ack_role"
            # Create ACK file for coordination
            touch "/tmp/restart_ack_\${SERVICE_NAME}"
        fi
        # Small sleep to prevent CPU hogging
        sleep 1
    done
}

# Start listener in background
listen_for_requests &
LISTENER_PID=\$!

# Monitor service logs for errors (with resource limits)
log "Starting watcher for \$SERVICE_NAME"
# Use timeout and limit log lines to prevent resource exhaustion
timeout 3600 journalctl -u "\$SERVICE_NAME" -f --no-pager --lines=100 | while read -r line; do
    if [[ "\$line" =~ ERROR|FATAL ]]; then
        log "Error detected. Initiating coordinated restart."
        
        # Try coordinated restart first
        if send_restart_request; then
            # ACK received, wait for coordination
            sleep 5
            if systemctl list-unit-files | grep -q "\$SERVICE_NAME"; then
                systemctl restart "\$SERVICE_NAME"
                log "Service restarted (coordinated)"
            else
                log "ERROR: Service \$SERVICE_NAME not found"
            fi
        else
            # No ACK, restart locally only
            sleep 5
            if systemctl list-unit-files | grep -q "\$SERVICE_NAME"; then
                systemctl restart "\$SERVICE_NAME"
                log "Service restarted (local only)"
            else
                log "ERROR: Service \$SERVICE_NAME not found"
            fi
        fi
        break
    fi
done &
JOURNAL_PID=\$!

# Wait for either process to exit
wait
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
    if [[ "$role" == "client" && "$local_ip" != "unknown" ]]; then
        print_info "Use your IPv4 address ($local_ip) when configuring the server side."
    fi
    press_any_key
}

disable_watcher() {
    local service="$1"
    local suffix="$2"
    local config_file="$3"
    local watcher_script="/tmp/backhaul-watcher-${suffix}.sh"
    local watcher_pid_file="/tmp/backhaul-watcher-${suffix}.pid"
    local watcher_log="/tmp/backhaul-watcher-${suffix}.log"
    
    # Stop background process with proper cleanup
    if [[ -f "$watcher_pid_file" ]]; then
        local watcher_pid=$(cat "$watcher_pid_file")
        if [[ -n "$watcher_pid" ]]; then
            print_info "Stopping watcher process (PID: $watcher_pid)..."
            
            # Try graceful termination first
            kill "$watcher_pid" 2>/dev/null
            
            # Wait up to 5 seconds for graceful shutdown
            local count=0
            while kill -0 "$watcher_pid" 2>/dev/null && [[ $count -lt 5 ]]; do
                sleep 1
                ((count++))
            done
            
            # If still running, force kill
            if kill -0 "$watcher_pid" 2>/dev/null; then
                print_warning "Process not responding to SIGTERM, forcing termination..."
                kill -9 "$watcher_pid" 2>/dev/null
                sleep 1
            fi
            
            # Verify process is dead
            if kill -0 "$watcher_pid" 2>/dev/null; then
                print_error "Failed to terminate watcher process (PID: $watcher_pid)"
            else
                print_success "Watcher process terminated successfully"
            fi
            
            rm -f "$watcher_pid_file"
        fi
    fi
    
    # Kill any remaining child processes of the watcher
    pkill -f "backhaul-watcher-${suffix}" 2>/dev/null
    
    # Remove watcher script
    if [[ -f "$watcher_script" ]]; then
        rm -f "$watcher_script"
        print_info "Removed watcher script"
    fi
    
    # Remove watcher log
    if [[ -f "$watcher_log" ]]; then
        rm -f "$watcher_log"
        print_info "Removed watcher log"
    fi
    
    # Remove any temporary ACK files
    rm -f "/tmp/restart_ack_${service}"
    
    # Remove UFW rule for listen port (if present in config)
    local listen_port
    listen_port=$(grep '^restart_watcher_listen_port' "$config_file" | awk -F'=' '{print $2}' | tr -d ' "')
    if [ -n "$listen_port" ]; then
        manage_ufw_delete "${suffix}-watcher"
    fi
    
    # Update config file
    sed -i '/^restart_watcher_enabled/d' "$config_file"
    sed -i '/^restart_watcher_pid/d' "$config_file"
    echo "restart_watcher_enabled = \"n\"" >> "$config_file"
    print_success "Watcher disabled and all processes removed."
    press_any_key
}

edit_watcher_config() {
    local service="$1"
    local suffix="$2"
    local config_file="$3"
    local role remote_host remote_port listen_port secret
    
    # Determine role and extract config
    if grep -q '^\[server\]' "$config_file"; then
        role="server"
        print_info "This is a SERVER tunnel"
    else
        role="client"
        print_info "This is a CLIENT tunnel"
    fi
    
    remote_host=$(grep '^remote_addr' "$config_file" | cut -d'"' -f2 | cut -d':' -f1)
    remote_port=$(grep '^restart_watcher_remote_port' "$config_file" | awk -F'=' '{print $2}' | tr -d ' "')
    listen_port=$(grep '^restart_watcher_listen_port' "$config_file" | awk -F'=' '{print $2}' | tr -d ' "')
    secret=$(grep '^restart_watcher_secret' "$config_file" | cut -d'"' -f2)
    remote_port=${remote_port:-45680}
    listen_port=${listen_port:-45679}
    secret=${secret:-$RESTART_WATCHER_SECRET}

    clear
    print_info "=== Watcher Configuration ==="
    echo
    
    echo
    print_info "The watcher helps both sides restart together when there are problems."
    echo
    
    # Show current secret
    if [[ -n "$secret" ]]; then
        print_info "Current secret: $secret"
        echo "Copy this to the other side."
        echo
    else
        print_info "No secret configured yet."
        echo
    fi
    
    # Port configuration with role-based defaults
    print_info "--- Ports ---"
    
    local default_listen_port default_remote_port
    if [[ "$role" == "server" ]]; then
        default_listen_port=45690
        default_remote_port=45680
        # Get remote host from config or ask user
        remote_host=$(grep '^restart_watcher_remote_host' "$config_file" | cut -d'"' -f2 2>/dev/null)
        if [[ -z "$remote_host" ]]; then
            read -p "Enter client IP address: " remote_host
        fi
    else
        default_listen_port=45680
        default_remote_port=45690
        # Get remote host from tunnel config
        remote_host=$(grep '^remote_addr' "$config_file" | cut -d'"' -f2 | cut -d':' -f1)
    fi
    
    # Use unified default value handling
    echo "Current receive port: ${listen_port:-$default_listen_port}"
    while true; do
        read -p "Port for receiving messages [${listen_port:-$default_listen_port}]: " new_listen_port
        new_listen_port=$(get_default_value "$new_listen_port" "${listen_port:-$default_listen_port}")
        if ! validate_port "$new_listen_port"; then
            print_warning "Invalid port number. Please enter a value between 1 and 65535."
            continue
        fi
        break
    done
    echo "Current send port: ${remote_port:-$default_remote_port}"
    while true; do
        read -p "Port for sending messages [${remote_port:-$default_remote_port}]: " new_remote_port
        new_remote_port=$(get_default_value "$new_remote_port" "${remote_port:-$default_remote_port}")
        if ! validate_port "$new_remote_port"; then
            print_warning "Invalid port number. Please enter a value between 1 and 65535."
            continue
        fi
        break
    done
    
    # Validate ports are different
    if [[ "$new_listen_port" == "$new_remote_port" ]]; then
        print_error "Receive and send ports must be different!"
        press_any_key
        return
    fi

    # Secret configuration
    echo
    print_info "--- Secret ---"
    if [[ -n "$secret" ]]; then
        if confirm_action "Keep current secret?" "y"; then
            new_secret="$secret"
        else
            new_secret="backhaul-watcher-naxon"
            print_info "New secret: $new_secret"
        fi
    else
        new_secret="backhaul-watcher-naxon"
        print_info "Generated secret: $new_secret"
    fi

    # Update config file
        sed -i '/^restart_watcher_secret/d' "$config_file"
        sed -i '/^restart_watcher_listen_port/d' "$config_file"
        sed -i '/^restart_watcher_remote_port/d' "$config_file"
    sed -i '/^restart_watcher_pid/d' "$config_file"
        echo "restart_watcher_secret = \"$new_secret\"" >> "$config_file"
        echo "restart_watcher_listen_port = $new_listen_port" >> "$config_file"
        echo "restart_watcher_remote_port = $new_remote_port" >> "$config_file"
    echo "restart_watcher_pid = $watcher_pid" >> "$config_file"
    
        print_success "Watcher config updated."
    press_any_key
}

test_watcher() {
    local service="$1"
    local suffix="$2"
    local config_file="$3"
    local role remote_host remote_port listen_port secret
    
    # Determine role and extract config
    if grep -q '^\[server\]' "$config_file"; then
        role="server"
        # For server, we need to get the client IP from the user since it's not in config
        print_info "This is a SERVER tunnel. You need to provide the client IP for testing."
        read -p "Enter client IP address for testing: " remote_host
        if [[ -z "$remote_host" ]]; then
            print_error "Client IP is required for testing."
            press_any_key
            return
        fi
    else
        role="client"
        remote_host=$(grep '^remote_addr' "$config_file" | cut -d'"' -f2 | cut -d':' -f1)
        if [[ -z "$remote_host" ]]; then
            print_error "Could not determine remote host from config."
            press_any_key
            return
        fi
    fi
    
    remote_port=$(grep '^restart_watcher_remote_port' "$config_file" | awk -F'=' '{print $2}' | tr -d ' "')
    listen_port=$(grep '^restart_watcher_listen_port' "$config_file" | awk -F'=' '{print $2}' | tr -d ' "')
    secret=$(grep '^restart_watcher_secret' "$config_file" | cut -d'"' -f2)
    remote_port=${remote_port:-45680}
    listen_port=${listen_port:-45679}
    secret=${secret:-backhaul-watcher-naxon}

    clear
    print_info "--- Watcher Test ---"
    echo "Remote host: $remote_host"
    echo "Remote port: $remote_port"
    echo "Listen port: $listen_port"
    echo "Role: $role"
    echo
    echo "1. Send test restart signal to remote"
    echo "2. Listen for test restart signal (manual receive)"
    echo "0. Back"
    read -p "Select [0-2]: " testopt
    case $testopt in
        1)
            print_info "Sending test RESTART_REQUEST to $remote_host:$remote_port ..."
            echo "RESTART_REQUEST:$secret:$role" | nc "$remote_host" "$remote_port" -w 2
            if [[ $? -eq 0 ]]; then
                print_success "Signal sent successfully."
            else
                print_error "Failed to send signal. Check network connectivity and firewall."
            fi
            press_any_key
            ;;
        2)
            print_info "Listening for test RESTART_REQUEST on port $listen_port ..."
            print_info "Press Ctrl+C to cancel"
            echo
            cancelled=0
            trap 'cancelled=1' SIGINT
            msg=$(nc -l -p "$listen_port" -w 30 2>/dev/null)
            trap - SIGINT
            if [[ $cancelled -eq 1 ]]; then
                echo
                print_info "Listen cancelled by user."
                press_any_key
                return
            fi
            if [[ "$msg" =~ ^RESTART_REQUEST:$secret: ]]; then
                local sender_role=${msg##*:}
                print_success "Received RESTART_REQUEST from $sender_role. Sending ACK back."
                echo "RESTART_ACK:$secret:$role" | nc "$remote_host" "$remote_port" -w 2
                print_info "ACK sent."
            else
                print_error "No valid RESTART_REQUEST received or timeout."
            fi
            press_any_key
            ;;
        0|*)
            return
            ;;
    esac
}

show_watcher_status() {
    local service="$1"
    local suffix="$2"
    local config_file="$3"
    local watcher_script="/tmp/backhaul-watcher-${suffix}.sh"
    local watcher_pid_file="/tmp/backhaul-watcher-${suffix}.pid"
    local watcher_log="/tmp/backhaul-watcher-${suffix}.log"
    
    clear
    print_info "=== Watcher Status ==="
    echo
    
    # Check if watcher is enabled in config
    local enabled=$(grep '^restart_watcher_enabled' "$config_file" | cut -d'"' -f2 2>/dev/null)
    if [[ "$enabled" == "y" ]]; then
        print_success "Watcher is enabled in configuration"
    else
        print_warning "Watcher is not enabled in configuration"
    fi
    
    # Check if watcher script exists
    if [[ -f "$watcher_script" ]]; then
        print_success "Watcher script exists: $watcher_script"
    else
        print_warning "Watcher script not found"
    fi
    
    # Check if watcher process is running
    if [[ -f "$watcher_pid_file" ]]; then
        local watcher_pid=$(cat "$watcher_pid_file")
        if [[ -n "$watcher_pid" ]] && kill -0 "$watcher_pid" 2>/dev/null; then
            print_success "Watcher process is running (PID: $watcher_pid)"
        else
            print_error "Watcher process is not running (PID file exists but process dead)"
        fi
    else
        print_warning "Watcher process not found"
    fi
    
    # Show configuration
    echo
    print_info "--- Configuration ---"
    local secret listen_port remote_port
    secret=$(grep '^restart_watcher_secret' "$config_file" | cut -d'"' -f2)
    listen_port=$(grep '^restart_watcher_listen_port' "$config_file" | awk -F'=' '{print $2}' | tr -d ' "')
    remote_port=$(grep '^restart_watcher_remote_port' "$config_file" | awk -F'=' '{print $2}' | tr -d ' "')
    
    echo "Secret: ${secret:-not set}"
    echo "Listen port: ${listen_port:-not set}"
    echo "Remote port: ${remote_port:-not set}"
    
    # Show recent logs if available
    if [[ -f "$watcher_log" ]]; then
        echo
        print_info "--- Recent Logs ---"
        tail -n 5 "$watcher_log" 2>/dev/null || echo "No logs available"
    fi
    
    press_any_key
}

show_watcher_logs() {
    local service="$1"
    local suffix="$2"
    local config_file="$3"
    local watcher_log="/tmp/backhaul-watcher-${suffix}.log"
    clear
    print_info "=== Watcher Logs ==="
    if [[ -f "$watcher_log" ]]; then
    print_info "Last 20 lines of watcher logs:"
        tail -n 20 "$watcher_log"
    echo
        read -p "View full log? (y/n) [n]: " viewfull
        viewfull=${viewfull:-n}
    if [[ "${viewfull,,}" == "y" ]]; then
            less "$watcher_log"
        fi
    else
        print_warning "The watcher may not be running or has not generated any logs yet."
    fi
    press_any_key
}

# --- Watcher Submenu Help ---
watcher_submenu_help() {
    clear
    print_info "================= Coordinated Restart Watcher Help ================="
    echo "This submenu lets you manage the coordinated restart watcher for this tunnel."
    echo
    print_info "What the watcher does:"
    echo "• Monitors tunnel logs for error patterns (e.g., ERROR|FATAL)"
    echo "• When an error is detected, coordinates a restart with the remote side"
    echo "• Uses a secure netcat-based protocol for communication"
    echo "• Automatically restarts both sides in a coordinated manner"
    echo
    print_info "Configuration requirements:"
    echo "• Listen port: Where this side receives restart requests from remote"
    echo "• Remote port: Where this side sends restart requests to remote"
    echo "• Secret: Must be identical on both sides (client and server)"
    echo "• Error pattern: Regex pattern to trigger restarts (default: ERROR|FATAL)"
    echo "• Delays: Time to wait before restarting each side"
    echo
    print_warning "IMPORTANT: Port configuration must be opposite on both sides!"
    echo "  If this side listens on 45679, remote must send to 45679"
    echo "  If this side sends to 45680, remote must listen on 45680"
    echo
    echo "Menu options:"
    echo " 1. Enable watcher: Set up and start the watcher background process."
    echo " 2. Disable watcher: Stop and remove the watcher background process."
    echo " 3. Edit watcher config: Change error pattern, delays, secret, and ports."
    echo " 4. Show watcher status: View watcher script content."
    echo " 5. Show watcher logs: View recent logs for the watcher."
    echo " 6. Test watcher: Send or receive a test restart signal."
    echo " 0. Back: Return to tunnel management."
    press_any_key
}

# --- Technical Enhancement Functions ---

# Show health and performance metrics for a tunnel
show_health_and_performance() {
    local tunnel_name="$1"
    local service="$2"
    
    clear
    print_info "=== Health Check & Performance Metrics ==="
    echo
    
    # Initialize logging if not already done
    init_logging
    
    # Check tunnel health
    print_info "--- Tunnel Health Status ---"
    local health_status
    health_status=$(check_tunnel_health "$tunnel_name")
    
    case "$health_status" in
        "running")
            print_success "✓ Tunnel is running"
            ;;
        "dead")
            print_error "✗ Tunnel process is dead"
            ;;
        "not_started")
            print_warning "⚠ Tunnel is not started"
            ;;
        *)
            print_warning "? Tunnel status unknown"
            ;;
    esac
    
    # Check system resources
    echo
    print_info "--- System Resources ---"
    check_system_resources
    
    # Show performance metrics
    echo
    print_info "--- Performance Metrics ---"
    if [[ -f "$PERFORMANCE_LOG_FILE" ]]; then
        local recent_ops
        recent_ops=$(tail -n 10 "$PERFORMANCE_LOG_FILE" 2>/dev/null)
        if [[ -n "$recent_ops" ]]; then
            echo "Recent operations:"
            echo "$recent_ops" | while IFS= read -r line; do
                if [[ "$line" =~ \"operation\":\"([^\"]+)\",\"duration\":([0-9]+),\"success\":(true|false) ]]; then
                    local op="${BASH_REMATCH[1]}"
                    local duration="${BASH_REMATCH[2]}"
                    local success="${BASH_REMATCH[3]}"
                    local status_icon=$([[ "$success" == "true" ]] && echo "✓" || echo "✗")
                    echo "  $status_icon $op: ${duration}s"
                fi
            done
        else
            echo "No performance data available"
        fi
    else
        echo "No performance data available"
    fi
    
    # Show health history
    echo
    print_info "--- Health History ---"
    if [[ -f "$HEALTH_LOG_FILE" ]]; then
        local recent_health
        recent_health=$(tail -n 5 "$HEALTH_LOG_FILE" 2>/dev/null)
        if [[ -n "$recent_health" ]]; then
            echo "Recent health checks:"
            echo "$recent_health" | while IFS= read -r line; do
                if [[ "$line" =~ \"timestamp\":\"([^\"]+)\",\"tunnel\":\"([^\"]+)\",\"status\":\"([^\"]+)\" ]]; then
                    local timestamp="${BASH_REMATCH[1]}"
                    local tunnel="${BASH_REMATCH[2]}"
                    local status="${BASH_REMATCH[3]}"
                    local status_icon
                    case "$status" in
                        "running") status_icon="✓" ;;
                        "dead") status_icon="✗" ;;
                        "not_started") status_icon="⚠" ;;
                        *) status_icon="?" ;;
                    esac
                    echo "  $status_icon $timestamp: $status"
                fi
            done
        else
            echo "No health history available"
        fi
    else
        echo "No health history available"
    fi
    
    # Optimize process priority
    echo
    print_info "--- Process Optimization ---"
    optimize_process_priority "$tunnel_name"
    
    press_any_key
}

# Validate tunnel configuration
validate_tunnel_config() {
    local config_file="$1"
    
    if [[ ! -f "$config_file" ]]; then
        print_error "Configuration file not found: $config_file"
        press_any_key
        return 1
    fi
    
    # Initialize logging if not already done
    init_logging
    
    # Run comprehensive validation using the validation module
    validate_config_detailed "$config_file"
    return $?
}

# Graceful restart with health checks and error recovery
graceful_restart_with_ui() {
    local tunnel_name="$1"
    local service="backhaul-$tunnel_name"
    
    clear
    print_info "=== Graceful Restart ==="
    echo
    
    # Initialize logging if not already done
    init_logging
    
    print_info "Starting graceful restart for tunnel: $tunnel_name"
    echo
    
    # Check current health
    print_info "--- Pre-restart Health Check ---"
    local pre_health
    pre_health=$(check_tunnel_health "$tunnel_name")
    print_info "Current status: $pre_health"
    
    # Check system resources
    print_info "--- System Resources ---"
    check_system_resources
    
    # Perform graceful restart with performance tracking
    echo
    print_info "--- Performing Graceful Restart ---"
    with_performance_tracking "graceful_restart" graceful_restart "$tunnel_name"
    local restart_result=$?
    
    # Post-restart health check
    echo
    print_info "--- Post-restart Health Check ---"
    sleep 3  # Give service time to stabilize
    local post_health
    post_health=$(check_tunnel_health "$tunnel_name")
    print_info "New status: $post_health"
    
    # Summary
    echo
    print_info "--- Restart Summary ---"
    if [[ $restart_result -eq 0 && "$post_health" == "running" ]]; then
        print_success "\u2713 Graceful restart completed successfully"
        print_info "Tunnel is healthy and running"
    else
        print_error "\u2717 Graceful restart failed or tunnel is unhealthy"
        print_info "Current status: $post_health"
        
        if confirm_action "Would you like to attempt recovery?" "y"; then
            print_info "Attempting error recovery..."
            attempt_error_recovery "tunnel_start" "Graceful restart failed"
        fi
    fi
    
    press_any_key
    return $restart_result
}

create_tunnel() {
    local tunnel_name
    local server_ip
    local server_port
    local local_port
    local protocol
    
    # Rate limiting check
    if ! rate_limit_check "create_tunnel" 5; then
        echo "⚠ Rate limit exceeded. Please wait before creating another tunnel."
        return 1
    fi
    
    echo "=== Create New Tunnel ==="
    echo "💡 Tip: Use descriptive names like 'office-vpn' or 'home-connection'"
    
    # Input validation with sanitization
    while true; do
        read -p "Enter tunnel name: " tunnel_name
        tunnel_name=$(sanitize_input "$tunnel_name" 50)
        
        if [ -z "$tunnel_name" ]; then
            echo "❌ Tunnel name cannot be empty"
            continue
        fi
        
        if [[ ! "$tunnel_name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
            echo "❌ Tunnel name can only contain letters, numbers, hyphens, and underscores"
            continue
        fi
        
        if [ -d "$TUNNEL_DIR/$tunnel_name" ]; then
            echo "❌ Tunnel '$tunnel_name' already exists"
            continue
        fi
        
        break
    done
    
    while true; do
        read -p "Enter server IP address: " server_ip
        server_ip=$(sanitize_input "$server_ip" 15)
        
        if ! validate_ip "$server_ip"; then
            echo "❌ Invalid IP address format"
            continue
        fi
        
        break
    done
    
    while true; do
        read -p "Enter server port (1-65535): " server_port
        server_port=$(sanitize_input "$server_port" 5)
        
        if ! validate_port "$server_port"; then
            echo "❌ Invalid port number (must be 1-65535)"
            continue
        fi
        
        break
    done
    
    while true; do
        read -p "Enter local port (1-65535): " local_port
        local_port=$(sanitize_input "$local_port" 5)
        
        if ! validate_port "$local_port"; then
            echo "❌ Invalid port number (must be 1-65535)"
            continue
        fi
        
        # Check if port is already in use
        if is_port_in_use "$local_port"; then
            echo "❌ Port $local_port is already in use"
            continue
        fi
        
        break
    done
    
    echo "Select protocol:"
    echo "1) TCP"
    echo "2) UDP"
    read -p "Enter choice (1-2): " protocol_choice
    
    case $protocol_choice in
        1) protocol="tcp" ;;
        2) protocol="udp" ;;
        *) protocol="tcp" ;;
    esac
    
    # Performance monitoring wrapper
    monitor_performance "create_tunnel_impl" "$tunnel_name" "$server_ip" "$server_port" "$local_port" "$protocol"
}

create_tunnel_impl() {
    local tunnel_name="$1"
    local server_ip="$2"
    local server_port="$3"
    local local_port="$4"
    local protocol="$5"
    
    local tunnel_dir="$TUNNEL_DIR/$tunnel_name"
    local config_file="$tunnel_dir/config"
    
    # Create tunnel directory with secure permissions
    mkdir -p "$tunnel_dir"
    harden_permissions "$tunnel_dir"
    
    # Create configuration with secure write
    local config_content="TUNNEL_NAME=$tunnel_name
SERVER_IP=$server_ip
SERVER_PORT=$server_port
LOCAL_PORT=$local_port
PROTOCOL=$protocol
CREATED_DATE=$(date '+%Y-%m-%d %H:%M:%S')
STATUS=stopped"
    
    secure_write "$config_file" "$config_content"
    secure_config_file "$config_file"
    
    # Create tunnel script with secure permissions
    local tunnel_script="$tunnel_dir/tunnel.sh"
    cat > "$tunnel_script" << EOF
#!/bin/bash
# Secure tunnel script for $tunnel_name
# Auto-generated by EasyBackhaul

source "$SCRIPT_DIR/globals.sh"
source "$SCRIPT_DIR/helpers.sh"

TUNNEL_NAME="$tunnel_name"
SERVER_IP="$server_ip"
SERVER_PORT="$server_port"
LOCAL_PORT="$local_port"
PROTOCOL="$protocol"

# Security: Drop privileges if running as root
if [ "\$(id -u)" -eq 0 ]; then
    exec su -s /bin/bash -c "\$0 \$*" "\$SUDO_USER"
fi

# Rate limiting
if ! rate_limit_check "tunnel_connect" 10; then
    log_message "ERROR" "Rate limit exceeded for tunnel $tunnel_name"
    exit 1
fi

# Input validation
if ! validate_ip "\$SERVER_IP" || ! validate_port "\$SERVER_PORT" || ! validate_port "\$LOCAL_PORT"; then
    log_message "ERROR" "Invalid configuration for tunnel $tunnel_name"
    exit 1
fi

# Secure logging
secure_log_message "INFO" "Starting tunnel $tunnel_name"

# Start tunnel with performance monitoring
monitor_performance "start_tunnel_connection" "\$SERVER_IP" "\$SERVER_PORT" "\$LOCAL_PORT" "\$PROTOCOL"
EOF
    
    chmod 700 "$tunnel_script"
    
    # Create UFW rules
    create_ufw_rules "$tunnel_name" "$server_ip" "$server_port" "$local_port" "$protocol"
    
    # Update main config
    update_config_file "$tunnel_name" "$server_ip" "$server_port" "$local_port" "$protocol"
    
    echo "✅ Tunnel '$tunnel_name' created successfully"
    echo "📁 Location: $tunnel_dir"
    echo "🔒 Permissions hardened for security"
    
    # Security audit
    audit_security
    
    # Performance optimization
    cleanup_temp_files
}

delete_tunnel() {
    local tunnel_name="$1"
    
    if [ -z "$tunnel_name" ]; then
        echo "❌ Tunnel name is required"
        return 1
    fi
    
    # Input sanitization
    tunnel_name=$(sanitize_input "$tunnel_name" 50)
    
    local tunnel_dir="$TUNNEL_DIR/$tunnel_name"
    
    if [ ! -d "$tunnel_dir" ]; then
        echo "❌ Tunnel '$tunnel_name' not found"
        return 1
    fi
    
    # Confirm deletion with security warning
    echo "⚠ SECURITY WARNING: This will permanently delete tunnel '$tunnel_name'"
    echo "   - All configuration files will be securely erased"
    echo "   - UFW rules will be removed"
    echo "   - Any running processes will be terminated"
    echo ""
    read -p "Type 'DELETE' to confirm: " confirmation
    
    if [ "$confirmation" != "DELETE" ]; then
        echo "❌ Deletion cancelled"
        return 1
    fi
    
    # Performance monitoring wrapper
    monitor_performance "delete_tunnel_impl" "$tunnel_name"
}

delete_tunnel_impl() {
    local tunnel_name="$1"
    local tunnel_dir="$TUNNEL_DIR/$tunnel_name"
    
    # Stop tunnel if running
    stop_tunnel "$tunnel_name" 2>/dev/null
    
    # Remove UFW rules
    remove_ufw_rules "$tunnel_name"
    
    # Securely delete all files
    if [ -d "$tunnel_dir" ]; then
        find "$tunnel_dir" -type f -exec secure_delete {} \;
        rm -rf "$tunnel_dir"
    fi
    
    # Remove from main config
    remove_from_config "$tunnel_name"
    
    # Clean up watcher files if they exist
    cleanup_watcher_files "$tunnel_name"
    
    echo "✅ Tunnel '$tunnel_name' securely deleted"
    
    # Performance optimization
    cleanup_temp_files
}

start_tunnel() {
    local tunnel_name="$1"
    
    if [ -z "$tunnel_name" ]; then
        echo "❌ Tunnel name is required"
        return 1
    fi
    
    # Input sanitization
    tunnel_name=$(sanitize_input "$tunnel_name" 50)
    
    # Rate limiting check
    if ! rate_limit_check "start_tunnel" 10; then
        echo "⚠ Rate limit exceeded. Please wait before starting another tunnel."
        return 1
    fi
    
    local tunnel_dir="$TUNNEL_DIR/$tunnel_name"
    local config_file="$tunnel_dir/config"
    local tunnel_script="$tunnel_dir/tunnel.sh"
    
    if [ ! -d "$tunnel_dir" ]; then
        echo "❌ Tunnel '$tunnel_name' not found"
        return 1
    fi
    
    if [ ! -f "$config_file" ]; then
        echo "❌ Configuration file not found"
        return 1
    fi
    
    # Load configuration with validation
    source "$config_file"
    
    if ! validate_ip "$SERVER_IP" || ! validate_port "$SERVER_PORT" || ! validate_port "$LOCAL_PORT"; then
        echo "❌ Invalid configuration detected"
        return 1
    fi
    
    # Check if already running
    if is_tunnel_running "$tunnel_name"; then
        echo "⚠ Tunnel '$tunnel_name' is already running"
        return 0
    fi
    
    # Performance monitoring wrapper
    monitor_performance "start_tunnel_impl" "$tunnel_name"
}

start_tunnel_impl() {
    local tunnel_name="$1"
    local tunnel_dir="$TUNNEL_DIR/$tunnel_name"
    local tunnel_script="$tunnel_dir/tunnel.sh"
    
    # Security: Verify script permissions
    if [ "$(stat -c %a "$tunnel_script" 2>/dev/null)" != "700" ]; then
        echo "❌ Security: Tunnel script has insecure permissions"
        chmod 700 "$tunnel_script"
    fi
    
    # Start tunnel in background with secure logging
    nohup "$tunnel_script" > "$tunnel_dir/tunnel.log" 2>&1 &
    local pid=$!
    
    # Create PID file with secure permissions
    echo "$pid" > "$tunnel_dir/tunnel.pid"
    chmod 600 "$tunnel_dir/tunnel.pid"
    
    # Update status
    update_tunnel_status "$tunnel_name" "running"
    
    # Secure logging
    secure_log_message "INFO" "Started tunnel $tunnel_name (PID: $pid)"
    
    echo "✅ Tunnel '$tunnel_name' started successfully"
    echo "📊 PID: $pid"
    echo "📝 Logs: $tunnel_dir/tunnel.log"
    
    # Performance monitoring
    echo "💻 System resources: $(get_system_resources)"
}

stop_tunnel() {
    local tunnel_name="$1"
    
    if [ -z "$tunnel_name" ]; then
        echo "❌ Tunnel name is required"
        return 1
    fi
    
    # Input sanitization
    tunnel_name=$(sanitize_input "$tunnel_name" 50)
    
    local tunnel_dir="$TUNNEL_DIR/$tunnel_name"
    local pid_file="$tunnel_dir/tunnel.pid"
    
    if [ ! -d "$tunnel_dir" ]; then
        echo "❌ Tunnel '$tunnel_name' not found"
        return 1
    fi
    
    if [ ! -f "$pid_file" ]; then
        echo "⚠ Tunnel '$tunnel_name' is not running"
        return 0
    fi
    
    # Performance monitoring wrapper
    monitor_performance "stop_tunnel_impl" "$tunnel_name"
}

stop_tunnel_impl() {
    local tunnel_name="$1"
    local tunnel_dir="$TUNNEL_DIR/$tunnel_name"
    local pid_file="$tunnel_dir/tunnel.pid"
    
    local pid=$(cat "$pid_file" 2>/dev/null)
    
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        # Graceful shutdown
        kill -TERM "$pid" 2>/dev/null
        
        # Wait for graceful shutdown
        local count=0
        while kill -0 "$pid" 2>/dev/null && [ $count -lt 10 ]; do
            sleep 1
            ((count++))
        done
        
        # Force kill if still running
        if kill -0 "$pid" 2>/dev/null; then
            kill -KILL "$pid" 2>/dev/null
            echo "⚠ Force killed tunnel process"
        fi
    fi
    
    # Securely delete PID file
    secure_delete "$pid_file"
    
    # Update status
    update_tunnel_status "$tunnel_name" "stopped"
    
    # Secure logging
    secure_log_message "INFO" "Stopped tunnel $tunnel_name"
    
    echo "✅ Tunnel '$tunnel_name' stopped successfully"
    
    # Performance optimization
    optimize_memory_usage
} 