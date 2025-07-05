#!/bin/bash
# tunnel_mgmt.sh
# List/manage tunnels, single tunnel management, connection test 

# Note: When built into easybackhaul.sh, all modules are concatenated together
# No need to source separate files as they're already included

# WARNING: Do not use a global CONFIG_FILE variable. Always pass config file paths explicitly to functions.

# --- Tunnel Management ---
manage_tunnels() {
    push_menu "manage_tunnels"
    # Help function for tunnel list
    tunnel_list_help() {
        clear
        print_server_info_banner_minimal
        print_info "================= Tunnel Management Help ================="
        echo "This menu lets you manage your Backhaul tunnels."
        echo
        echo "Options:"
        echo "- Select a tunnel number to manage that specific tunnel"
        echo "- Each tunnel shows its current status (Running/Stopped)"
        echo "- From the tunnel menu, you can start, stop, restart, view logs, etc."
        echo "- Use 0 to return to the main menu"
        echo "- For more details, see the main help from the main menu."
        echo "================================================================"
        press_any_key
    }

    while true; do
        clear
        print_server_info_banner
        print_info "--- Available Backhaul Tunnels ---"
        echo
        mapfile -t services < <(systemctl list-unit-files --type=service 'backhaul-*.service' --no-legend | awk '{print $1}' | grep -v 'backhaul-watcher-')
        if [[ ${#services[@]} -eq 0 ]]; then
            print_warning "No Backhaul tunnels found. Use 'Configure a New Tunnel' first."
            press_any_key
            return_to_previous_menu
            return
        fi
        
        local i=1
        for service in "${services[@]}"; do
            local status
            if systemctl is-active --quiet "$service"; then
                status="running"
            else
                status="stopped"
            fi
            local suffix=$(echo "$service" | sed 's/backhaul-\(.*\)\.service/\1/')
            echo " $i. $suffix ($status)"
            ((i++))
        done
        echo
        print_info "----------------------------------------------------------------"
        print_menu_footer
        menu_loop 0 $((i-1)) "?" "tunnel_list_help" "Select tunnel to manage [0-$((i-1)), ? for help]"
        case $choice in
            0) return_to_previous_menu; return ;;
            *)
                local selected_service="${services[$((choice-1))]}"
                local suffix=$(echo "$selected_service" | sed 's/backhaul-\(.*\)\.service/\1/')
                manage_specific_tunnel "$selected_service" "$suffix"
                ;;
        esac
    done
}

manage_specific_tunnel() {
    local service=$1 suffix=$2
    local config_file="$CONFIG_DIR/config-${suffix}.toml"
    
    # Help function for specific tunnel management
    tunnel_management_help() {
        clear
        print_server_info_banner_minimal
        print_info "================= Tunnel Management Help ================="
        echo "This menu lets you manage a specific Backhaul tunnel/service."
        echo
        echo " 1. Start: Start the selected tunnel service."
        echo " 2. Stop: Stop the tunnel service."
        echo " 3. Restart: Restart the tunnel service."
        echo " 4. View Live Logs: View real-time tunnel logs."
        echo " 5. View Configuration: View the TOML config (press q to exit)."
        echo " 6. Edit Configuration: Edit config in nano, then optionally restart."
        echo " 7. Change Log Level: Adjust log verbosity (debug/info/warn/error)."
        echo " 8. Test Connection: Test if the tunnel is reachable."
        echo " 9. Manage Restart Watcher: Set up automatic restart on errors."
        echo "10. Validate Configuration: Check config syntax and validate settings."
        echo "11. Show Tunnel Info: Display tunnel details and status."
        echo "12. Health Check & Performance: Monitor tunnel health and performance."
        echo "13. Delete Tunnel: Permanently remove this tunnel and all its data."
        echo " 0. Back to Tunnel List: Return to the previous menu."
        echo
        print_info "Tips:"
        echo "- Use Ctrl+C to exit log views and return to this menu."
        echo "- Use 'q' to exit configuration view."
        echo "- For more details, see the main help from the main menu."
        echo "================================================================"
        press_any_key
    }

    while true; do
        # Show tunnel status
        local status
        if systemctl is-active --quiet "$service"; then
            status="running"
        else
            status="stopped"
        fi
        
        clear
        print_server_info_banner_minimal
        print_info "--- Managing Tunnel: $suffix ---"
        print_info "Service: $service"
        print_tunnel_status "$suffix" "$status"
        
        # Show tunnel info
        if [ -f "$config_file" ]; then
            local cert_path=$(grep '^tls_cert' "$config_file" | cut -d'"' -f2)
            local key_path=$(grep '^tls_key' "$config_file" | cut -d'"' -f2)
            if [[ -n "$cert_path" && -n "$key_path" ]]; then
                print_success "TLS: Configured"
            else
                print_warning "TLS: Not configured"
            fi
        fi
        
        echo
        print_info "Select an option:"
        echo " 1. Start Tunnel"
        echo " 2. Stop Tunnel"
        echo " 3. Restart Tunnel"
        echo " 4. View Live Logs"
        echo " 5. View Configuration"
        echo " 6. Edit Configuration"
        echo " 7. Change Log Level"
        echo " 8. Test Connection"
        echo " 9. Manage Restart Watcher"
        echo "10. Validate Configuration"
        echo "11. Show Tunnel Info"
        echo "12. Health Check & Performance"
        echo "13. Delete Tunnel"
        echo
        print_info "----------------------------------------------------------------"
        print_menu_footer
        
        menu_loop 0 13 "?" "tunnel_management_help" "Select an option [0-13, ? for help]"
        case $choice in
            1) 
                if with_spinner "Starting tunnel" systemctl start "$service"; then
                    print_success "Tunnel started successfully. You can now connect to this tunnel."
                else
                    print_error "Failed to start tunnel. Check logs for details."
                fi
                press_any_key
                ;;
            2) 
                if with_spinner "Stopping tunnel" systemctl stop "$service"; then
                    print_success "Tunnel stopped. Connections will be refused until restarted."
                else
                    print_error "Failed to stop tunnel. Check logs for details."
                fi
                press_any_key
                ;;
            3) 
                if with_spinner "Restarting tunnel" systemctl restart "$service"; then
                    print_success "Tunnel restarted. Check logs if you encounter issues."
                else
                    print_error "Failed to restart tunnel. Check logs for details."
                fi
                press_any_key
                ;;
            4)
                print_info "--- Live Logs for Tunnel: $suffix ---"
                echo
                echo "Select log viewing mode:"
                echo " 1) Live follow (Ctrl+C to exit log view and return to menu)"
                echo " 2) Interactive (scroll/search, press q to quit, F to follow live, Ctrl+C to exit log view and return to menu)"
                echo " 0) Cancel"
                echo
                while true; do
                    read -r -p "Select [1-2, 0 to cancel, default 2]: " log_mode
                    log_mode=${log_mode:-2}
                    
                    case $log_mode in
                        0) break ;;
                        1|2) 
                            if [[ "$log_mode" == "1" ]]; then
                                                            print_warning "You are about to enter live log view. Press Ctrl+C to exit log view and return to the menu."
                        else
                            print_warning "You are about to enter interactive log view. Use arrow keys to navigate, / to search, F to follow live, q to quit. Press Ctrl+C to exit log view and return to the menu."
                            fi
                            press_any_key
                            
                            if [[ "$log_mode" == "1" ]]; then
                                # Run log viewer in subshell with default SIGINT
                                (journalctl -u "$service" -f --no-pager)
                            else
                                (journalctl -u "$service" --no-pager | less -R)
                            fi
                            break
                            ;;
                        *) 
                            print_warning "Invalid option. Please enter 1, 2, or 0."
                            press_any_key
                            ;;
                    esac
                done
                ;;
            5)
                print_info "--- Configuration for Tunnel: $suffix ---"
                echo
                print_info "Viewing configuration. Press 'q' to exit and return to the menu."
                sleep 1
                less "$config_file"
                ;;
            6)
                                if [ ! -f "$config_file" ]; then
                    print_error "Config file not found for this tunnel. Please check your configuration and try again."
                    press_any_key
                    continue
                fi
                
                backup_config "$config_file"
                nano "$config_file"
                if confirm_action "Restart tunnel to apply changes?" "y"; then
                    if with_spinner "Restarting tunnel" systemctl restart "$service"; then
                                            print_success "Tunnel restarted with new configuration."
                else
                    print_error "Failed to restart tunnel. Check logs for details."
                fi
                fi
                press_any_key
                ;;
            7)
                print_info "--- Change Log Level for Tunnel: $suffix ---"
                echo
                local current_level=$(grep -E '^\s*log_level\s*=\s*"' "$config_file" | head -n1 | cut -d'"' -f2)
                print_info "Current log level: ${current_level:-info}"
                echo
                echo "Available log levels:"
                echo "  debug: Detailed debugging information."
                echo "  info:  Normal operation messages (default)."
                echo "  warn:  Warning messages only."
                echo "  error: Error messages only."
                echo "  cancel: Cancel log level change."
                echo
                select new_level in debug info warn error cancel; do
                    case $new_level in
                        debug|info|warn|error)
                            update_config_value "$config_file" "log_level" "$new_level"
                            print_success "Log level updated to $new_level."
                            if confirm_action "Restart tunnel to apply new log level?" "y"; then
                                if with_spinner "Restarting tunnel" systemctl restart "$service"; then
                                    print_success "Tunnel restarted with new log level."
                                else
                                    print_error "Failed to restart tunnel. Check logs for details."
                                fi
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
            press_any_key
                ;;
            8) test_connection "$config_file"; press_any_key;;
            9) manage_watcher_submenu "$service" "$suffix" "$config_file" ;;
            10) validate_tunnel_config "$config_file"; press_any_key ;;
            11)
                clear
                print_info "--- Tunnel Information: $suffix ---"
                echo
                echo "  - Service: $service"
                echo "  - Config: $config_file"
                echo "  - Status: $(systemctl is-active "$service" 2>/dev/null || echo "inactive")"
                echo "  - Enabled: $(systemctl is-enabled "$service" 2>/dev/null || echo "disabled")"
                press_any_key
                ;;
            12) show_tunnel_health_and_performance "$service" "$suffix" ;;
            13)
                print_info "--- Delete Tunnel: $suffix ---"
                echo
                print_warning "WARNING: This will permanently delete the tunnel and all its data!"
                echo
                echo "The following will be deleted:"
                echo "  - Service: $service"
                echo "  - Configuration: $config_file"
                echo "  - Logs and temporary files"
                echo "  - UFW rules (if any)"
                echo
                if confirm_action "Are you sure you want to PERMANENTLY delete this tunnel?" "n"; then
                    print_warning "Deleting tunnel $suffix..."
                    
                    # Stop and disable service
                    with_spinner "Stopping and disabling service" systemctl stop "$service" 2>/dev/null && systemctl disable "$service" 2>/dev/null
                    
                    # Remove service file
                    local service_file="$SERVICE_DIR/$service"
                    rm -f "$service_file"
                    
                    # Remove config file
                    rm -f "$config_file"
                    
                    # Clean up watcher if exists
                    local watcher_script="/tmp/backhaul-watcher-${suffix}.sh"
                    local watcher_pid_file="/tmp/backhaul-watcher-${suffix}.pid"
                    local watcher_log="/tmp/backhaul-watcher-${suffix}.log"
                    
                    if [[ -f "$watcher_pid_file" ]]; then
                        local watcher_pid=$(cat "$watcher_pid_file")
                        if [[ -n "$watcher_pid" ]]; then
                            kill "$watcher_pid" 2>/dev/null
                        fi
                        rm -f "$watcher_pid_file"
                    fi
                    
                    rm -f "$watcher_script" "$watcher_log"
                    pkill -f "backhaul-watcher-${suffix}" 2>/dev/null
                    
                    # Remove UFW rules
                    manage_ufw_delete "$suffix"
                    
                    # Reload systemd
                    systemctl daemon-reload
                    
                    print_success "Tunnel $suffix has been completely deleted. You may now create a new tunnel or exit."
                    press_any_key
                    return
                else
                    print_info "Tunnel deletion cancelled."
                    press_any_key
                fi
                ;;
            \?)
                clear
                print_info "================= Tunnel Management Help ================="
                echo "This menu lets you manage a specific Backhaul tunnel."
                echo
                echo "Options:"
                echo " 1. Start Tunnel: Start the tunnel service"
                echo " 2. Stop Tunnel: Stop the tunnel service"
                echo " 3. Restart Tunnel: Restart the tunnel service"
                echo " 4. View Live Logs: View real-time tunnel logs"
                echo " 5. View Configuration: View the TOML config (press q to exit)."
                echo " 6. Edit Configuration: Edit the TOML config in nano editor"
                echo " 7. Change Log Level: Set logging verbosity (debug, info, warn, error)"
                echo " 8. Test Connection: Test if the tunnel can connect to its remote"
                echo " 9. Manage Restart Watcher: Configure automatic restart on errors"
                echo "10. Validate Configuration: Check config syntax and settings"
                echo "11. Show Tunnel Info: Display tunnel details and status"
                echo "12. Health Check & Performance: Monitor tunnel health, resource usage, and performance metrics."
                echo "13. Delete Tunnel: Permanently remove this tunnel and all its data"
                echo " 0. Back to Tunnel List: Return to the previous menu."
                echo
                echo "- Use Ctrl+C to exit log views and return to this menu."
                echo "- Configuration changes require a restart to take effect."
                echo "- The restart watcher can automatically restart tunnels on errors."
                press_any_key
                ;;
            0) return ;;
            *)
                print_warning "Invalid option. Please enter 0-13 or ? for help."
                press_any_key
                ;;
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
    push_menu "manage_watcher_submenu"
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
        echo "7. Show watcher secret"
        echo "?. Help"
        echo "0. Back"
        read -r -p "Select [0-7, ? for help]: " wopt
        case $wopt in
            1) enable_watcher "$service" "$suffix" "$config_file" ;;
            2) disable_watcher "$service" "$suffix" "$config_file" ;;
            3) edit_watcher_config "$service" "$suffix" "$config_file" ;;
            4) show_watcher_status "$service" "$suffix" "$config_file" ;;
            5) show_watcher_logs "$service" "$suffix" "$config_file" ;;
            6) test_watcher "$service" "$suffix" "$config_file" ;;
            7) show_watcher_secret "$config_file" ;;
            \?) watcher_submenu_help ;;
            0) return_to_previous_menu; return ;;
            *) print_warning "Invalid option."; press_any_key ;;
        esac
    done
}

# --- Watcher Submenu Help ---
watcher_submenu_help() {
    clear
    print_info "=== Watcher Help ==="
    echo
    print_info "The Coordinated Restart Watcher monitors tunnel services and"
    print_info "coordinates restarts between client and server sides."
    echo
    print_info "Features:"
    echo "  • Automatic error detection in service logs"
    echo "  • Coordinated restart between both sides"
    echo "  • Configurable restart delays and retry limits"
    echo "  • Secure communication with shared secrets"
    echo "  • Port conflict detection and resolution"
    echo
    print_info "Setup Process:"
    echo "  1. Server generates a shared secret"
    echo "  2. Client enters the same secret"
    echo "  3. Both sides configure ports and delays"
    echo "  4. Watcher starts monitoring automatically"
    echo
    print_info "Communication:"
    echo "  • Uses netcat for simple TCP communication"
    echo "  • Authenticates with shared secret"
    echo "  • Sends restart requests and acknowledgments"
    echo "  • Handles network failures gracefully"
    echo
    press_any_key
}

# --- Technical Enhancement Functions ---

# Show health and performance metrics for a tunnel
show_tunnel_health_and_performance() {
    local tunnel_name="$1"
    local service="$2"
    
    clear
    print_server_info_banner_minimal
    print_info "=== Health Check & Performance Metrics ==="
    print_info "Tunnel: $tunnel_name"
    echo
    
    # Initialize logging if not already done
    init_logging
    
    # Check tunnel health
    print_info "--- Tunnel Health Status ---"
    local health_status
    health_status=$(check_tunnel_health "$tunnel_name")
    
    case "$health_status" in
        "running")
            print_success "Tunnel is running"
            ;;
        "dead")
            print_error "Tunnel process is dead"
            ;;
        "not_started")
            print_warning "Tunnel is not started"
            ;;
        *)
            print_warning "Tunnel status unknown"
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
                    if [[ "$success" == "true" ]]; then
                        print_success "$op: ${duration}s"
                    else
                        print_error "$op: ${duration}s"
                    fi
                fi
            done
        else
            print_warning "No performance data available in log file"
        fi
    else
        print_warning "Performance log file not found: $PERFORMANCE_LOG_FILE"
        print_info "Performance tracking will be available after the first operation"
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
                        "running") status_icon="Running" ;;
                        "dead") status_icon="Dead" ;;
                        "not_started") status_icon="Not Started" ;;
                        *) status_icon="Unknown" ;;
                    esac
                    print_status_with_icon "$status" "$timestamp"
                fi
            done
        else
            print_warning "No health history available in log file"
        fi
    else
        print_warning "Health log file not found: $HEALTH_LOG_FILE"
        print_info "Health tracking will be available after the first health check"
    fi
    
    # Optimize process priority
    echo
    print_info "--- Process Optimization ---"
    optimize_process_priority "$tunnel_name"
    
    echo
    print_info "Press any key to return to tunnel management..."
    read -n 1 -s
}

# Validate tunnel configuration - using comprehensive validation from validation.sh

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
        print_success "Graceful restart completed successfully"
        print_info "Tunnel is healthy and running"
    else
        print_error "Graceful restart failed or tunnel is unhealthy"
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
        print_warning "Rate limit exceeded. Please wait before creating another tunnel."
        return 1
    fi
    
    echo "=== Create New Tunnel ==="
    echo "💡 Tip: Use descriptive names like 'office-vpn' or 'home-connection'"
    
    # Input validation with sanitization
    tunnel_name=$(validate_tunnel_name "check_exists")
    server_ip=$(validate_ip_with_prompt)
    server_port=$(validate_port_with_prompt "Enter server port (1-65535): ")
    local_port=$(validate_port_with_prompt "Enter local port (1-65535): " "check_usage")
    
    echo "Select protocol:"
    echo "1) TCP"
    echo "2) UDP"
            read -r -p "Select an option [1-2, ? for help]: " protocol_choice
    
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

# Note: This script is standalone and doesn't need to source other modules

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
if ! validate_tunnel_parameters "\$SERVER_IP" "\$SERVER_PORT" "\$LOCAL_PORT" "\$TUNNEL_NAME"; then
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
    print_success "Tunnel '$tunnel_name' created successfully"
    echo "📁 Location: $tunnel_dir"
    echo "🔒 Permissions hardened for security"
    
    # Security audit
    audit_security
    
    # Performance optimization
    cleanup_temp_files
}

start_tunnel() {
    local tunnel_name="$1"
    
    if [ -z "$tunnel_name" ]; then
        print_error "Tunnel name is required"
        return 1
    fi
    
    # Input sanitization
    tunnel_name=$(sanitize_input "$tunnel_name" 50)
    
    # Rate limiting check
    if ! rate_limit_check "start_tunnel" 10; then
        print_warning "Rate limit exceeded. Please wait before starting another tunnel."
        return 1
    fi
    
    local tunnel_dir="$TUNNEL_DIR/$tunnel_name"
    local config_file="$tunnel_dir/config"
    local tunnel_script="$tunnel_dir/tunnel.sh"
    
    if [ ! -d "$tunnel_dir" ]; then
        print_error "Tunnel '$tunnel_name' not found"
        return 1
    fi
    
    if [ ! -f "$config_file" ]; then
        print_error "Configuration file not found"
        return 1
    fi
    
    # Load configuration with validation
    source "$config_file"
    
    if ! validate_tunnel_parameters "$SERVER_IP" "$SERVER_PORT" "$LOCAL_PORT" "$tunnel_name"; then
        print_error "Invalid configuration detected"
        return 1
    fi
    
    # Check if already running
    if is_tunnel_running "$tunnel_name"; then
        print_warning "Tunnel '$tunnel_name' is already running"
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
        print_error "Security: Tunnel script has insecure permissions"
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
    print_success "Tunnel '$tunnel_name' started successfully"
    echo "📊 PID: $pid"
    echo "📝 Logs: $tunnel_dir/tunnel.log"
    
    # Performance monitoring
    echo "💻 System resources: $(get_system_resources)"
}

stop_tunnel() {
    local tunnel_name="$1"
    
    if [ -z "$tunnel_name" ]; then
        print_error "Tunnel name is required"
        return 1
    fi
    
    # Input sanitization
    tunnel_name=$(sanitize_input "$tunnel_name" 50)
    
    local tunnel_dir="$TUNNEL_DIR/$tunnel_name"
    local pid_file="$tunnel_dir/tunnel.pid"
    
    if [ ! -d "$tunnel_dir" ]; then
        print_error "Tunnel '$tunnel_name' not found"
        return 1
    fi
    
    if [ ! -f "$pid_file" ]; then
        print_warning "Tunnel '$tunnel_name' is not running"
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
            print_warning "Force killed tunnel process"
        fi
    fi
    
    # Securely delete PID file
    secure_delete "$pid_file"
    print_success "Tunnel '$tunnel_name' stopped successfully"
    
    # Performance optimization
    optimize_memory_usage
} 