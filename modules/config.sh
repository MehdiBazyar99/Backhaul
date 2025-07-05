# config.sh
# Validation functions, backup config, and tunnel configuration wizard

# WARNING: Do not use a global CONFIG_FILE variable. Always pass config file paths explicitly to functions.

# --- Configuration & Validation ---
# Note: validate_port() and validate_ip() are now defined in helpers.sh

# Get process information for a port
get_port_process_info() {
    local port_to_check=$1
    local process_info=""
    
    # Try to get process info using ss
    if command -v ss >/dev/null 2>&1; then
        process_info=$(ss -lntup 2>/dev/null | grep ":${port_to_check}[[:space:]]" | head -1)
        if [[ -n "$process_info" ]]; then
            # Extract PID and process name
            local pid=$(echo "$process_info" | awk '{print $6}' | sed 's/.*pid=\([0-9]*\).*/\1/')
            if [[ -n "$pid" && "$pid" != "pid=" ]]; then
                local process_name=$(ps -p "$pid" -o comm= 2>/dev/null | head -1)
                local cmd_line=$(ps -p "$pid" -o cmd= 2>/dev/null | head -1 | cut -c1-60)
                echo "Process ID: $pid"
                echo "Process Name: $process_name"
                echo "Command: $cmd_line..."
                return
            fi
        fi
    fi
    
    # Fallback to netstat if ss doesn't work
    if command -v netstat >/dev/null 2>&1; then
        process_info=$(netstat -tlnp 2>/dev/null | grep ":${port_to_check}[[:space:]]" | head -1)
        if [[ -n "$process_info" ]]; then
            local pid=$(echo "$process_info" | awk '{print $7}' | cut -d'/' -f1)
            if [[ -n "$pid" && "$pid" != "-" ]]; then
                local process_name=$(ps -p "$pid" -o comm= 2>/dev/null | head -1)
                local cmd_line=$(ps -p "$pid" -o cmd= 2>/dev/null | head -1 | cut -c1-60)
                echo "Process ID: $pid"
                echo "Process Name: $process_name"
                echo "Command: $cmd_line..."
                return
            fi
        fi
    fi
    
    # If we can't get detailed info, show basic port usage
    echo "Port is in use but process details unavailable"
}

# Note: check_port_availability() and backup_config() are now defined in helpers.sh

# --- Configuration Wizard ---
configure_tunnel() {
    local tunnel_name=""
    local setup_type=""
    local transport=""
    local server_ip=""
    local server_port=""
    local local_port=""
    local auth_token=""
    
    clear
    print_server_info_banner_minimal
    print_info "--- Tunnel Configuration Wizard ---"
    
    print_info "This wizard will help you create a new Backhaul tunnel configuration."
    print_info "You can cancel at any time by entering '0' or press '?' for help."
    echo
    
    # Get tunnel name
    while true; do
        read -p "Enter tunnel name (e.g., my-vpn, web-server): " tunnel_name
        if [[ "$tunnel_name" == "0" ]]; then
            print_info "Configuration cancelled."
            return
        elif [[ "$tunnel_name" == "?" ]]; then
            print_info "--- Tunnel Name Help ---"
            echo "The tunnel name is used to identify this tunnel."
            echo "Use descriptive names like 'my-vpn' or 'web-server'."
            echo "Avoid spaces and special characters."
            echo "This name will be used for the service and config files."
            press_any_key
        elif [[ -n "$tunnel_name" ]]; then
            # Validate tunnel name
            if [[ "$tunnel_name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
                break
            else
                print_warning "❌ Invalid tunnel name. Use only letters, numbers, hyphens, and underscores."
                press_any_key
            fi
        else
            print_warning "❌ Please enter a tunnel name."
            press_any_key
        fi
    done
    
    # Get setup type
    echo
    print_info "--- Tunnel Type ---"
    echo " 1. Server (accepts connections from clients)"
    echo " 2. Client (connects to a server)"
    echo " 0. Cancel"
    echo
    while true; do
        read -p "Select tunnel type [1-2, 0 to cancel]: " setup_type
        case $setup_type in
            1) setup_type="server"; break ;;
            2) setup_type="client"; break ;;
            0)
                print_info "Configuration cancelled."
                return
                ;;
            *)
                print_warning "❌ Invalid option. Please enter 1-2 or 0 to cancel."
                press_any_key
                ;;
        esac
    done

    # Get transport protocol
    echo
    print_info "--- Transport Protocol ---"
    echo " 1. TCP (most reliable, recommended)"
    echo " 2. UDP (faster, less reliable)"
    echo " 3. WebSocket (for web environments)"
    echo " 4. WebSocket Secure (WSS, encrypted)"
    echo " 0. Cancel"
    echo
    while true; do
        read -p "Select transport protocol [1-4, 0 to cancel]: " transport_choice
        case $transport_choice in
            1) transport="tcp"; break ;;
            2) transport="udp"; break ;;
            3) transport="ws"; break ;;
            4) transport="wss"; break ;;
            0)
                print_info "Configuration cancelled."
                return
                ;;
            *)
                print_warning "❌ Invalid option. Please enter 1-4 or 0 to cancel."
                press_any_key
                ;;
        esac
    done

    # Get server details
    if [[ "$setup_type" == "client" ]]; then
        echo
        print_info "--- Server Configuration ---"
        while true; do
            read -p "Enter server IP address (e.g., 192.168.1.100): " server_ip
            if [[ "$server_ip" == "0" ]]; then
                print_info "Configuration cancelled."
                return
            elif [[ "$server_ip" == "?" ]]; then
                print_info "--- Server IP Help ---"
                echo "Enter the IP address of your Backhaul server."
                echo "This is the server that will accept your connection."
                echo "Examples: 192.168.1.100, 10.0.0.5, or a public IP"
                press_any_key
            elif [[ -n "$server_ip" ]]; then
                # Basic IP validation
                if [[ "$server_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    break
                else
                    print_warning "❌ Please enter a valid IP address (e.g., 192.168.1.100)."
                    press_any_key
                fi
            else
                print_warning "❌ Please enter a server IP address."
                press_any_key
            fi
        done
        
        while true; do
            read -p "Enter server port (e.g., 8080): " server_port
            if [[ "$server_port" == "0" ]]; then
                print_info "Configuration cancelled."
                return
            elif [[ "$server_port" == "?" ]]; then
                print_info "--- Server Port Help ---"
                echo "Enter the port number your server is listening on."
                echo "This should match the port configured on your server."
                echo "Common ports: 8080, 8443, 4567"
                press_any_key
            elif [[ -n "$server_port" ]] && [[ "$server_port" =~ ^[0-9]+$ ]] && [[ $server_port -ge 1 ]] && [[ $server_port -le 65535 ]]; then
                break
            else
                print_warning "❌ Please enter a valid port number (1-65535)."
                press_any_key
            fi
        done
    fi

    # Get local port
    echo
    print_info "--- Local Port Configuration ---"
    while true; do
        read -p "Enter local port to forward (e.g., 80, 443, 8080): " local_port
        if [[ "$local_port" == "0" ]]; then
            print_info "Configuration cancelled."
            return
        elif [[ "$local_port" == "?" ]]; then
            print_info "--- Local Port Help ---"
            echo "Enter the port number of the service you want to expose."
            echo "This is the port your local service is running on."
            echo "Examples: 80 (HTTP), 443 (HTTPS), 22 (SSH), 8080 (web app)"
            press_any_key
        elif [[ -n "$local_port" ]] && [[ "$local_port" =~ ^[0-9]+$ ]] && [[ $local_port -ge 1 ]] && [[ $local_port -le 65535 ]]; then
            break
        else
            print_warning "❌ Please enter a valid port number (1-65535)."
            press_any_key
        fi
    done

    # Get authentication token
    echo
    print_info "--- Authentication ---"
        while true; do
        read -p "Enter authentication token (optional, press Enter to skip): " auth_token
        if [[ "$auth_token" == "0" ]]; then
            print_info "Configuration cancelled."
            return
        elif [[ "$auth_token" == "?" ]]; then
            print_info "--- Authentication Token Help ---"
            echo "A token provides security for your tunnel connection."
            echo "Both client and server must use the same token."
            echo "Leave empty for no authentication (less secure)."
            echo "Use a strong, random string for better security."
            press_any_key
        else
            break
        fi
    done
    
    # Create configuration
    echo
    print_info "--- Creating Configuration ---"
    local service_name_suffix="$tunnel_name"
    local config_file="$CONFIG_DIR/config-${service_name_suffix}.toml"
    
    # Build configuration content
    local config_content=""
    if [[ "$setup_type" == "server" ]]; then
        config_content+="[server]\n"
        config_content+="bind_addr = \"0.0.0.0:${local_port}\"\n"
        if [[ -n "$auth_token" ]]; then
            config_content+="token = \"${auth_token}\"\n"
        fi
    else
        config_content+="[client]\n"
        config_content+="remote_addr = \"${server_ip}:${server_port}\"\n"
        config_content+="local_addr = \"127.0.0.1:${local_port}\"\n"
        if [[ -n "$auth_token" ]]; then
            config_content+="token = \"${auth_token}\"\n"
        fi
    fi
    
    config_content+="transport = \"${transport}\"\n"
    config_content+="heartbeat = 30\n"
    config_content+="log_level = \"info\"\n"
    
    # Write configuration file
    echo -e "$config_content" > "$config_file"
    chmod 600 "$config_file"
    
    print_success "✅ Configuration created: $config_file"
    
    # Create systemd service
    echo
    print_info "--- Creating System Service ---"
    create_systemd_service "$service_name_suffix" "$config_file"
    
    print_success "✅ Tunnel configuration completed successfully!"
    print_info "You can now manage this tunnel from the main menu."
    echo
    print_info "Configuration summary:"
    echo "  - Name: $tunnel_name"
    echo "  - Type: $setup_type"
    echo "  - Transport: $transport"
    if [[ "$setup_type" == "client" ]]; then
        echo "  - Server: $server_ip:$server_port"
    fi
    echo "  - Local port: $local_port"
    echo "  - Config file: $config_file"
    echo "  - Service: backhaul-$service_name_suffix.service"
}

update_config_file() {
    local tunnel_name="$1"
    local server_ip="$2"
    local server_port="$3"
    local local_port="$4"
    local protocol="$5"
    
    # Input validation
    if ! validate_ip "$server_ip" || ! validate_port "$server_port" || ! validate_port "$local_port"; then
        log_message "ERROR" "Invalid configuration parameters for tunnel $tunnel_name"
        return 1
    fi
    
    # Sanitize inputs
    tunnel_name=$(sanitize_input "$tunnel_name" 50)
    server_ip=$(sanitize_input "$server_ip" 15)
    server_port=$(sanitize_input "$server_port" 5)
    local_port=$(sanitize_input "$local_port" 5)
    protocol=$(sanitize_input "$protocol" 3)
    
    # Create config directory if it doesn't exist
    mkdir -p "$CONFIG_DIR"
    harden_permissions "$CONFIG_DIR"
    
    # Read existing config or create new one
    local temp_config=$(mktemp)
    if [ -f "$CONFIG_FILE" ]; then
        # Remove existing entry for this tunnel if it exists
        grep -v "^$tunnel_name=" "$CONFIG_FILE" > "$temp_config" 2>/dev/null || true
    fi
    
    # Add new tunnel entry
    echo "$tunnel_name=$server_ip:$server_port:$local_port:$protocol" >> "$temp_config"
    
    # Securely write the updated config
    secure_write "$CONFIG_FILE" "$(cat "$temp_config")"
    secure_config_file "$CONFIG_FILE"
    
    # Clean up temp file
    rm -f "$temp_config"
    
    secure_log_message "INFO" "Updated config for tunnel $tunnel_name"
}

remove_from_config() {
    local tunnel_name="$1"
    
    # Input sanitization
    tunnel_name=$(sanitize_input "$tunnel_name" 50)
    
    if [ ! -f "$CONFIG_FILE" ]; then
        return 0
    fi
    
    # Create temporary file with tunnel removed
    local temp_config=$(mktemp)
    grep -v "^$tunnel_name=" "$CONFIG_FILE" > "$temp_config" 2>/dev/null || true
    
    # Securely write the updated config
    secure_write "$CONFIG_FILE" "$(cat "$temp_config")"
    secure_config_file "$CONFIG_FILE"
    
    # Clean up temp file
    rm -f "$temp_config"
    
    secure_log_message "INFO" "Removed tunnel $tunnel_name from config"
}

backup_configuration() {
    print_info "=== Backup Configuration ==="
    
    local backup_dir="$CONFIG_DIR/backups"
    mkdir -p "$backup_dir"
    
    local backup_file="$backup_dir/backhaul_config_$(date +%Y%m%d_%H%M%S).tar.gz"
    
    if tar -czf "$backup_file" -C "$CONFIG_DIR" . 2>/dev/null; then
        print_success "✅ Configuration backed up to: $backup_file"
    else
        print_error "❌ Failed to create backup"
    fi
}

restore_configuration() {
    print_info "=== Restore Configuration ==="
    
    local backup_dir="$CONFIG_DIR/backups"
    if [ ! -d "$backup_dir" ]; then
        print_error "❌ No backup directory found"
        return 1
    fi
    
    local backup_files=($(ls -t "$backup_dir"/*.tar.gz 2>/dev/null))
    if [ ${#backup_files[@]} -eq 0 ]; then
        print_error "❌ No backup files found"
        return 1
    fi
    
    echo "Available backups:"
    local i=1
    for backup in "${backup_files[@]}"; do
        echo " $i. $(basename "$backup") ($(stat -c %y "$backup" 2>/dev/null || stat -f %Sm "$backup" 2>/dev/null))"
        ((i++))
    done
    
    while true; do
        read -p "Select backup to restore [1-${#backup_files[@]}, 0 to cancel]: " choice
        if [[ "$choice" == "0" ]]; then
            print_info "Restore cancelled."
            return
        elif [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 ]] && [[ $choice -le ${#backup_files[@]} ]]; then
            local selected_backup="${backup_files[$((choice-1))]}"
            
            # Backup current config
            backup_configuration
            
            if confirm_action "Proceed with restore?" "n"; then
                if tar -xzf "$selected_backup" -C "$CONFIG_DIR" 2>/dev/null; then
                    print_success "✅ Configuration restored from: $(basename "$selected_backup")"
                else
                    print_error "❌ Failed to restore configuration"
                fi
            fi
            break
        else
            print_warning "❌ Invalid selection"
        fi
    done
}

validate_configuration() {
    local config_file="$1"
    
    if [ ! -f "$config_file" ]; then
        return 1
    fi
    
    # Check file permissions
    local perms=$(stat -c %a "$config_file" 2>/dev/null)
    if [ "$perms" != "600" ]; then
        echo "⚠ Config file has insecure permissions: $perms"
        return 1
    fi
    
    # Validate syntax
    while IFS='=' read -r tunnel_name tunnel_config; do
        if [ -n "$tunnel_name" ] && [ -n "$tunnel_config" ]; then
            IFS=':' read -r server_ip server_port local_port protocol <<< "$tunnel_config"
            
            if ! validate_ip "$server_ip" || ! validate_port "$server_port" || ! validate_port "$local_port"; then
                echo "❌ Invalid configuration for tunnel $tunnel_name"
                return 1
            fi
        fi
    done < "$config_file"
    
    return 0
}

# Export configuration
export_configuration() {
    local tunnel_name="$1"
    local export_file="$CONFIG_DIR/${tunnel_name}_config_$(date +%Y%m%d_%H%M%S).toml"
    
    if [ -f "$CONFIG_DIR/config-${tunnel_name}.toml" ]; then
        cp "$CONFIG_DIR/config-${tunnel_name}.toml" "$export_file"
        print_success "✅ Configuration exported to: $export_file"
    else
        print_error "❌ Invalid configuration for tunnel $tunnel_name"
    fi
}

