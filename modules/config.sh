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
    local tls_cert_path=""
    local tls_key_path=""
    
    clear
    print_server_info_banner_minimal
    print_info "=========================================="
    print_info "      VPN Tunnel Configuration Wizard"
    print_info "=========================================="
    print_info "This wizard helps you set up a VPN tunnel between:"
    print_info "  • Iran Server: Relay/exit point (users connect here)"
    print_info "  • Foreign Server: VPN panel hosting (tunnel destination)"
    print_info "Users connect to Iran server → Traffic forwarded to foreign server VPN panel"
    echo
    
    # --- Step 1: Setup Type ---
    print_info "Choose your setup preference:"
    echo " 1. Quick Setup (recommended) - Uses sensible defaults for most settings"
    echo " 2. Advanced Setup - Configure all settings manually"
    echo " 0. Back to Main Menu"
    
    local setup_type_choice
    while true; do
        read -p "Select setup type [1-2, 0] (default: 1): " setup_type_choice
        setup_type_choice=${setup_type_choice:-1}
        case $setup_type_choice in
            1|2) break ;;
            0) return ;;
            *) print_warning "Invalid selection." ;;
        esac
    done

    # --- Step 2: Automatic Role Detection ---
    local mode_choice
    local default_mode
    
    # Get server country if not already set
    if [[ -z "$SERVER_COUNTRY" ]]; then
        print_info "Detecting server location..."
        get_server_info
    fi
    
    if [[ "$SERVER_COUNTRY" == "IR" ]]; then
        default_mode="1"
        print_info "Detected server location: Iran (defaulting to Server mode)"
    else
        default_mode="2"
        print_info "Detected server location: $SERVER_COUNTRY (defaulting to Client mode)"
    fi
    
    while true; do
        echo
        print_info "Select tunnel mode:"
        echo " 1. Server (Listens for connections)"
        echo " 2. Client (Connects to a server)"
        echo " 0. Back to Main Menu"
        read -p "Select mode [1-2, 0] (default: $default_mode): " mode_choice
        mode_choice=${mode_choice:-$default_mode}
        case $mode_choice in
            1) setup_type="server"; break ;;
            2) setup_type="client"; break ;;
            0) return ;;
            *) print_warning "Invalid selection." ;;
        esac
    done

    # --- Step 3: Transport Protocol ---
    print_info "Select transport protocol:"
    if [[ $setup_type_choice -eq 1 ]]; then
        # Quick setup - simplified options
        echo " 1. TCP (recommended) - Standard, reliable, works everywhere"
        echo " 2. WebSocket (WS) - Good for bypassing firewalls"
        echo " 3. Secure WebSocket (WSS) - Encrypted, most secure"
        echo " 4. Show all options"
        
        local transport_choice
        while true; do
            read -p "Select transport [1-4] (default: 1): " transport_choice
            transport_choice=${transport_choice:-1}
            case $transport_choice in
                1) transport="tcp"; break ;;
                2) transport="ws"; break ;;
                3) transport="wss"; break ;;
                4) 
                    # Show all options
                    print_info "All transport options:"
                    echo " 1. tcp - Standard TCP (recommended)"
                    echo " 2. tcpmux - Multiplexed TCP"
                    echo " 3. udp - UDP"
                    echo " 4. ws - WebSocket"
                    echo " 5. wsmux - Multiplexed WebSocket"
                    echo " 6. wss - Secure WebSocket"
                    echo " 7. wssmux - Multiplexed Secure WebSocket"
                    read -p "Select transport [1-7] (default: 1): " transport_choice
                    transport_choice=${transport_choice:-1}
                    local transport_options=("tcp" "tcpmux" "udp" "ws" "wsmux" "wss" "wssmux")
                    if [[ "$transport_choice" =~ ^[1-7]$ ]]; then
                        transport="${transport_options[$((transport_choice-1))]}"
                        break
                    else
                        print_warning "Invalid selection."
                    fi
                    ;;
                *) print_warning "Invalid selection." ;;
            esac
        done
    else
        # Advanced setup - show all options
        print_info "Available transports:"
        local transport_options=("tcp" "tcpmux" "udp" "ws" "wsmux" "wss" "wssmux")
        local transport_descriptions=(
            "Standard TCP - Fast and reliable"
            "Multiplexed TCP - Multiple connections over single TCP"
            "UDP - For UDP-specific applications"
            "WebSocket - Good for bypassing firewalls"
            "Multiplexed WebSocket - Multiple connections over WS"
            "Secure WebSocket - Encrypted with TLS"
            "Multiplexed Secure WebSocket - Multiple connections over WSS"
        )
        
        local i=1
        for t in "${transport_options[@]}"; do
            echo " $i. $t - ${transport_descriptions[$((i-1))]}"
            ((i++))
        done
        
        while true; do
            read -p "Select transport protocol [1-${#transport_options[@]}]: " transport_choice
            if [[ "$transport_choice" =~ ^[1-7]$ ]]; then
                transport="${transport_options[$((transport_choice-1))]}"
                break
            else
                print_warning "Invalid selection. Enter a number 1-${#transport_options[@]}."
            fi
        done
    fi

    # --- Step 4: Basic Configuration ---
    print_info "--- Basic Configuration ---"
    local tunnel_port server_ip token
    
    if [[ "$setup_type" == "server" ]]; then
        local default_tunnel_port=443
        while true; do
            read -p "Enter the main tunnel port to listen on [${default_tunnel_port}]: " tunnel_port
            tunnel_port=${tunnel_port:-$default_tunnel_port}
            if ! validate_port "$tunnel_port"; then
                print_warning "Invalid port number."
            elif ! check_port_availability "$tunnel_port"; then
                read -p "Port $tunnel_port is in use. Auto-select a free port? (y/n): " autoport
                if [[ "${autoport,,}" == "y" ]]; then
                    for p in $(seq 20000 1 65000); do
                        if check_port_availability "$p"; then
                            tunnel_port="$p"
                            print_success "Selected free port: $tunnel_port"
                            break
                        fi
                    done
                    break
                else
                    continue
                fi
            else
                break
            fi
        done
        
        local_port="$tunnel_port"
        server_ip=""
        server_port=""
        
    else # client
        print_info "--- Foreign Server Configuration ---"
        print_info "This foreign server will connect to Iran server to provide VPN panel access."
        print_info "Users will connect to Iran server, which forwards traffic to this foreign server."
        
        while true; do
            read -p "Enter the public IP address of the Iran server: " server_ip
            validate_ip "$server_ip" && break || print_warning "Invalid IP address format."
        done
        
        # Optional: Offer to ping the server IP
        read -p "Do you want to ping the Iran server IP to check connectivity? (y/n) [y]: " do_ping
        do_ping=${do_ping:-y}
        if [[ "${do_ping,,}" == "y" ]]; then
            print_info "Pinging $server_ip..."
            if ping -c 2 -W 2 "$server_ip" >/dev/null 2>&1; then
                print_success "Ping successful! Iran server is reachable."
            else
                print_warning "Ping failed. The Iran server may be offline or unreachable."
            fi
        fi
        
        while true; do
            local default_tunnel_port=443
            read -p "Enter the tunnel port set on the Iran server [${default_tunnel_port}]: " tunnel_port
            tunnel_port=${tunnel_port:-$default_tunnel_port}
            if ! validate_port "$tunnel_port"; then
                print_warning "Invalid port number."
            elif ! check_port_availability "$tunnel_port"; then
                read -p "Port $tunnel_port is in use. Auto-select a free port? (y/n): " autoport
                if [[ "${autoport,,}" == "y" ]]; then
                    for p in $(seq 20000 1 65000); do
                        if check_port_availability "$p"; then
                            tunnel_port="$p"
                            print_success "Selected free port: $tunnel_port"
                            break
                        fi
                    done
                    break
                else
                    continue
                fi
            else
                break
            fi
        done
        
        server_port="$tunnel_port"
        local_port="1080"  # Default local port for client
    fi

    # Token prompt (same for both server and client)
    local default_token="vpn-tunnel-naxon"
    while true; do
        read -p "Enter a secure authentication token [default: $default_token, must match on both sides]: " token
        # Use default token if input is empty
        token=${token:-$default_token}
        if [[ -n "$token" ]]; then
            auth_token="$token"
            break
        else
            print_warning "Token cannot be empty."
        fi
    done

    # --- Step 5: Advanced Configuration (Conditional) ---
    local log_level="info" nodelay="true" keepalive_period=75
    local heartbeat=40 connection_pool=8 retry_interval=3 dial_timeout=10
    local tls_cert="" tls_key="" edge_ip=""
    local mux_version=1 mux_framesize=32768 mux_recievebuffer=4194304 mux_streambuffer=65536
    local mux_con=8 accept_udp="false" channel_size=2048 aggressive_pool="false"
    local sniffer="false" sniffer_log="/root/backhaul.json" web_port=0
    
    if [[ $setup_type_choice -eq 2 ]]; then
        # Advanced setup - ask for all settings
        print_info "--- Advanced & Transport-Specific Configuration ---"
        
        # Basic settings
        while true; do
            read -p "Log Level (debug, info, warn, error) [info]: " log_level
            log_level=${log_level:-info}
            if [[ "$log_level" =~ ^(debug|info|warn|error)$ ]]; then
                break
            else
                print_warning "Invalid log level. Use: debug, info, warn, or error."
            fi
        done
        
        # Sniffer settings
        while true; do
            read -p "Enable sniffer (traffic logging)? (y/n) [n]: " sniffer_choice
            sniffer_choice=${sniffer_choice:-n}
            if [[ "${sniffer_choice,,}" =~ ^[yn]$ ]]; then
                if [[ "${sniffer_choice,,}" == "y" ]]; then
                    sniffer="true"
                    while true; do
                        read -p "Sniffer log file path [/root/backhaul.json]: " sniffer_log
                        sniffer_log=${sniffer_log:-/root/backhaul.json}
                        break
                    done
                else
                    sniffer="false"
                fi
                break
            else
                print_warning "Please enter y or n."
            fi
        done
        
        # Web interface
        while true; do
            read -p "Web interface port (0 to disable) [0]: " web_port
            web_port=${web_port:-0}
            if [[ "$web_port" =~ ^[0-9]+$ ]] && [[ $web_port -ge 0 ]] && [[ $web_port -le 65535 ]]; then
                break
            else
                print_warning "Please enter a number between 0 and 65535."
            fi
        done

        # Transport-specific settings
        if [[ "$transport" != "udp" ]]; then
            while true; do
                read -p "Enable TCP_NODELAY for lower latency? (y/n) [y]: " nodelay_choice
                nodelay_choice=${nodelay_choice:-y}
                if [[ "${nodelay_choice,,}" =~ ^[yn]$ ]]; then
                    nodelay=$([[ "${nodelay_choice,,}" == "y" ]] && echo "true" || echo "false")
                    break
                else
                    print_warning "Please enter y or n."
                fi
            done
            
            while true; do
                read -p "Keep-alive period in seconds [75]: " keepalive_period
                keepalive_period=${keepalive_period:-75}
                if [[ "$keepalive_period" =~ ^[0-9]+$ ]] && [[ $keepalive_period -ge 1 ]] && [[ $keepalive_period -le 300 ]]; then
                    break
                else
                    print_warning "Please enter a number between 1 and 300."
                fi
            done
        fi
        
        # Server-specific settings
        if [[ "$setup_type" == "server" ]]; then
            while true; do
                read -p "Heartbeat interval in seconds [40]: " heartbeat
                heartbeat=${heartbeat:-40}
                if [[ "$heartbeat" =~ ^[0-9]+$ ]] && [[ $heartbeat -ge 1 ]] && [[ $heartbeat -le 120 ]]; then
                    break
                else
                    print_warning "Please enter a number between 1 and 120."
                fi
            done
            
            while true; do
                read -p "Channel size [2048]: " channel_size
                channel_size=${channel_size:-2048}
                if [[ "$channel_size" =~ ^[0-9]+$ ]] && [[ $channel_size -ge 1024 ]] && [[ $channel_size -le 8192 ]]; then
                    break
                else
                    print_warning "Please enter a number between 1024 and 8192."
                fi
            done
            
            if [[ "$transport" == "tcp" ]]; then
                while true; do
                    read -p "Accept UDP traffic over TCP? (y/n) [n]: " accept_udp_choice
                    accept_udp_choice=${accept_udp_choice:-n}
                    if [[ "${accept_udp_choice,,}" =~ ^[yn]$ ]]; then
                        accept_udp=$([[ "${accept_udp_choice,,}" == "y" ]] && echo "true" || echo "false")
                        break
                    else
                        print_warning "Please enter y or n."
                    fi
                done
            fi
        else # client
            while true; do
                read -p "Connection pool size [8]: " connection_pool
                connection_pool=${connection_pool:-8}
                if [[ "$connection_pool" =~ ^[0-9]+$ ]] && [[ $connection_pool -ge 1 ]] && [[ $connection_pool -le 32 ]]; then
                    break
                else
                    print_warning "Please enter a number between 1 and 32."
                fi
            done
            
            while true; do
                read -p "Enable aggressive pool management? (y/n) [n]: " aggressive_pool_choice
                aggressive_pool_choice=${aggressive_pool_choice:-n}
                if [[ "${aggressive_pool_choice,,}" =~ ^[yn]$ ]]; then
                    aggressive_pool=$([[ "${aggressive_pool_choice,,}" == "y" ]] && echo "true" || echo "false")
                    break
                else
                    print_warning "Please enter y or n."
                fi
            done
            
            while true; do
                read -p "Connection retry interval in seconds [3]: " retry_interval
                retry_interval=${retry_interval:-3}
                if [[ "$retry_interval" =~ ^[0-9]+$ ]] && [[ $retry_interval -ge 1 ]] && [[ $retry_interval -le 30 ]]; then
                    break
                else
                    print_warning "Please enter a number between 1 and 30."
                fi
            done
            
            while true; do
                read -p "Connection dial timeout in seconds [10]: " dial_timeout
                dial_timeout=${dial_timeout:-10}
                if [[ "$dial_timeout" =~ ^[0-9]+$ ]] && [[ $dial_timeout -ge 1 ]] && [[ $dial_timeout -le 60 ]]; then
                    break
                else
                    print_warning "Please enter a number between 1 and 60."
                fi
            done
        fi

        # Multiplexing settings for *mux protocols
        if [[ "$transport" =~ ^(tcpmux|wsmux|wssmux)$ ]]; then
            echo
            print_info "--- Multiplexing (MUX) Parameters ---"
            
            while true; do 
                read -p "Multiplexing concurrency [8]: " mux_con
                mux_con=${mux_con:-8}
                if [[ "$mux_con" =~ ^[0-9]+$ ]] && [[ $mux_con -ge 1 ]] && [[ $mux_con -le 64 ]]; then
                    break
                else
                    print_warning "Please enter a number between 1 and 64."
                fi
            done
            
            while true; do
                read -p "SMUX protocol version (1 or 2) [1]: " mux_version
                mux_version=${mux_version:-1}
                if [[ "$mux_version" =~ ^[12]$ ]]; then
                    break
                else
                    print_warning "Please enter 1 or 2."
                fi
            done
            
            while true; do
                read -p "Mux frame size in bytes [32768]: " mux_framesize
                mux_framesize=${mux_framesize:-32768}
                if [[ "$mux_framesize" =~ ^[0-9]+$ ]] && [[ $mux_framesize -ge 1024 ]] && [[ $mux_framesize -le 65536 ]]; then
                    break
                else
                    print_warning "Please enter a number between 1024 and 65536."
                fi
            done
            
            while true; do
                read -p "Mux receive buffer in bytes [4194304]: " mux_recievebuffer
                mux_recievebuffer=${mux_recievebuffer:-4194304}
                if [[ "$mux_recievebuffer" =~ ^[0-9]+$ ]] && [[ $mux_recievebuffer -ge 65536 ]] && [[ $mux_recievebuffer -le 16777216 ]]; then
                    break
                else
                    print_warning "Please enter a number between 65536 and 16777216."
                fi
            done
            
            while true; do
                read -p "Mux stream buffer in bytes [65536]: " mux_streambuffer
                mux_streambuffer=${mux_streambuffer:-65536}
                if [[ "$mux_streambuffer" =~ ^[0-9]+$ ]] && [[ $mux_streambuffer -ge 1024 ]] && [[ $mux_streambuffer -le 1048576 ]]; then
                    break
                else
                    print_warning "Please enter a number between 1024 and 1048576."
                fi
            done
        fi
    fi
    
    # TLS certificate handling for secure protocols
    if [[ "$transport" =~ ^(wss|wssmux)$ ]]; then
        echo
        print_info "--- TLS Certificate Configuration ---"
        print_info "Secure protocols (WSS/WSSMUX) require TLS certificates."
        
        # Check for existing certificates
        local CERT_DIR="/etc/backhaul/certs"
        local existing_certs
        existing_certs=$(find "$CERT_DIR" -maxdepth 1 -name '*.crt' 2>/dev/null)
        
        if [ -n "$existing_certs" ]; then
            echo
            print_info "Existing certificates found:"
            local i=1
            for cert in $existing_certs; do
                echo " $i. $cert"
                ((i++))
            done
            echo " 0. Generate a new certificate"
            
            local cert_choice
            while true; do
                read -p "Select certificate [0-$((i-1))]: " cert_choice
                if [[ "$cert_choice" =~ ^[0-9]+$ ]] && [[ $cert_choice -le $((i-1)) ]]; then
                    if [[ $cert_choice -eq 0 ]]; then
                        generate_self_signed_cert
                        # Get the newly generated certificate
                        local new_certs
                        new_certs=$(find "$CERT_DIR" -maxdepth 1 -name '*.crt' 2>/dev/null | sort | tail -1)
                        if [[ -n "$new_certs" ]]; then
                            tls_cert_path="$new_certs"
                            tls_key_path="${new_certs%.crt}.key"
                        fi
                    else
                        local chosen_cert
                        chosen_cert=$(echo "$existing_certs" | sed -n "${cert_choice}p")
                        tls_cert_path="$chosen_cert"
                        tls_key_path="${chosen_cert%.crt}.key"
                    fi
                    break
                else
                    print_warning "Invalid selection."
                fi
            done
        else
            print_info "No existing certificates found. Generating a new one..."
            generate_self_signed_cert
            # Get the newly generated certificate
            local new_certs
            new_certs=$(find "$CERT_DIR" -maxdepth 1 -name '*.crt' 2>/dev/null | sort | tail -1)
            if [[ -n "$new_certs" ]]; then
                tls_cert_path="$new_certs"
                tls_key_path="${new_certs%.crt}.key"
            fi
        fi
    fi
    
    # --- Step 6: Generate Configuration ---
    echo
    print_info "--- Configuration Summary ---"
    echo "Mode: $setup_type"
    echo "Transport: $transport"
    if [[ "$setup_type" == "server" ]]; then
        echo "Listen Port: $local_port"
    else
        echo "Server IP: $server_ip"
        echo "Server Port: $server_port"
        echo "Local Port: $local_port"
    fi
    echo "Auth Token: $auth_token"
    if [[ -n "$tls_cert_path" ]]; then
        echo "TLS Certificate: $tls_cert_path"
        echo "TLS Key: $tls_key_path"
    fi
    
    if [[ $setup_type_choice -eq 2 ]]; then
        echo "Log Level: $log_level"
        echo "Sniffer: $sniffer"
        if [[ "$sniffer" == "true" ]]; then
            echo "Sniffer Log: $sniffer_log"
        fi
        if [[ $web_port -gt 0 ]]; then
            echo "Web Interface: port $web_port"
        fi
    fi
    
    echo
    read -p "Generate configuration with these settings? (y/n) [y]: " confirm
    confirm=${confirm:-y}
    if [[ "${confirm,,}" != "y" ]]; then
        print_info "Configuration cancelled."
        press_any_key
        return
    fi
    
    # Generate the configuration
    local config_content=""
    config_content+="mode = \"$setup_type\"\n"
    config_content+="transport = \"$transport\"\n"
    config_content+="auth_token = \"$auth_token\"\n"
    
    if [[ "$setup_type" == "server" ]]; then
        config_content+="listen = \":$local_port\"\n"
    else
        config_content+="server = \"$server_ip:$server_port\"\n"
        config_content+="local = \":$local_port\"\n"
    fi
    
    # Add TLS settings for secure protocols
    if [[ -n "$tls_cert_path" && -n "$tls_key_path" ]]; then
        config_content+="tls_cert = \"$tls_cert_path\"\n"
        config_content+="tls_key = \"$tls_key_path\"\n"
    fi
    
    # Add advanced settings if in advanced mode
    if [[ $setup_type_choice -eq 2 ]]; then
        config_content+="log_level = \"$log_level\"\n"
        config_content+="sniffer = $sniffer\n"
        if [[ "$sniffer" == "true" ]]; then
            config_content+="sniffer_log = \"$sniffer_log\"\n"
        fi
        if [[ $web_port -gt 0 ]]; then
            config_content+="web_port = $web_port\n"
        fi
        
        if [[ "$transport" != "udp" ]]; then
            config_content+="nodelay = $nodelay\n"
            config_content+="keepalive_period = $keepalive_period\n"
        fi
        
        if [[ "$setup_type" == "server" ]]; then
            config_content+="heartbeat = $heartbeat\n"
            config_content+="channel_size = $channel_size\n"
            if [[ "$transport" == "tcp" ]]; then
                config_content+="accept_udp = $accept_udp\n"
            fi
        else
            config_content+="connection_pool = $connection_pool\n"
            config_content+="aggressive_pool = $aggressive_pool\n"
            config_content+="retry_interval = $retry_interval\n"
            config_content+="dial_timeout = $dial_timeout\n"
        fi
        
        if [[ "$transport" =~ ^(tcpmux|wsmux|wssmux)$ ]]; then
            config_content+="mux_con = $mux_con\n"
            config_content+="mux_version = $mux_version\n"
            config_content+="mux_framesize = $mux_framesize\n"
            config_content+="mux_recievebuffer = $mux_recievebuffer\n"
            config_content+="mux_streambuffer = $mux_streambuffer\n"
        fi
    fi
    
    # Generate tunnel name
    local timestamp
    timestamp=$(date +%Y%m%d-%H%M%S)
    tunnel_name="tunnel-${setup_type}-${transport}-${timestamp}"
    
    # Save configuration
    local config_file="$CONFIG_DIR/config-${tunnel_name}.toml"
    mkdir -p "$CONFIG_DIR"
    echo -e "$config_content" > "$config_file"
    chmod 600 "$config_file"
    
    print_success "Configuration saved to: $config_file"
    
    # Create systemd service
    create_systemd_service "$tunnel_name" "$config_file"
    
    # Ask if user wants to start the tunnel
    echo
    read -p "Start the tunnel now? (y/n) [y]: " start_now
    start_now=${start_now:-y}
    if [[ "${start_now,,}" == "y" ]]; then
        if systemctl start "backhaul-$tunnel_name"; then
            print_success "Tunnel started successfully!"
            print_info "You can now connect to this tunnel."
        else
            print_error "Failed to start tunnel. Check logs for details."
        fi
    else
        print_info "Tunnel created but not started. You can start it later from the management menu."
    fi
    
    press_any_key
}

update_config_file() {
    local tunnel_name="$1"
    local server_ip="$2"
    local server_port="$3"
    local local_port="$4"
    local protocol="$5"
    
    # Input validation
    if ! validate_tunnel_parameters "$server_ip" "$server_port" "$local_port" "$tunnel_name"; then
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
        print_success "Configuration backed up to: $backup_file"
    else
        print_error "Failed to create backup"
    fi
}

restore_configuration() {
    print_info "=== Restore Configuration ==="
    
    local backup_dir="$CONFIG_DIR/backups"
    if [ ! -d "$backup_dir" ]; then
        print_error "No backup directory found"
        return 1
    fi
    
    local backup_files=($(ls -t "$backup_dir"/*.tar.gz 2>/dev/null))
    if [ ${#backup_files[@]} -eq 0 ]; then
        print_error "No backup files found"
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
                    print_success "Configuration restored from: $(basename "$selected_backup")"
                else
                                          print_error "Failed to restore configuration"
                fi
            fi
            break
        else
            print_warning "Invalid selection"
        fi
    done
}

# Export configuration
export_configuration() {
    local tunnel_name="$1"
    local export_file="$CONFIG_DIR/${tunnel_name}_config_$(date +%Y%m%d_%H%M%S).toml"
    
    if [ -f "$CONFIG_DIR/config-${tunnel_name}.toml" ]; then
        cp "$CONFIG_DIR/config-${tunnel_name}.toml" "$export_file"
        print_success "Configuration exported to: $export_file"
    else
        print_error "Invalid configuration for tunnel $tunnel_name"
    fi
}

# --- Advanced Configuration Function ---
configure_advanced_settings() {
    local config_content="$1"
    local transport="$2"
    local setup_type="$3"
    
    clear
    print_info "=== Advanced Configuration ==="
    print_info "Customize advanced parameters for your tunnel."
    echo
    
    # Remove existing advanced settings from config_content
    config_content=$(echo "$config_content" | grep -v -E "^(keepalive_period|nodelay|channel_size|heartbeat|mux_|connection_pool|aggressive_pool|dial_timeout|retry_interval|accept_udp|sniffer_log) =")
    
    # Basic settings for all protocols
    echo
    print_info "--- Basic Settings ---"
    
    # Keepalive period
    local keepalive_period
    while true; do
        read -p "Keepalive period in seconds [75]: " keepalive_period
        keepalive_period=${keepalive_period:-75}
        if [[ "$keepalive_period" =~ ^[0-9]+$ ]] && [[ $keepalive_period -ge 1 ]] && [[ $keepalive_period -le 3600 ]]; then
            break
        else
            print_warning "Please enter a number between 1 and 3600."
        fi
    done
    config_content+="keepalive_period = $keepalive_period\n"
    
    # Channel size
    local channel_size
    while true; do
        read -p "Channel size [2048]: " channel_size
        channel_size=${channel_size:-2048}
        if [[ "$channel_size" =~ ^[0-9]+$ ]] && [[ $channel_size -ge 1 ]] && [[ $channel_size -le 100000 ]]; then
            break
        else
            print_warning "Please enter a number between 1 and 100000."
        fi
    done
    config_content+="channel_size = $channel_size\n"
    
    # Heartbeat
    local heartbeat
    while true; do
        read -p "Heartbeat interval in seconds [40]: " heartbeat
        heartbeat=${heartbeat:-40}
        if [[ "$heartbeat" =~ ^[0-9]+$ ]] && [[ $heartbeat -ge 1 ]] && [[ $heartbeat -le 300 ]]; then
            break
        else
            print_warning "Please enter a number between 1 and 300."
        fi
    done
    config_content+="heartbeat = $heartbeat\n"
    
    # TCP_NODELAY for TCP-based protocols
    if [[ "$transport" =~ ^(tcp|tcpmux|ws|wss|wsmux|wssmux)$ ]]; then
        local nodelay
        while true; do
            read -p "Enable TCP_NODELAY (y/n) [n]: " nodelay
            nodelay=${nodelay:-n}
            if [[ "$nodelay" =~ ^[YyNn]$ ]]; then
                if [[ "$nodelay" =~ ^[Yy]$ ]]; then
                    config_content+="nodelay = true\n"
                else
                    config_content+="nodelay = false\n"
                fi
                break
            else
                print_warning "Please enter y or n."
            fi
        done
    fi
    
    # Accept UDP for TCP protocol
    if [[ "$transport" == "tcp" ]]; then
        local accept_udp
        while true; do
            read -p "Accept UDP connections (y/n) [n]: " accept_udp
            accept_udp=${accept_udp:-n}
            if [[ "$accept_udp" =~ ^[YyNn]$ ]]; then
                if [[ "$accept_udp" =~ ^[Yy]$ ]]; then
                    config_content+="accept_udp = true\n"
                else
                    config_content+="accept_udp = false\n"
                fi
                break
            else
                print_warning "Please enter y or n."
            fi
        done
    fi
    
    # Client-specific settings
    if [[ "$setup_type" == "client" ]]; then
        echo
        print_info "--- Client-Specific Settings ---"
        
        # Connection pool
        local connection_pool
        while true; do
            read -p "Connection pool size [8]: " connection_pool
            connection_pool=${connection_pool:-8}
            if [[ "$connection_pool" =~ ^[0-9]+$ ]] && [[ $connection_pool -ge 1 ]] && [[ $connection_pool -le 100 ]]; then
                break
            else
                print_warning "Please enter a number between 1 and 100."
            fi
        done
        config_content+="connection_pool = $connection_pool\n"
        
        # Aggressive pool
        local aggressive_pool
        while true; do
            read -p "Enable aggressive pool management (y/n) [n]: " aggressive_pool
            aggressive_pool=${aggressive_pool:-n}
            if [[ "$aggressive_pool" =~ ^[YyNn]$ ]]; then
                if [[ "$aggressive_pool" =~ ^[Yy]$ ]]; then
                    config_content+="aggressive_pool = true\n"
                else
                    config_content+="aggressive_pool = false\n"
                fi
                break
            else
                print_warning "Please enter y or n."
            fi
        done
        
        # Dial timeout
        local dial_timeout
        while true; do
            read -p "Dial timeout in seconds [10]: " dial_timeout
            dial_timeout=${dial_timeout:-10}
            if [[ "$dial_timeout" =~ ^[0-9]+$ ]] && [[ $dial_timeout -ge 1 ]] && [[ $dial_timeout -le 60 ]]; then
                break
            else
                print_warning "Please enter a number between 1 and 60."
            fi
        done
        config_content+="dial_timeout = $dial_timeout\n"
        
        # Retry interval
        local retry_interval
        while true; do
            read -p "Retry interval in seconds [3]: " retry_interval
            retry_interval=${retry_interval:-3}
            if [[ "$retry_interval" =~ ^[0-9]+$ ]] && [[ $retry_interval -ge 1 ]] && [[ $retry_interval -le 30 ]]; then
                break
            else
                print_warning "Please enter a number between 1 and 30."
            fi
        done
        config_content+="retry_interval = $retry_interval\n"
    fi
    
    # Multiplexing settings for *mux protocols
    if [[ "$transport" =~ ^(tcpmux|wsmux|wssmux)$ ]]; then
        echo
        print_info "--- Multiplexing Settings ---"
        
        # Mux concurrency
        local mux_con
        while true; do
            read -p "Mux concurrency (number of connections) [8]: " mux_con
            mux_con=${mux_con:-8}
            if [[ "$mux_con" =~ ^[0-9]+$ ]] && [[ $mux_con -ge 1 ]] && [[ $mux_con -le 64 ]]; then
                break
            else
                print_warning "Please enter a number between 1 and 64."
            fi
        done
        config_content+="mux_con = $mux_con\n"
        
        # Mux version
        local mux_version
        while true; do
            read -p "SMUX protocol version (1 or 2) [1]: " mux_version
            mux_version=${mux_version:-1}
            if [[ "$mux_version" =~ ^[12]$ ]]; then
                break
            else
                print_warning "Please enter 1 or 2."
            fi
        done
        config_content+="mux_version = $mux_version\n"
        
        # Mux frame size
        local mux_framesize
        while true; do
            read -p "Mux frame size in bytes [32768]: " mux_framesize
            mux_framesize=${mux_framesize:-32768}
            if [[ "$mux_framesize" =~ ^[0-9]+$ ]] && [[ $mux_framesize -ge 1024 ]] && [[ $mux_framesize -le 65536 ]]; then
                break
            else
                print_warning "Please enter a number between 1024 and 65536."
            fi
        done
        config_content+="mux_framesize = $mux_framesize\n"
        
        # Mux receive buffer
        local mux_recievebuffer
        while true; do
            read -p "Mux receive buffer in bytes [4194304]: " mux_recievebuffer
            mux_recievebuffer=${mux_recievebuffer:-4194304}
            if [[ "$mux_recievebuffer" =~ ^[0-9]+$ ]] && [[ $mux_recievebuffer -ge 65536 ]] && [[ $mux_recievebuffer -le 16777216 ]]; then
                break
            else
                print_warning "Please enter a number between 65536 and 16777216."
            fi
        done
        config_content+="mux_recievebuffer = $mux_recievebuffer\n"
        
        # Mux stream buffer
        local mux_streambuffer
        while true; do
            read -p "Mux stream buffer in bytes [65536]: " mux_streambuffer
            mux_streambuffer=${mux_streambuffer:-65536}
            if [[ "$mux_streambuffer" =~ ^[0-9]+$ ]] && [[ $mux_streambuffer -ge 1024 ]] && [[ $mux_streambuffer -le 1048576 ]]; then
                break
            else
                print_warning "Please enter a number between 1024 and 1048576."
            fi
        done
        config_content+="mux_streambuffer = $mux_streambuffer\n"
    fi
    
    # Optional features
    echo
    print_info "--- Optional Features ---"
    
    # Sniffer
    local sniffer
    while true; do
        read -p "Enable network sniffing/monitoring (y/n) [n]: " sniffer
        sniffer=${sniffer:-n}
        if [[ "$sniffer" =~ ^[YyNn]$ ]]; then
            if [[ "$sniffer" =~ ^[Yy]$ ]]; then
                config_content+="sniffer = true\n"
                
                # Custom sniffer log path
                local sniffer_log_path
                read -p "Sniffer log file path [/var/log/backhaul-${tunnel_name}.json]: " sniffer_log_path
                sniffer_log_path=${sniffer_log_path:-"/var/log/backhaul-${tunnel_name}.json"}
                config_content+="sniffer_log = \"$sniffer_log_path\"\n"
                
                print_info "Sniffer enabled with log file: $sniffer_log_path"
            else
                config_content+="sniffer = false\n"
            fi
            break
        else
            print_warning "Please enter y or n."
        fi
    done
    
    # Web interface port
    local web_port
    while true; do
        read -p "Web interface port (0 to disable) [0]: " web_port
        web_port=${web_port:-0}
        if [[ "$web_port" =~ ^[0-9]+$ ]] && [[ $web_port -ge 0 ]] && [[ $web_port -le 65535 ]]; then
            if [[ $web_port -gt 0 ]]; then
                config_content+="web_port = $web_port\n"
            fi
            break
        else
            print_warning "Please enter a number between 0 and 65535."
        fi
    done
    
    print_success "Advanced configuration completed."
    echo
    print_info "Configuration summary:"
    echo "  - Keepalive: ${keepalive_period}s"
    echo "  - Channel size: $channel_size"
    echo "  - Heartbeat: ${heartbeat}s"
    if [[ "$transport" =~ ^(tcp|tcpmux|ws|wss|wsmux|wssmux)$ ]]; then
        echo "  - TCP_NODELAY: $([[ "$nodelay" =~ ^[Yy]$ ]] && echo "enabled" || echo "disabled")"
    fi
    if [[ "$transport" == "tcp" ]]; then
        echo "  - Accept UDP: $([[ "$accept_udp" =~ ^[Yy]$ ]] && echo "enabled" || echo "disabled")"
    fi
    if [[ "$setup_type" == "client" ]]; then
        echo "  - Connection pool: $connection_pool"
        echo "  - Aggressive pool: $([[ "$aggressive_pool" =~ ^[Yy]$ ]] && echo "enabled" || echo "disabled")"
        echo "  - Dial timeout: ${dial_timeout}s"
        echo "  - Retry interval: ${retry_interval}s"
    fi
    if [[ "$transport" =~ ^(tcpmux|wsmux|wssmux)$ ]]; then
        echo "  - Mux concurrency: $mux_con"
        echo "  - Mux version: $mux_version"
        echo "  - Mux frame size: $mux_framesize bytes"
        echo "  - Mux receive buffer: $mux_recievebuffer bytes"
        echo "  - Mux stream buffer: $mux_streambuffer bytes"
    fi
    echo "  - Sniffer: $([[ "$sniffer" =~ ^[Yy]$ ]] && echo "enabled" || echo "disabled")"
    if [[ "$sniffer" =~ ^[Yy]$ ]]; then
        echo "  - Sniffer log: $sniffer_log_path"
    fi
    if [[ $web_port -gt 0 ]]; then
        echo "  - Web interface: port $web_port"
    else
        echo "  - Web interface: disabled"
    fi
    
    press_any_key
    echo "$config_content"
}

# --- Helper Functions ---

# Note: All helper functions (validate_port, validate_ip, generate_self_signed_cert, etc.) 
# are already implemented in helpers.sh and backhaul_core.sh modules.
# These modules are concatenated together by build.sh, so we can use them directly.

