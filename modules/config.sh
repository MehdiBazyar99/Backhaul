# config.sh
# Validation functions, backup config, and tunnel configuration wizard

# --- Configuration & Validation ---
validate_port() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
validate_ip() { [[ "$1" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; }
validate_number() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -gt 0 ]; }

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

# Unified port checking function - uses 'ss' as it's more modern and available on most systems
check_port_availability() {
    local port_to_check=$1
    if ss -lntu 2>/dev/null | awk '{print $5}' | grep -q ":${port_to_check}$"; then
        print_error "Port ${port_to_check} is already in use by another service."
        print_info "Process information:"
        get_port_process_info "$port_to_check"
        return 1
    else
        return 0
    fi
}

backup_config() {
    local config_file="$1"
    if [ -f "$config_file" ]; then
        mkdir -p "$BACKUP_DIR"
        local backup_path="$BACKUP_DIR/$(basename "$config_file").bak.$(date +%F_%T)"
        print_info "--> Backing up current configuration to $backup_path"
        if ! cp "$config_file" "$backup_path"; then
            print_warning "Failed to backup $config_file to $backup_path. Please check permissions."
        fi
    fi
}

configure_new_tunnel() {
    clear
    print_server_info_banner
    print_info "=========================================="
    print_info "      VPN Tunnel Configuration Wizard"
    print_info "=========================================="
    print_info "This wizard helps you set up a VPN tunnel between:"
    print_info "  • Iran Server: Relay/exit point (users connect here)"
    print_info "  • Foreign Server: VPN panel hosting (tunnel destination)"
    print_info "Users connect to Iran server → Traffic forwarded to foreign server VPN panel"

    # --- Step 1: Setup Type ---
    print_info "\nChoose your setup preference:"
    print_info "1. Quick Setup (recommended) - Uses sensible defaults for most settings"
    print_info "2. Advanced Setup - Configure all settings manually"
    print_info "0. Back to Main Menu"
    
    local setup_type
    while true; do
        read -p "Select setup type [1-2, 0] (default: 1): " setup_type
        setup_type=${setup_type:-1}
        case $setup_type in
            1|2) break ;;
            0) return ;;
            *) print_warning "Invalid selection." ;;
        esac
    done

    # --- Step 2: Mode ---
    local mode_choice
    local default_mode
    if [[ "$SERVER_COUNTRY" == "Iran" ]]; then
        default_mode="1"
        print_info "\nDetected server location: Iran (defaulting to Server mode)"
    else
        default_mode="2"
        print_info "\nDetected server location: $SERVER_COUNTRY (defaulting to Client mode)"
    fi
    while true; do
        echo
        print_info "1. Server (Listens for connections)"
        print_info "2. Client (Connects to a server)"
        print_info "0. Back to Main Menu"
        read -p "Select mode [1-2, 0] (default: $default_mode): " mode_choice
        mode_choice=${mode_choice:-$default_mode}
        case $mode_choice in
            1) INSTALL_MODE="server"; break ;;
            2) INSTALL_MODE="client"; break ;;
            0) return ;;
            *) print_warning "Invalid selection." ;;
        esac
    done

    # --- Step 3: Transport Protocol (Simplified) ---
    print_info "\nSelect transport protocol:"
    if [[ $setup_type -eq 1 ]]; then
        # Quick setup - simplified options
        print_info "1. TCP (recommended) - Standard, reliable, works everywhere"
        print_info "2. WebSocket (WS) - Good for bypassing firewalls"
        print_info "3. Secure WebSocket (WSS) - Encrypted, most secure"
        print_info "4. Show all options"
        
        local transport_choice
        while true; do
            read -p "Select transport [1-4] (default: 1): " transport_choice
            transport_choice=${transport_choice:-1}
            case $transport_choice in
                1) TRANSPORT="tcp"; break ;;
                2) TRANSPORT="ws"; break ;;
                3) TRANSPORT="wss"; break ;;
                4) 
                    # Show all options
                    print_info "\nAll transport options:"
                    print_info "1. tcp - Standard TCP (recommended)"
                    print_info "2. tcpmux - Multiplexed TCP"
                    print_info "3. udp - UDP"
                    print_info "4. ws - WebSocket"
                    print_info "5. wsmux - Multiplexed WebSocket"
                    print_info "6. wss - Secure WebSocket"
                    print_info "7. wssmux - Multiplexed Secure WebSocket"
                    read -p "Select transport [1-7] (default: 1): " transport_choice
                    transport_choice=${transport_choice:-1}
                    local transport_options=("tcp" "tcpmux" "udp" "ws" "wsmux" "wss" "wssmux")
                    if [[ "$transport_choice" =~ ^[1-7]$ ]]; then
                        TRANSPORT="${transport_options[$((transport_choice-1))]}"
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
            echo "  $i) $t - ${transport_descriptions[$((i-1))]}"
            ((i++))
        done
        
        while true; do
            read -p "Select transport protocol [1-${#transport_options[@]}]: " transport_choice
            if [[ "$transport_choice" =~ ^[1-7]$ ]]; then
                TRANSPORT="${transport_options[$((transport_choice-1))]}"
                break
            else
                print_warning "Invalid selection. Enter a number 1-${#transport_options[@]}."
            fi
        done
    fi

    # --- Step 4: Basic Configuration ---
    print_info "\n--- Basic Configuration ---"
    local tunnel_port server_ip token forwarded_ports_input
    if [[ "$INSTALL_MODE" == "server" ]]; then
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
        
        # VPN-focused port forwarding configuration
        print_info "\n--- VPN Panel Port Forwarding Configuration ---"
        print_info "This forwards ports from Iran server to your VPN panel on the foreign server."
        print_info "Users will connect to these ports on the Iran server to access your VPN panel."
        print_info "Common VPN panel ports:"
        print_info "  • 80,443 - Web panel (HTTP/HTTPS)"
        print_info "  • 8080,8443 - Alternative web panel ports"
        print_info "  • 1194,500,4500 - VPN protocols (OpenVPN, IPSec)"
        print_info "  • 1080,1081 - SOCKS proxy"
        
        while true; do
            read -p "How do you want to configure port forwarding? 1) Simple (recommended) 2) Advanced [1/2]: " pf_mode
            pf_mode=${pf_mode:-1}
            if [[ "$pf_mode" == "1" ]]; then
                # Simple mode - just ask for VPN panel ports to expose
                while true; do
                    read -p "Enter VPN panel ports to expose (e.g., 80,443,8080): " local_ports
                    if [[ -n "$local_ports" ]]; then
                        break
                    else
                        print_warning "Please enter at least one port."
                    fi
                done
                break
            elif [[ "$pf_mode" == "2" ]]; then
                # Advanced mode - for complex VPN setups
                print_info "\n--- Advanced VPN Port Forwarding (Guided) ---"
                print_info "This mode allows custom port mapping for complex VPN setups."
                print_info "Most users should use Simple mode. Only use Advanced if you need:"
                print_info "  • Different ports on Iran vs foreign server"
                print_info "  • Multiple VPN panels on different IPs"
                print_info "  • Custom routing scenarios"
                print_info "Example: 443=8443 (Iran port 443 → foreign port 8443)"
                
                local pf_rules=()
                while true; do
                    print_info "\n--- Add Advanced VPN Port Forwarding Rule ---"
                    
                    # Local port (Iran server port)
                    while true; do
                        read -p "Iran server port to listen on [443]: " local_port
                        if [[ "$local_port" == "?" || "$local_port" == "h" ]]; then
                            print_info "This is the port on Iran server that users will connect to"
                            print_info "Common ports: 80 (HTTP), 443 (HTTPS), 8080, 8443"
                            continue
                        fi
                        local_port=${local_port:-443}
                        if ! validate_port "$local_port"; then
                            print_warning "Invalid port number."
                            continue
                        fi
                        break
                    done
                    
                    # Remote port (Foreign server VPN panel port)
                    while true; do
                        read -p "Foreign server VPN panel port [443]: " remote_port
                        if [[ "$remote_port" == "?" || "$remote_port" == "h" ]]; then
                            print_info "This is the port on your foreign server where VPN panel is running"
                            print_info "Common ports: 80 (HTTP), 443 (HTTPS), 8080, 8443"
                            continue
                        fi
                        remote_port=${remote_port:-443}
                        if ! validate_port "$remote_port"; then
                            print_warning "Invalid port number."
                            continue
                        fi
                        break
                    done
                    
                    # Remote IP (optional - for multiple VPN panels)
                    print_info "Remote IP (optional):"
                    print_info "  • Leave blank = forward to foreign server (recommended)"
                    print_info "  • Specific IP = forward to different server (multiple VPN panels)"
                    read -p "Forward to specific remote IP? (leave blank for foreign server): " remote_ip
                    if [[ "$remote_ip" == "?" || "$remote_ip" == "h" ]]; then
                        print_info "Leave blank to forward to the foreign server - recommended for most users"
                        print_info "Or enter a specific IP if you have multiple VPN panels on different servers"
                        continue
                    fi
                    if [[ -n "$remote_ip" ]] && ! validate_ip "$remote_ip"; then
                        print_warning "Invalid IP address format."
                        continue
                    fi
                    
                    # Build the rule
                    local rule="$local_port"
                    if [[ -n "$remote_ip" && -n "$remote_port" ]]; then
                        rule+="=$remote_ip:$remote_port"
                    elif [[ -n "$remote_port" ]]; then
                        rule+="=$remote_port"
                    fi
                    
                    pf_rules+=("$rule")
                    print_success "Added rule: $rule (Iran:$local_port → Foreign:$remote_port)"
                    
                    read -p "Add another rule? (y/n) [n]: " another
                    another=${another:-n}
                    if [[ "${another,,}" != "y" ]]; then break; fi
                done
                
                # Combine all rules
                if [[ ${#pf_rules[@]} -gt 0 ]]; then
                    forwarded_ports_input=$(IFS=, ; echo "${pf_rules[*]}")
                    print_info "\nFinal VPN port forwarding configuration:"
                    local idx=1
                    for r in "${pf_rules[@]}"; do
                        echo "  $idx. $r"
                        ((idx++))
                    done
                else
                    # Default to common VPN web panel ports if no rules added
                    forwarded_ports_input="80,443"
                    print_info "\nNo rules added. Using default VPN web panel ports: 80,443"
                fi
                break
            else
                print_warning "Invalid selection."
            fi
        done
    else # client
        print_info "\n--- Foreign Server Configuration ---"
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
    fi

    # Token prompt (same for both server and client)
    local default_token="vpn-tunnel-naxon"
    while true; do
        read -p "Enter a secure authentication token [default: $default_token, must match on both sides]: " token
        # Use default token if input is empty
        token=${token:-$default_token}
        if [[ -n "$token" ]]; then
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
    
    if [[ $setup_type -eq 2 ]]; then
        # Advanced setup - ask for all settings
        print_info "\n--- Advanced & Transport-Specific Configuration ---"
        while true; do
            read -p "Log Level (debug, info, warn, error) [info]: " log_level
            log_level=${log_level:-info}
            break
        done
        while true; do
            read -p "Enable sniffer (traffic logging)? [false]: " sniffer
            sniffer=${sniffer:-false}
            break
        done
        if [[ "$sniffer" == "true" ]]; then
            while true; do
                read -p "Sniffer log file path [/root/backhaul.json]: " sniffer_log
                sniffer_log=${sniffer_log:-/root/backhaul.json}
                break
            done
        fi
        while true; do
            read -p "Web interface port (0 to disable) [0]: " web_port
            web_port=${web_port:-0}
            break
        done

        if [[ "$TRANSPORT" != "udp" ]]; then
            while true; do
                read -p "Enable TCP_NODELAY for lower latency? [true]: " nodelay
                nodelay=${nodelay:-true}
                break
            done
            while true; do
                read -p "Keep-alive period in seconds [75]: " keepalive_period
                keepalive_period=${keepalive_period:-75}
                break
            done
        fi
        
        if [[ "$INSTALL_MODE" == "server" ]]; then
            while true; do
                read -p "Heartbeat interval in seconds [40]: " heartbeat
                heartbeat=${heartbeat:-40}
                break
            done
            while true; do
                read -p "Channel size [2048]: " channel_size
                channel_size=${channel_size:-2048}
                break
            done
            if [[ "$TRANSPORT" == "tcp" ]]; then
                while true; do
                    read -p "Accept UDP traffic over TCP? [false]: " accept_udp
                    accept_udp=${accept_udp:-false}
                    break
                done
            fi
        else # client
            while true; do
                read -p "Connection pool size [8]: " connection_pool
                connection_pool=${connection_pool:-8}
                break
            done
            while true; do
                read -p "Enable aggressive pool management? [false]: " aggressive_pool
                aggressive_pool=${aggressive_pool:-false}
                break
            done
            while true; do
                read -p "Connection retry interval in seconds [3]: " retry_interval
                retry_interval=${retry_interval:-3}
                break
            done
            while true; do
                read -p "Connection dial timeout in seconds [10]: " dial_timeout
                dial_timeout=${dial_timeout:-10}
                break
            done
        fi

        if [[ "$TRANSPORT" == *"mux"* ]]; then
            print_info "\n--- Multiplexing (MUX) Parameters ---"
            while true; do 
                read -p "Multiplexing concurrency [8]: " mux_con
                mux_con=${mux_con:-8}
                if [[ "$mux_con" =~ ^[0-9]+$ ]]; then
                    break
                else
                    print_error "Must be a positive number."
                fi
            done
            while true; do 
                read -p "SMUX protocol version (1 or 2) [1]: " mux_version
                mux_version=${mux_version:-1}
                if [[ "$mux_version" =~ ^[12]$ ]]; then
                    break
                else
                    print_error "Must be 1 or 2."
                fi
            done
            while true; do 
                read -p "Mux frame size (bytes) [32768]: " mux_framesize
                mux_framesize=${mux_framesize:-32768}
                if [[ "$mux_framesize" =~ ^[0-9]+$ ]]; then
                    break
                else
                    print_error "Must be a positive number."
                fi
            done
            while true; do 
                read -p "Mux receive buffer (bytes) [4194304]: " mux_recievebuffer
                mux_recievebuffer=${mux_recievebuffer:-4194304}
                if [[ "$mux_recievebuffer" =~ ^[0-9]+$ ]]; then
                    break
                else
                    print_error "Must be a positive number."
                fi
            done
            while true; do 
                read -p "Mux stream buffer (bytes) [65536]: " mux_streambuffer
                mux_streambuffer=${mux_streambuffer:-65536}
                if [[ "$mux_streambuffer" =~ ^[0-9]+$ ]]; then
                    break
                else
                    print_error "Must be a positive number."
                fi
            done

            if [[ "$TRANSPORT" == "ws"* && "$INSTALL_MODE" == "client" ]]; then
                print_info "\n--- WebSocket Parameters ---"
                while true; do
                    read -p "Edge IP for CDN connection (optional, press Enter to skip): " edge_ip
                    if [[ -z "$edge_ip" ]]; then
                        break
                    fi
                    break
                done
            fi
        fi
    fi

    if [[ "$TRANSPORT" == "wss"* && "$INSTALL_MODE" == "server" ]]; then
        print_info "\n--- Secure WebSocket (WSS) Certificate Setup ---"
        print_warning "This requires a valid TLS certificate and key."
        local CERT_DIR="/etc/backhaul/certs"
        mkdir -p "$CERT_DIR"
        local newest_cert newest_key
        newest_cert=$(ls -1t "$CERT_DIR"/*.crt 2>/dev/null | head -n1)
        if [[ -n "$newest_cert" ]]; then
            newest_key="${newest_cert%.crt}.key"
            if [ -f "$newest_cert" ] && [ -f "$newest_key" ]; then
                print_info "Found existing certificate: $newest_cert"
                print_info "Associated key: $newest_key"
                read -p "Use this certificate? (Y/n/generate new/manual): " cert_choice
                case "${cert_choice,,}" in
                    ""|y|yes)
                        tls_cert="$newest_cert"
                        tls_key="$newest_key"
                        ;;
                    g|generate)
                        generate_self_signed_cert
                        newest_cert=$(ls -1t "$CERT_DIR"/*.crt 2>/dev/null | head -n1)
                        newest_key="${newest_cert%.crt}.key"
                        tls_cert="$newest_cert"
                        tls_key="$newest_key"
                        ;;
                    m|manual)
                        while true; do
                            read -e -p "Enter the full path to your TLS certificate file: " tls_cert
                            if [ -f "$tls_cert" ]; then break; else print_error "File not found. Please provide a valid path."; fi
                        done
                        while true; do
                            read -e -p "Enter the full path to your TLS private key file: " tls_key
                            if [ -f "$tls_key" ]; then break; else print_error "File not found. Please provide a valid path."; fi
                        done
                        ;;
                    *)
                        tls_cert="$newest_cert"
                        tls_key="$newest_key"
                        ;;
                esac
            else
                print_info "No valid certificate/key pair found. Generating a new one."
                generate_self_signed_cert
                newest_cert=$(ls -1t "$CERT_DIR"/*.crt 2>/dev/null | head -n1)
                newest_key="${newest_cert%.crt}.key"
                tls_cert="$newest_cert"
                tls_key="$newest_key"
            fi
        else
            print_info "No existing certificates found. Generating a new one."
            generate_self_signed_cert
            newest_cert=$(ls -1t "$CERT_DIR"/*.crt 2>/dev/null | head -n1)
            newest_key="${newest_cert%.crt}.key"
            tls_cert="$newest_cert"
            tls_key="$newest_key"
        fi
    fi

    # --- Step 6: Coordinated Restart on Error (Optional) ---
    if [[ $setup_type -eq 2 ]]; then
        print_info "\n--- Optional: Coordinated Restart on Error ---"
        read -p "Enable coordinated restart-on-error watcher for this tunnel? [n]: " enable_restart
        enable_restart=${enable_restart:-n}
        local restart_pattern restart_delay_local restart_delay_remote restart_secret restart_listen_port restart_remote_port
        if [[ "${enable_restart,,}" == "y" ]]; then
            read -p "Error pattern to trigger restart [ERROR|FATAL]: " restart_pattern
            restart_pattern=${restart_pattern:-ERROR|FATAL}
            read -p "Restart delay (seconds, local side) [10]: " restart_delay_local
            restart_delay_local=${restart_delay_local:-10}
            read -p "Restart delay (seconds, remote side) [10]: " restart_delay_remote
            restart_delay_remote=${restart_delay_remote:-10}
            read -p "Shared secret for restart coordination (leave blank to auto-generate): " restart_secret
            if [[ -z "$restart_secret" ]]; then
                restart_secret=$(generate_restart_secret)
                print_info "Generated secret: $restart_secret"
            fi
            # Prompt for watcher ports
            echo
            print_info "Configure watcher ports:"
            echo "  • Listen port: Where this side receives restart requests from remote"
            echo "  • Remote port: Where this side sends restart requests to remote"
            echo
            print_warning "IMPORTANT: The remote side must use the opposite ports!"
            echo "  If this side listens on 45679, remote must send to 45679"
            echo "  If this side sends to 45680, remote must listen on 45680"
            echo
            read -p "Watcher listen port (receive restart requests) [45679]: " restart_listen_port
            restart_listen_port=${restart_listen_port:-45679}
            read -p "Watcher remote port (send restart requests) [45680]: " restart_remote_port
            restart_remote_port=${restart_remote_port:-45680}
        fi
    else
        # Quick setup - skip restart watcher
        enable_restart="n"
    fi

    # --- Step 7: Build Config & Service ---
    local config_content service_name_suffix
    if [[ "$INSTALL_MODE" == "server" ]]; then
        service_name_suffix="server-${TRANSPORT}-${tunnel_port}"
        config_content="[server]\n"
        config_content+="bind_addr = \"0.0.0.0:$tunnel_port\"\n"
        config_content+="transport = \"$TRANSPORT\"\n"
        config_content+="token = \"$token\"\n"
        config_content+="log_level = \"$log_level\"\n"
        config_content+="heartbeat = $heartbeat\n"
        config_content+="channel_size = $channel_size\n"
        config_content+="sniffer = $sniffer\n"
        config_content+="sniffer_log = \"$sniffer_log\"\n"
        config_content+="web_port = $web_port\n"
        if [[ "$TRANSPORT" != "udp" ]]; then
            config_content+="nodelay = $nodelay\n"
            config_content+="keepalive_period = $keepalive_period\n"
        fi
        if [[ "$TRANSPORT" == "tcp" ]]; then config_content+="accept_udp = $accept_udp\n"; fi
        if [[ "$TRANSPORT" == "wss"* ]]; then
            config_content+="tls_cert = \"$tls_cert\"\n"
            config_content+="tls_key = \"$tls_key\"\n"
        fi
        
        local ports_toml=""
        IFS=',' read -ra ADDR <<< "$forwarded_ports_input"
        for p in "${ADDR[@]}"; do
            p=$(echo "$p" | tr -d ' ')
            [ -n "$p" ] && ports_toml+="\"$p\", "
        done
        ports_toml=${ports_toml%, }
        [ -n "$ports_toml" ] && config_content+="ports = [$ports_toml]\n"
        
        # Add restart watcher config as TOML comments/keys
        config_content+="\n# Coordinated Restart Watcher\n"
        config_content+="restart_watcher_enabled = \"${enable_restart,,}\"\n"
        if [[ "${enable_restart,,}" == "y" ]]; then
            config_content+="restart_watcher_pattern = \"$restart_pattern\"\n"
            config_content+="restart_watcher_delay_local = $restart_delay_local\n"
            config_content+="restart_watcher_delay_remote = $restart_delay_remote\n"
            config_content+="restart_watcher_secret = \"$restart_secret\"\n"
            config_content+="restart_watcher_listen_port = $restart_listen_port\n"
            config_content+="restart_watcher_remote_port = $restart_remote_port\n"
        fi
    else # client
        service_name_suffix="client-${TRANSPORT}-$(echo "$server_ip" | tr '.' '-')-${tunnel_port}"
        config_content="[client]\n"
        config_content+="remote_addr = \"$server_ip:$tunnel_port\"\n"
        if [ -n "$edge_ip" ]; then config_content+="edge_ip = \"$edge_ip\"\n"; fi
        config_content+="transport = \"$TRANSPORT\"\n"
        config_content+="token = \"$token\"\n"
        config_content+="log_level = \"$log_level\"\n"
        config_content+="connection_pool = $connection_pool\n"
        config_content+="aggressive_pool = $aggressive_pool\n"
        config_content+="retry_interval = $retry_interval\n"
        config_content+="dial_timeout = $dial_timeout\n"
        config_content+="sniffer = $sniffer\n"
        config_content+="sniffer_log = \"$sniffer_log\"\n"
        config_content+="web_port = $web_port\n"
        if [[ "$TRANSPORT" != "udp" ]]; then
            config_content+="nodelay = $nodelay\n"
            config_content+="keepalive_period = $keepalive_period\n"
        fi
    fi
    
    if [[ "$TRANSPORT" == *"mux"* ]]; then
        config_content+="\n# MUX Parameters\n"
        if [[ "$INSTALL_MODE" == "server" ]]; then config_content+="mux_con = $mux_con\n"; fi
        config_content+="mux_version = $mux_version\n"
        config_content+="mux_framesize = $mux_framesize\n"
        config_content+="mux_recievebuffer = $mux_recievebuffer\n"
        config_content+="mux_streambuffer = $mux_streambuffer\n"
    fi

    # Add restart watcher config for client mode
    if [[ "$INSTALL_MODE" == "client" ]]; then
        config_content+="\n# Coordinated Restart Watcher\n"
        config_content+="restart_watcher_enabled = \"${enable_restart,,}\"\n"
        if [[ "${enable_restart,,}" == "y" ]]; then
            config_content+="restart_watcher_pattern = \"$restart_pattern\"\n"
            config_content+="restart_watcher_delay_local = $restart_delay_local\n"
            config_content+="restart_watcher_delay_remote = $restart_delay_remote\n"
            config_content+="restart_watcher_secret = \"$restart_secret\"\n"
            config_content+="restart_watcher_listen_port = $restart_listen_port\n"
            config_content+="restart_watcher_remote_port = $restart_remote_port\n"
        fi
    fi

    # --- Step 8: Confirmation and Creation ---
    clear
    print_server_info_banner
    print_info "--- Configuration Summary ---"
    echo -e "$config_content"
    echo "---------------------------"
    read -p "Is this configuration correct? [y]: " confirm
    confirm=${confirm:-y}
    if [[ "${confirm,,}" != "y" ]]; then
        print_warning "Configuration cancelled. You can go back and edit your entries."
        press_any_key
        return 1
    fi

    mkdir -p "$CONFIG_DIR"
    local config_file="$CONFIG_DIR/config-${service_name_suffix}.toml"
    
    if [ -f "$config_file" ]; then
        print_warning "A configuration file for this tunnel already exists: $config_file"
        if confirm_action "Do you want to create a backup before overwriting?" "y"; then
            backup_config "$config_file"
            print_success "Backup created."
        fi
    fi

    echo -e "$config_content" > "$config_file"
    chmod 600 "$config_file"
    print_success "Configuration file created: $config_file"

    if [[ "$INSTALL_MODE" == "server" ]]; then
        manage_ufw_add "$tunnel_port" "$TRANSPORT" "$service_name_suffix"
        # Add UFW rule for watcher listen port if enabled
        if [[ "${enable_restart,,}" == "y" ]]; then
            manage_ufw_add "$restart_listen_port" "tcp" "${service_name_suffix}-watcher"
        fi
    fi

    create_systemd_service "$service_name_suffix" "$config_file"
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
    echo ""
    echo "=== Backup Configuration ==="
    
    local backup_dir="$CONFIG_DIR/backups"
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    local backup_file="$backup_dir/easybackhaul_backup_$timestamp.tar.gz"
    
    # Create backup directory with secure permissions
    mkdir -p "$backup_dir"
    harden_permissions "$backup_dir"
    
    # Create backup
    tar -czf "$backup_file" -C "$CONFIG_DIR" . 2>/dev/null
    
    if [ $? -eq 0 ]; then
        # Set secure permissions on backup file
        chmod 600 "$backup_file"
        
        echo "✅ Configuration backed up to: $backup_file"
        echo "📊 Backup size: $(du -h "$backup_file" | cut -f1)"
        
        # List recent backups
        echo ""
        echo "Recent backups:"
        ls -la "$backup_dir"/*.tar.gz 2>/dev/null | tail -5 || echo "No previous backups found"
        
        secure_log_message "INFO" "Configuration backed up to $backup_file"
    else
        echo "❌ Backup failed"
        log_message "ERROR" "Configuration backup failed"
    fi
}

restore_configuration() {
    echo ""
    echo "=== Restore Configuration ==="
    
    local backup_dir="$CONFIG_DIR/backups"
    
    if [ ! -d "$backup_dir" ]; then
        echo "❌ No backup directory found"
        return 1
    fi
    
    # List available backups
    local backups=($(ls "$backup_dir"/*.tar.gz 2>/dev/null))
    
    if [ ${#backups[@]} -eq 0 ]; then
        echo "❌ No backup files found"
        return 1
    fi
    
    echo "Available backups:"
    for i in "${!backups[@]}"; do
        local backup_file="${backups[$i]}"
        local backup_name=$(basename "$backup_file")
        local backup_size=$(du -h "$backup_file" | cut -f1)
        local backup_date=$(stat -c %y "$backup_file" 2>/dev/null | cut -d' ' -f1)
        echo "$((i+1))) $backup_name ($backup_size, $backup_date)"
    done
    
    echo ""
    read -p "Select backup to restore (1-${#backups[@]}): " choice
    
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt ${#backups[@]} ]; then
        echo "❌ Invalid selection"
        return 1
    fi
    
    local selected_backup="${backups[$((choice-1))]}"
    
    echo ""
    echo "⚠ WARNING: This will overwrite current configuration."
    echo "   Backup file: $selected_backup"
    read -p "Proceed with restore? (y/n): " confirm
    
    if [ "$confirm" != "y" ]; then
        echo "❌ Restore cancelled"
        return 1
    fi
    
    # Create temporary restore directory
    local temp_restore=$(mktemp -d)
    
    # Extract backup
    if tar -xzf "$selected_backup" -C "$temp_restore" 2>/dev/null; then
        # Validate extracted files
        if [ -f "$temp_restore/config" ]; then
            # Backup current config
            if [ -f "$CONFIG_FILE" ]; then
                cp "$CONFIG_FILE" "$CONFIG_FILE.bak.$(date '+%Y%m%d_%H%M%S')"
            fi
            
            # Restore files
            cp -r "$temp_restore"/* "$CONFIG_DIR/"
            
            # Set secure permissions
            harden_permissions "$CONFIG_DIR"
            secure_config_file "$CONFIG_FILE"
            
            echo "✅ Configuration restored successfully"
            secure_log_message "INFO" "Configuration restored from $selected_backup"
        else
            echo "❌ Invalid backup file (missing config)"
            log_message "ERROR" "Invalid backup file structure"
        fi
    else
        echo "❌ Failed to extract backup file"
        log_message "ERROR" "Backup extraction failed"
    fi
    
    # Clean up
    rm -rf "$temp_restore"
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

