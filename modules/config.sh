# modules/config.sh
# Tunnel configuration wizard and related TOML file management.

# WARNING: Do not use a global CONFIG_FILE variable. All configurations are per-tunnel TOML files.

# --- Helper: Get process information for a port ---
# This is kept here as it's specific to the config wizard's port checking UX
_get_port_process_info() {
    local port_to_check="$1"
    log_message "DEBUG" "Checking process for port $port_to_check"
    
    if command -v ss &>/dev/null; then
        # Using ss for more detailed info, including user if possible
        ss -lntupe "sport = :$port_to_check" 2>/dev/null | awk 'NR>1 {print "  - Process (ss): " $0}' && return 0
    fi
    if command -v netstat &>/dev/null; then
        netstat -tlnp 2>/dev/null | grep ":${port_to_check}[[:space:]]" | awk '{print "  - Process (netstat): " $0}' && return 0
    fi
    if command -v lsof &>/dev/null; then # More resource intensive
        lsof -i ":$port_to_check" -sTCP:LISTEN -P -n -- 2>/dev/null | awk 'NR>1 {print "  - Process (lsof): " $0}' && return 0
    fi
    print_info "  Port $port_to_check is in use, but detailed process info unavailable with current tools."
    return 1
}


# --- Sub-functions for configure_tunnel wizard ---

_prompt_setup_type_and_mode() {
    local -n setup_type_choice_ref=$1 # Output: 1 for Quick, 2 for Advanced
    local -n tunnel_mode_ref=$2       # Output: "server" or "client"

    print_menu_header "secondary" "Tunnel Setup Type" "Step 1 of 5: Setup Type"
    local setup_options=("1. Quick Setup (Recommended)" "2. Advanced Setup")
    local setup_exit_details=("0" "Back to Main Menu") # Array: [key, text]
    _setup_type_help() {
        print_info "Setup Type Help:"
        echo " - Quick Setup: Uses sensible defaults for most common scenarios."
        echo " - Advanced Setup: Allows manual configuration of all parameters."
        press_any_key
    }
    menu_loop "Select setup type" setup_options setup_exit_details "_setup_type_help"
    local menu_rc=$?
    case "$menu_rc" in
        3) go_to_main_menu; return 0 ;; # m -> main menu
        4) request_script_exit; return 0 ;; # e -> exit script
        5) return_from_menu; return 0 ;; # r -> return/back (to previous menu, likely main menu here)
        2) _prompt_setup_type_and_mode setup_type_choice_ref tunnel_mode_ref; return $? ;; # ? -> help shown, re-call current function
        0) # Numeric choice or default exit "0"
           if [[ "$MENU_CHOICE" == "0" ]]; then return_from_menu; return 0; fi # Explicit "0" handled as back
           : # No-op if MENU_CHOICE was numeric and not "0"
           ;;
        *) handle_error "ERROR" "Unhandled menu_loop code $menu_rc in _prompt_setup_type_and_mode"; return 1;;
    esac
    # If we reach here, menu_rc was 0 and MENU_CHOICE is a valid numeric option
    setup_type_choice_ref="$MENU_CHOICE"

    # --- Mode (Server/Client) ---
    print_menu_header "secondary" "Tunnel Mode" "Step 2 of 5: Select Mode"
    local default_mode_val="2" # Default to client if not Iran
    local detected_loc_info=""
    if [[ -n "$SERVER_COUNTRY" && "$SERVER_COUNTRY" != "N/A" ]]; then
        if [[ "$SERVER_COUNTRY" == "IR" ]]; then
            default_mode_val="1"
            detected_loc_info="Detected server location: Iran (Suggesting Server Mode)"
        else
            detected_loc_info="Detected server location: $SERVER_COUNTRY (Suggesting Client Mode)"
        fi
        print_info "$detected_loc_info"
    else
        print_info "Server location unknown. Please choose mode carefully."
    fi

    local mode_options=("1. Server (Listens for connections - typically on Iran VPS)" "2. Client (Connects to a server - typically on Foreign VPS)")
    _mode_help() {
        print_info "Tunnel Mode Help:"
        echo " - Server Mode: This machine will act as the entry point for users."
        echo "                It listens for incoming connections from Backhaul clients."
        echo " - Client Mode: This machine will connect out to a Backhaul server."
        echo "                It forwards traffic from a local port to the remote server."
        press_any_key
    }
    # setup_exit_details is ("0" "Back to Main Menu")
    menu_loop "Select tunnel mode (Default: $default_mode_val)" mode_options setup_exit_details "_mode_help"
    menu_rc=$?
    case "$menu_rc" in
        3) go_to_main_menu; return 0 ;;
        4) request_script_exit; return 0 ;;
        5) _prompt_setup_type_and_mode setup_type_choice_ref tunnel_mode_ref; return $? ;; # 'r' goes back to previous step (setup type)
        2) # Help shown, re-call current step/function
            # This recursive call needs careful thought or a loop structure within _prompt_setup_type_and_mode
            # For now, let the outer configure_tunnel loop handle it by returning a specific code if needed,
            # or simply re-prompt by continuing the while loop within this function if it had one.
            # Given the current structure, making it re-call itself for this step:
            _prompt_setup_type_and_mode setup_type_choice_ref tunnel_mode_ref; return $? ;;
        0) # Numeric choice or default exit "0"
           if [[ "$MENU_CHOICE" == "0" ]]; then return_from_menu; return 0; fi # Explicit "0" handled as back to main menu
           : # No-op if MENU_CHOICE was numeric and not "0"
           ;;
        *) handle_error "ERROR" "Unhandled menu_loop code $menu_rc in tunnel mode selection"; return 1;;
    esac

    if [[ "$MENU_CHOICE" == "1" ]]; then
        tunnel_mode_ref="server"
    elif [[ "$MENU_CHOICE" == "2" ]]; then
        tunnel_mode_ref="client"
    else
        handle_error "ERROR" "Invalid mode choice '$MENU_CHOICE' from menu_loop." # Should not happen if menu_loop is correct
        return 1
    fi
    return 0
}

_prompt_transport_protocol() {
    local setup_type_choice=$1   # 1 for Quick, 2 for Advanced
    local -n transport_ref=$2    # Output: selected transport string (e.g., "tcp")

    print_menu_header "secondary" "Transport Protocol" "Step 3 of 5: Select Protocol"

    local transport_options_arr=(
        "tcp (Standard, reliable)"
        "ws (WebSocket, good for CDNs/firewalls)"
        "wss (Secure WebSocket, encrypted)"
        "tcpmux (Multiplexed TCP)"
        "wsmux (Multiplexed WebSocket)"
        "wssmux (Multiplexed Secure WebSocket)"
        "udp (For UDP-based applications)"
    )
    local all_transport_choices=()
    for i in "${!transport_options_arr[@]}"; do
        all_transport_choices+=("$(($i + 1)). ${transport_options_arr[$i]}")
    done
    
    local quick_transport_choices=(
        "1. ${transport_options_arr[0]}" # tcp
        "2. ${transport_options_arr[1]}" # ws
        "3. ${transport_options_arr[2]}" # wss
        "4. Show all options"
    )
    local current_exit_details=("0" "Back to Main Menu") # Array: [key, text]

    _transport_help() {
        print_info "Transport Protocol Help:"
        echo " - tcp: Standard, fast, and reliable."
        echo " - ws: WebSocket, useful for proxying through CDNs like Cloudflare."
        echo " - wss: Secure WebSocket (TLS/SSL encrypted), also good for CDNs."
        echo " - *mux: Multiplexed versions allow multiple streams over one connection."
        echo " - udp: For applications requiring UDP (e.g., some games, VoIP)."
        press_any_key
    }

    if [[ "$setup_type_choice" -eq 1 ]]; then # Quick setup
        menu_loop "Select transport (Default: 1 for TCP)" quick_transport_choices current_exit_details "_transport_help"
        local menu_rc=$?
        case "$menu_rc" in
            3) go_to_main_menu; return 0 ;; 4) request_script_exit; return 0 ;;
            5) _prompt_setup_type_and_mode setup_type_choice_ref tunnel_mode_ref; return $? ;; # 'r' to go back to mode selection
            2) _prompt_transport_protocol "$setup_type_choice" transport_ref; return $? ;; # '?' to re-call
            0) if [[ "$MENU_CHOICE" == "0" ]]; then return_from_menu; return 0; fi
               : # No-op for other numeric choices handled by menu_rc=0
               ;;
            *) handle_error "ERROR" "Unhandled menu_loop code $menu_rc in quick transport selection"; return 1;;
        esac
        
        case "$MENU_CHOICE" in
            "1") : ; transport_ref="tcp" ;;
            "2") : ; transport_ref="ws" ;;
            "3") : ; transport_ref="wss" ;;
            "4") # Show all options
                : ; # Added colon for case "4"
                print_menu_header "secondary" "All Transport Protocols" "Step 3 of 5 (Detail)"
                menu_loop "Select transport (Default: 1 for TCP)" all_transport_choices current_exit_details "_transport_help"
                menu_rc=$?
                case "$menu_rc" in
                    3) : ; go_to_main_menu; return 0 ;;
                    4) : ; request_script_exit; return 0 ;;
                    5) : ; _prompt_transport_protocol "$setup_type_choice" transport_ref; return $? ;; # 'r' to go back to quick transport options
                    2) # Re-call this specific sub-part (all options)
                        : ; # Added colon
                        # This needs a slight restructure or a loop to show all options again.
                        # For now, this will re-call the parent _prompt_transport_protocol.
                        _prompt_transport_protocol "$setup_type_choice" transport_ref; return $? ;;
                    0) if [[ "$MENU_CHOICE" == "0" ]]; then return_from_menu; return 0; fi
                       : # No-op
                       ;;
                    *) : ; handle_error "ERROR" "Unhandled menu_loop code $menu_rc in all transport selection"; return 1;;
                esac

                if [[ "$MENU_CHOICE" -ge 1 && "$MENU_CHOICE" -le ${#transport_options_arr[@]} ]]; then
                    transport_ref=$(echo "${transport_options_arr[$(($MENU_CHOICE-1))]}" | awk '{print $1}')
                else
                    handle_error "ERROR" "Invalid transport selection from all options."; return 1;
                fi
                ;;
            *) handle_error "ERROR" "Invalid quick transport choice: $MENU_CHOICE."; return 1 ;;
        esac
    else # Advanced setup
        menu_loop "Select transport protocol" all_transport_choices current_exit_details "_transport_help"
        local menu_rc=$?
        case "$menu_rc" in
            3) go_to_main_menu; return 0 ;; 4) request_script_exit; return 0 ;;
            5) _prompt_setup_type_and_mode setup_type_choice_ref tunnel_mode_ref; return $? ;; # 'r' to go back to mode selection
            2) _prompt_transport_protocol "$setup_type_choice" transport_ref; return $? ;; # '?' to re-call
            0) if [[ "$MENU_CHOICE" == "0" ]]; then return_from_menu; return 0; fi
               : # No-op
               ;;
            *) handle_error "ERROR" "Unhandled menu_loop code $menu_rc in advanced transport selection"; return 1;;
        esac

        if [[ "$MENU_CHOICE" -ge 1 && "$MENU_CHOICE" -le ${#transport_options_arr[@]} ]]; then
            transport_ref=$(echo "${transport_options_arr[$(($MENU_CHOICE-1))]}" | awk '{print $1}')
        else
            handle_error "ERROR" "Invalid advanced transport selection: $MENU_CHOICE."; return 1;
        fi
    fi
    log_message "INFO" "Selected transport: $transport_ref"
    return 0
}

_prompt_basic_config_params() {
    local tunnel_mode="$1"      # "server" or "client"
    local -n listen_port_ref=$2 # Output for server mode
    local -n remote_ip_ref=$3   # Output for client mode
    local -n remote_port_ref=$4 # Output for client mode
    local -n local_fwd_port_ref=$5 # Output for client mode (local port to forward from)
    local -n auth_token_ref=$6  # Output: auth token

    print_menu_header "secondary" "Basic Configuration" "Step 4 of 5"

    if [[ "$tunnel_mode" == "server" ]]; then
        print_info "Server Mode: Configure listening port."
        local default_listen_port=443
        # Ensure SERVER_IP is available for port conflict check context if needed
        if [[ -z "$SERVER_IP" || "$SERVER_IP" == "N/A" ]]; then get_server_info; fi

        while true; do
            read -r -p "Enter port for Backhaul server to listen on (e.g., 443, 8080) [${default_listen_port}]: " listen_port_val
            listen_port_val=${listen_port_val:-$default_listen_port}
            if ! validate_port "$listen_port_val"; then
                print_warning "Invalid port number. Must be 1-65535."
            elif ! check_port_availability "$listen_port_val"; then
                print_warning "Port $listen_port_val is currently in use on this server."
                _get_port_process_info "$listen_port_val" # Show what's using it
                if ! prompt_yes_no "Use this port anyway (if the process is temporary or will be stopped)?" "n"; then
                    continue # Ask for port again
                fi
                listen_port_ref="$listen_port_val"
                break
            else
                listen_port_ref="$listen_port_val"
                print_success "Port $listen_port_ref is available."
                break
            fi
        done
    else # client mode
        print_info "Client Mode: Configure remote server details and local forwarding port."
        while true; do
            read -r -p "Enter the public IP address of the Backhaul SERVER: " remote_ip_val
            if validate_ip "$remote_ip_val"; then
                if prompt_yes_no "Ping $remote_ip_val to check reachability?" "y"; then
                    run_with_spinner "Pinging $remote_ip_val..." ping -c 2 -W 2 "$remote_ip_val"
                fi
                remote_ip_ref="$remote_ip_val"
                break
            else
                print_warning "Invalid IP address format."
            fi
        done
        
        local default_remote_port=443
        while true; do
            read -r -p "Enter the port the Backhaul SERVER is listening on [${default_remote_port}]: " remote_port_val
            remote_port_val=${remote_port_val:-$default_remote_port}
            if validate_port "$remote_port_val"; then
                remote_port_ref="$remote_port_val"
                break
            else
                print_warning "Invalid port number."
            fi
        done

        local default_local_fwd_port=1080 # Common for SOCKS or local proxy
        print_info "Enter the local port this client will listen on to forward traffic."
        while true; do
            read -r -p "Local forwarding port on THIS machine (e.g., 1080, 8000) [${default_local_fwd_port}]: " local_fwd_port_val
            local_fwd_port_val=${local_fwd_port_val:-$default_local_fwd_port}
            if ! validate_port "$local_fwd_port_val"; then
                print_warning "Invalid port number."
            elif ! check_port_availability "$local_fwd_port_val"; then
                print_warning "Port $local_fwd_port_val is currently in use on this machine."
                _get_port_process_info "$local_fwd_port_val"
                 if ! prompt_yes_no "Use this port anyway?" "n"; then
                    continue
                fi
                local_fwd_port_ref="$local_fwd_port_val"
                break
            else
                local_fwd_port_ref="$local_fwd_port_val"
                print_success "Local forwarding port $local_fwd_port_ref is available."
                break
            fi
        done
    fi

    # Auth Token
    local default_auth_token="EasyBackhaulSecretToken" # More descriptive default
    print_info "Set an authentication token (must match on both server and client)."
    while true; do
        read -r -s -p "Enter auth token (min 8 chars) [${default_auth_token}]: " auth_token_val
        echo # Newline after secret input
        auth_token_val=${auth_token_val:-$default_auth_token}
        if [[ "${#auth_token_val}" -lt 8 ]]; then
            print_warning "Token too short. Please use at least 8 characters for security."
        else
            auth_token_ref="$auth_token_val"
            break
        fi
    done
    return 0
}

_prompt_tls_config() {
    local transport="$1"
    local -n tls_cert_path_ref=$2
    local -n tls_key_path_ref=$3

    if [[ ! "$transport" =~ ^(wss|wssmux)$ ]]; then
        return 0 # No TLS needed
    fi

    print_menu_header "secondary" "TLS Certificate Configuration" "Secure Protocols (WSS/WSSMUX)"
    print_info "Secure protocols (WSS/WSSMUX) require a TLS certificate and private key."

    local cert_dir_global="${CERT_DIR:-/etc/easybackhaul/certs}" # From globals.sh
    ensure_dir "$cert_dir_global" "700"
    
    mapfile -t existing_certs < <(find "$cert_dir_global" -maxdepth 1 -name '*.pem' -o -name '*.crt' 2>/dev/null | sort)
    
    local tls_options=()
    local cert_map=() # Associative array to map choice number to path

    if [[ ${#existing_certs[@]} -gt 0 ]]; then
        print_info "Existing certificates/keys found in $cert_dir_global:"
        local count=1
        for cert_file in "${existing_certs[@]}"; do
            # Heuristic to find matching key: replace .crt/.pem with .key
            local potential_key_file="${cert_file%.*}.key"
            if [[ ! -f "$potential_key_file" ]]; then potential_key_file="${cert_file%.*}.pem"; fi # Some might use .pem for keys too

            if [[ -f "$potential_key_file" ]]; then
                 tls_options+=("$count. Use: $(basename "$cert_file") + $(basename "$potential_key_file")")
                 cert_map[$count]="$cert_file;$potential_key_file" # Store pair
                 ((count++))
            else
                print_warning "Certificate $(basename "$cert_file") found without a clearly matching .key file, skipping."
            fi
        done
    fi
    tls_options+=("$((${#cert_map[@]} + 1)). Generate New Self-Signed Certificate")
    local generate_new_opt_num=$((${#cert_map[@]} + 1))
    
    local current_exit_details=("0" "Skip TLS (Not Recommended for WSS/WSSMUX)") # Array: [key, text]
    _tls_help() {
        print_info "TLS Configuration Help:"
        echo " - Select an existing certificate/key pair if available."
        echo " - Choose 'Generate New' to create a self-signed certificate."
        echo " - Skipping TLS for WSS/WSSMUX will likely cause connection failures."
        echo " - Certificate paths are stored in the tunnel's TOML config file."
        press_any_key
    }

    menu_loop "Select TLS certificate option" tls_options current_exit_details "_tls_help"
    local menu_rc=$?
    local user_choice="$MENU_CHOICE" # Capture choice before potential navigation

    case "$menu_rc" in
        3) go_to_main_menu; return 0 ;; 4) request_script_exit; return 0 ;;
        5) _prompt_basic_config_params "$tunnel_mode" server_listen_port client_remote_ip client_remote_port client_local_fwd_port common_auth_token; return $? ;; # 'r' to go back to basic params
        2) _prompt_tls_config "$transport" tls_cert_path_ref tls_key_path_ref; return $? ;; # '?' to re-call
        0) # Numeric choice or default exit "0"
           # Proceed to specific choice handling below
           : # No-op, allow execution to continue after the case statement
           ;;
        *) handle_error "ERROR" "Unhandled menu_loop code $menu_rc in TLS config"; return 1;;
    esac

    if [[ "$user_choice" == "0" ]]; then # Default exit for this menu (Skip TLS)
        print_warning "Skipping TLS configuration. WSS/WSSMUX will likely not work without it."
        tls_cert_path_ref=""
        tls_key_path_ref=""
        return 0
    elif (( MENU_CHOICE == generate_new_opt_num )); then
        if generate_self_signed_tls_cert; then # Uses its own internal prompts
            # Need to find the newest cert/key pair generated
            local new_cert=$(find "$cert_dir_global" -name '*.pem' -o -name '*.crt' -print0 | xargs -0 stat -c "%Y %n" | sort -nr | head -n1 | awk '{print $2}')
            local new_key="${new_cert%.*}.key" # Assuming .key based on generate_self_signed_tls_cert
             if [[ ! -f "$new_key" ]]; then new_key="${new_cert%.*}.pem"; fi


            if [[ -f "$new_cert" && -f "$new_key" ]]; then
                tls_cert_path_ref="$new_cert"
                tls_key_path_ref="$new_key"
                print_success "Using newly generated cert: $tls_cert_path_ref and key: $tls_key_path_ref"
            else
                handle_error "ERROR" "Failed to identify newly generated certificate/key pair."
                return 1
            fi
        else
            handle_error "ERROR" "Self-signed certificate generation failed."
            return 1
        fi
    elif [[ -n "${cert_map[$MENU_CHOICE]}" ]]; then
        IFS=';' read -r tls_cert_path_ref tls_key_path_ref <<< "${cert_map[$MENU_CHOICE]}"
        print_success "Using selected cert: $tls_cert_path_ref and key: $tls_key_path_ref"
    else
        handle_error "ERROR" "Invalid TLS certificate selection."
        return 1
    fi
    return 0
}

# --- Main Configuration Wizard ---
configure_tunnel() {
    # Initialize local variables to store configuration parameters
    local setup_is_advanced=false # Default to quick setup
    local tunnel_mode=""          # "server" or "client"
    local transport_protocol=""

    local server_listen_port=""   # For server mode
    local client_remote_ip=""     # For client mode
    local client_remote_port=""   # For client mode
    local client_local_fwd_port="" # For client mode
    local common_auth_token=""

    local cfg_tls_cert_path=""
    local cfg_tls_key_path=""

    # Advanced parameters with defaults
    local cfg_log_level="info"
    local cfg_sniffer="false"
    local cfg_sniffer_log="/var/log/easybackhaul/$(date +%s%N)-sniffer.json" # Default, needs tunnel name later
    local cfg_web_port=0
    local cfg_nodelay="true" # Common for TCP-based
    local cfg_keepalive_period=75
    # Server specific advanced
    local cfg_heartbeat=40
    local cfg_channel_size=2048
    local cfg_accept_udp="false" # Only for TCP server
    # Client specific advanced
    local cfg_connection_pool=8
    local cfg_aggressive_pool="false"
    local cfg_retry_interval=3
    local cfg_dial_timeout=10
    # MUX specific advanced
    local cfg_mux_con=8
    local cfg_mux_version=1 # Default to SMUX v1 usually
    local cfg_mux_framesize=32768
    local cfg_mux_receivebuffer=4194304 # Renamed from recieve to receive
    local cfg_mux_streambuffer=65536

    # --- Step 1 & 2: Setup Type (Quick/Advanced) and Mode (Server/Client) ---
    local setup_choice_val
    if ! _prompt_setup_type_and_mode setup_choice_val tunnel_mode; then
        # Handles navigation/exit signals from menu_loop
        if [[ "$CURRENT_MENU_FUNCTION" == "main_menu" || -z "$CURRENT_MENU_FUNCTION" ]]; then return_from_menu; fi
        return # Propagate exit/back to main menu loop
    fi
    [[ "$setup_choice_val" -eq 2 ]] && setup_is_advanced=true
    log_message "INFO" "Setup type: $(if $setup_is_advanced; then echo "Advanced"; else echo "Quick"; fi), Mode: $tunnel_mode"

    # --- Step 3: Transport Protocol ---
    if ! _prompt_transport_protocol "$setup_choice_val" transport_protocol; then
        if [[ "$CURRENT_MENU_FUNCTION" == "main_menu" || -z "$CURRENT_MENU_FUNCTION" ]]; then return_from_menu; fi
        return
    fi

    # --- Step 4: Basic Configuration (Ports, IP, Token) ---
    if ! _prompt_basic_config_params "$tunnel_mode" \
        server_listen_port client_remote_ip client_remote_port client_local_fwd_port \
        common_auth_token; then
        if [[ "$CURRENT_MENU_FUNCTION" == "main_menu" || -z "$CURRENT_MENU_FUNCTION" ]]; then return_from_menu; fi
        return
    fi

    # --- Step 5 (Conditional): Advanced Configuration ---
    if $setup_is_advanced; then
        # This would call a new sub-function: _prompt_advanced_parameters
        # For now, we'll just note that it would happen here.
        # _prompt_advanced_parameters "$tunnel_mode" "$transport_protocol" cfg_log_level ... (all cfg_* vars by ref)
        print_info "Advanced parameter prompting would occur here." # Placeholder
        # This part needs to be fully implemented similar to other _prompt_* functions
        # For brevity in this refactoring phase, we'll use defaults for advanced if not explicitly prompted
        log_message "INFO" "Advanced setup chosen - advanced parameters would be prompted here."
    fi

    # --- Step 6 (Conditional): TLS Configuration ---
    if [[ "$transport_protocol" =~ ^(wss|wssmux)$ ]]; then
        if ! _prompt_tls_config "$transport_protocol" cfg_tls_cert_path cfg_tls_key_path; then
             if [[ "$CURRENT_MENU_FUNCTION" == "main_menu" || -z "$CURRENT_MENU_FUNCTION" ]]; then return_from_menu; fi
             return
        fi
        if [[ -z "$cfg_tls_cert_path" || -z "$cfg_tls_key_path" ]]; then
            print_warning "WSS/WSSMUX selected but TLS cert/key not configured. Tunnel may not work."
        fi
    fi

    # --- Step 7: Configuration Summary & Confirmation ---
    print_menu_header "secondary" "Configuration Summary" "Review and Confirm"
    echo "  Mode: $tunnel_mode"
    echo "  Transport: $transport_protocol"
    if [[ "$tunnel_mode" == "server" ]]; then
        echo "  Listen Port: $server_listen_port"
    else # client
        echo "  Remote Server: $client_remote_ip:$client_remote_port"
        echo "  Local Forward Port: $client_local_fwd_port"
    fi
    echo "  Auth Token: [set]" # Don't display token
    
    if $setup_is_advanced; then
        echo "  --- Advanced Settings ---"
        echo "  Log Level: $cfg_log_level"
        # ... print other advanced settings ...
    fi
    if [[ -n "$cfg_tls_cert_path" ]]; then
        echo "  TLS Certificate: $cfg_tls_cert_path"
        echo "  TLS Key: $cfg_tls_key_path"
    fi
    
    if ! prompt_yes_no "Proceed with this configuration?" "y"; then
        print_info "Configuration cancelled."
        press_any_key
        return_from_menu # Or go_to_main_menu
        return
    fi

    # --- Step 8: Generate Tunnel Name and Save Configuration ---
    local tunnel_name_suffix
    tunnel_name_suffix="${tunnel_mode}-${transport_protocol}-$(date +%s | tail -c 5)" # Shorter timestamp part
    local final_tunnel_name="bh-$tunnel_name_suffix" # Prefix for clarity

    local config_file_path="$CONFIG_DIR/config-${final_tunnel_name}.toml"
    ensure_dir "$CONFIG_DIR" # From helpers.sh

    # Start building TOML content
    # Using printf for TOML generation for more control over quoting and types
    # Clear file first
    : > "$config_file_path"

    update_toml_value "$config_file_path" "mode" "$tunnel_mode" "string"
    update_toml_value "$config_file_path" "transport" "$transport_protocol" "string"
    update_toml_value "$config_file_path" "auth_token" "$common_auth_token" "string"

    if [[ "$tunnel_mode" == "server" ]]; then
        update_toml_value "$config_file_path" "listen" ":$server_listen_port" "string"
    else # client
        update_toml_value "$config_file_path" "server" "${client_remote_ip}:${client_remote_port}" "string"
        update_toml_value "$config_file_path" "local" ":$client_local_fwd_port" "string"
    fi

    if $setup_is_advanced; then
        update_toml_value "$config_file_path" "log_level" "$cfg_log_level" "string"
        update_toml_value "$config_file_path" "sniffer" "$cfg_sniffer" "boolean"
        if [[ "$cfg_sniffer" == "true" ]]; then
             local final_sniffer_log="/var/log/easybackhaul/${final_tunnel_name}-sniffer.json"
             update_toml_value "$config_file_path" "sniffer_log" "$final_sniffer_log" "string"
        fi
        if (( cfg_web_port > 0 )); then
            update_toml_value "$config_file_path" "web_port" "$cfg_web_port" "numeric"
        fi
        # ... and so on for all advanced parameters using update_toml_value
        # Example for nodelay:
        if [[ "$transport_protocol" != "udp" ]]; then # nodelay is TCP specific
             update_toml_value "$config_file_path" "nodelay" "$cfg_nodelay" "boolean"
             update_toml_value "$config_file_path" "keepalive_period" "$cfg_keepalive_period" "numeric"
        fi
        # ... etc. for all advanced params ...
    fi

    if [[ -n "$cfg_tls_cert_path" && -n "$cfg_tls_key_path" ]]; then
        update_toml_value "$config_file_path" "tls_cert" "$cfg_tls_cert_path" "string"
        update_toml_value "$config_file_path" "tls_key" "$cfg_tls_key_path" "string"
    fi
    
    set_secure_file_permissions "$config_file_path" "600"
    handle_success "Configuration saved: $config_file_path"

    # --- Step 9: Post-creation (Systemd, Start) ---
    # create_systemd_service is in systemd.sh, ensure it's sourced/available
    if type create_systemd_service &>/dev/null; then
        if create_systemd_service "$final_tunnel_name" "$config_file_path"; then # create_systemd_service should handle its own success/error messages
            if prompt_yes_no "Start the tunnel '$final_tunnel_name' now?" "y"; then
                if run_with_spinner "Starting tunnel $final_tunnel_name..." systemctl start "backhaul-${final_tunnel_name}.service"; then
                    handle_success "Tunnel '$final_tunnel_name' started."
                else
                    handle_error "ERROR" "Failed to start tunnel '$final_tunnel_name'. Check logs: journalctl -u backhaul-${final_tunnel_name}.service"
                fi
            else
                print_info "Tunnel '$final_tunnel_name' created but not started."
            fi
        else
             handle_error "ERROR" "Failed to create systemd service for '$final_tunnel_name'."
        fi
    else
        handle_error "WARNING" "Function 'create_systemd_service' not found. Cannot create service automatically."
    fi
    
    press_any_key
    return_from_menu # Return to the menu that called configure_tunnel
}


# --- Decommissioned/Old Functions ---
# update_config_file() { log_message "WARN" "DEPRECATED: update_config_file called. Use TOML-based config."; }
# remove_from_config() { log_message "WARN" "DEPRECATED: remove_from_config called. Use TOML-based config."; }
# backup_configuration() { log_message "WARN" "DEPRECATED: backup_configuration called. Use backup_configuration_path from helpers.sh."; }
# restore_configuration() { log_message "WARN" "DEPRECATED: restore_configuration called."; }
# export_configuration() { log_message "WARN" "DEPRECATED: export_configuration called."; }
# configure_advanced_settings() { log_message "WARN" "DEPRECATED: configure_advanced_settings called."; }


true # Ensure script is valid if sourced.
