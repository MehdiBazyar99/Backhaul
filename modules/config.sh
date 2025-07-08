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

    while true; do # Loop for Setup Type, to allow 'back' from Mode selection
        print_menu_header "secondary" "Tunnel Setup Type" "Step 1a: Setup Type"
        local setup_options=("1. Quick Setup (Recommended)" "2. Advanced Setup")
        _setup_type_help() {
            print_info "Setup Type Help:"
            echo " - Quick Setup: Uses sensible defaults for most common scenarios."
            echo " - Advanced Setup: Allows manual configuration of all parameters."
            echo "Use 'r' to cancel wizard, 'm' for main menu, 'x' to exit script."
            press_any_key
        }
        menu_loop "Select setup type" setup_options "_setup_type_help"
        local menu_rc=$?
        case "$menu_rc" in
            0) # Numeric choice
                setup_type_choice_ref="$MENU_CHOICE"
                # Proceed to Mode selection
                ;;
            2) # '?' Help
                continue # Re-loop for Setup Type
                ;;
            3) # 'm' Main Menu
                print_info "Configuration cancelled: returning to Main Menu."
                return 1 ;; # Signal cancel wizard
            4) # 'x' Exit script
                request_script_exit # This function handles its own exit.
                return 1 # Should not be reached if request_script_exit works.
                ;;
            5) # 'r' Return/Back (from first step is cancel wizard)
                print_info "Configuration cancelled: 'Back' from first step."
                return 1 ;; # Signal cancel wizard
            6)  # Invalid input in menu_loop
                print_info "Invalid setup type selection, please try again." # Optional: more specific message
                # press_any_key already handled by menu_loop before returning 6
                continue ;; # Re-prompt Setup Type
            *)
                handle_error "ERROR" "Unhandled menu_loop code $menu_rc in _prompt_setup_type_and_mode (Setup Type)"
                return 1 ;; # Signal cancel wizard on error
        esac

        # --- Mode (Server/Client) ---
        print_menu_header "secondary" "Tunnel Mode" "Step 1b: Select Mode"
        local default_mode_val="2"
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
        _mode_help_mode() { # Renamed to avoid conflict if _setup_type_help is somehow in scope
            print_info "Tunnel Mode Help:"
            echo " - Server Mode: This machine will act as the entry point for users."
            echo " - Client Mode: This machine will connect out to a Backhaul server."
            echo "Use 'r' to go back to Setup Type, 'm' for main menu, 'x' to exit script."
            press_any_key
        }

        menu_loop "Select tunnel mode (Default: $default_mode_val)" mode_options "_mode_help_mode"
        menu_rc=$?
        case "$menu_rc" in
            0) # Numeric choice
                if [[ "$MENU_CHOICE" == "1" ]]; then
                    tunnel_mode_ref="server"
                elif [[ "$MENU_CHOICE" == "2" ]]; then
                    tunnel_mode_ref="client"
                else
                    handle_error "ERROR" "Invalid mode choice '$MENU_CHOICE' from menu_loop."
                    print_warning "Please try selecting mode again."
                    press_any_key
                    continue 2 # Continue outer loop (Setup Type), effectively restarting Mode selection after Setup Type
                fi
                return 0 # Both parts successful
                ;;
            2) # '?' Help
                continue 2 # Re-loop for Mode (effectively re-prompts Mode after re-printing Setup Type header and re-running Mode logic)
                ;;
            3) # 'm' Main Menu
                print_info "Configuration cancelled: returning to Main Menu."
                return 1 ;; # Signal cancel wizard
            4) # 'x' Exit script
                request_script_exit
                return 1 ;;
            5) # 'r' Return/Back (to Setup Type selection)
                print_info "Going back to Setup Type selection."
                # The outer loop `continue` will handle re-prompting Setup Type
                continue 1 # Continue the outer while loop for Setup Type
                ;;
            6)  # Invalid input in menu_loop
                print_info "Invalid mode selection, please try again."
                # press_any_key handled by menu_loop
                # Need to re-prompt Mode. `continue 2` goes to the Mode part of the outer loop.
                # The '2' in 'continue 2' refers to the second enclosing loop, which is the 'while true'
                # that starts right before "print_menu_header ... Tunnel Mode ... Step 1b".
                # However, the current structure has only one `while true` loop at the top of the function.
                # So, `continue` (or `continue 1`) will restart the whole function from "Setup Type".
                # To re-prompt only "Mode", this sub-case needs to effectively loop back to its own menu_loop.
                # This can be done by simply `continue` which will hit the outer loop, then setup type will be re-confirmed,
                # then mode will be prompted again. This might be acceptable UX.
                # For a true "re-prompt only mode", this section would need its own inner loop.
                # Given the current structure, `continue` (same as `continue 1`) is the simplest.
                continue ;; # Re-prompt from Setup Type, which will then lead to Mode
            *)
                handle_error "ERROR" "Unhandled menu_loop code $menu_rc in _prompt_setup_type_and_mode (Mode)"
                return 1 ;; # Signal cancel wizard on error
        esac
    done # End of while true for Setup Type
}

_prompt_transport_protocol() {
    local setup_type_choice=$1   # 1 for Quick, 2 for Advanced
    local -n transport_ref=$2    # Output: selected transport string (e.g., "tcp")

    # Initial header print for this step
    print_menu_header "secondary" "Transport Protocol" "Step 3 of N: Select Protocol"

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

    _transport_help() {
        print_info "Transport Protocol Help:"
        echo " - tcp: Standard, fast, and reliable."
        echo " - ws: WebSocket, useful for proxying through CDNs like Cloudflare."
        echo " - wss: Secure WebSocket (TLS/SSL encrypted), also good for CDNs."
        echo " - *mux: Multiplexed versions allow multiple streams over one connection."
        echo " - udp: For applications requiring UDP (e.g., some games, VoIP)."
        echo "Use 'r' to return to Mode selection, 'c' to cancel configuration."
        press_any_key
    }

    local show_all_options_now=false
    if [[ "$setup_type_choice" -ne 1 ]]; then # If not quick setup (i.e., advanced)
        show_all_options_now=true
    fi

    local previous_menu_rc_for_header_logic="" # Used to help decide if header needs re-print after help

    while true; do
        local current_options_array_name
        local current_prompt_msg="Select transport"
        local current_header_title="Transport Protocol"
        local current_header_subtitle="Step 2 of N: Select Protocol" # Adjusted step number

        if $show_all_options_now; then
            current_options_array_name="all_transport_choices"
            current_header_title="All Transport Protocols"
            current_header_subtitle="Step 2 of N (Detail)" # Adjusted step number
        else
            current_options_array_name="quick_transport_choices"
            current_prompt_msg="Select transport (Default: 1 for TCP)"
        fi

        # Re-print header if we just switched to "all options" or if we are re-looping after help.
        # Also, ensure the initial header for this function call is printed before the loop.
        # The logic below tries to avoid redundant prints inside the loop.
        if [[ -z "$previous_menu_rc_for_header_logic" ]]; then # First time in loop for this function call
            print_menu_header "secondary" "$current_header_title" "$current_header_subtitle"
        elif $show_all_options_now && [[ "$previous_menu_rc_for_header_logic" != "2" && "$previous_menu_rc_for_header_logic" != "0" ]]; then # Switched to all, and not coming from help or successful choice
             print_menu_header "secondary" "$current_header_title" "$current_header_subtitle"
        elif [[ "$previous_menu_rc_for_header_logic" == "2" ]]; then # Always re-print after help
             print_menu_header "secondary" "$current_header_title" "$current_header_subtitle"
        fi

        menu_loop "$current_prompt_msg" "$current_options_array_name" "_transport_help"
        local menu_rc=$?
        previous_menu_rc_for_header_logic="$menu_rc" # Store for next iteration's header logic

        case "$menu_rc" in
            0) # Numeric choice
                if $show_all_options_now; then
                    if [[ "$MENU_CHOICE" -ge 1 && "$MENU_CHOICE" -le ${#transport_options_arr[@]} ]]; then
                        transport_ref=$(echo "${transport_options_arr[$(($MENU_CHOICE-1))]}" | awk '{print $1}')
                        log_message "INFO" "Selected transport: $transport_ref"
                        return 0 # Success
                    else
                        print_warning "Invalid numeric choice from all options: $MENU_CHOICE"; press_any_key
                        previous_menu_rc_for_header_logic="error" # Force header re-print
                        continue
                    fi
                else # Quick setup options
                    case "$MENU_CHOICE" in
                        "1") transport_ref="tcp"; break ;; # Break from inner switch, then outer loop will be exited by return 0
                        "2") transport_ref="ws"; break ;;
                        "3") transport_ref="wss"; break ;;
                        "4")
                            show_all_options_now=true
                            previous_menu_rc_for_header_logic="" # Force header re-print for "all options" view
                            continue ;; # Re-loop to show all options
                        *)
                            print_warning "Invalid quick transport choice: $MENU_CHOICE."; press_any_key
                            previous_menu_rc_for_header_logic="error" # Force header re-print
                            continue;;
                    esac
                    log_message "INFO" "Selected transport: $transport_ref"
                    return 0 # Success
                fi
                ;;
            2) # '?' Help
                # Header will be re-printed due to previous_menu_rc_for_header_logic being 2
                continue ;;
            3) # 'm' Main Menu
                print_info "Configuration cancelled: returning to Main Menu."
                return 1 ;; # Signal cancel wizard
            4) # 'x' Exit script
                request_script_exit
                return 1 ;; # Should not be reached
            5) # 'r' Return/Back
                print_info "Going back to Setup Type/Mode selection."
                return 2 ;; # Signal go back one step
            6)  # Invalid input in menu_loop
                # press_any_key handled by menu_loop
                # previous_menu_rc_for_header_logic will be 6, so header might not reprint unless logic is adjusted.
                # Setting it to "error" or similar to force header reprint.
                previous_menu_rc_for_header_logic="error_redraw"
                continue ;; # Re-prompt transport protocol
            *)
                handle_error "ERROR" "Unhandled menu_loop code $menu_rc in _prompt_transport_protocol"
                return 1;; # Signal cancel wizard on error
        esac
    done # This while loop is technically now only exited by `return` statements.
         # The `break` statements in numeric choice (0) for quick options were for the inner switch,
         # but now directly lead to `return 0`.
}

_prompt_basic_config_params() {
    local tunnel_mode="$1"      # "server" or "client"
    local -n listen_port_ref=$2 # Output for server mode
    local -n remote_ip_ref=$3   # Output for client mode
    local -n remote_port_ref=$4 # Output for client mode
    local -n local_fwd_port_ref=$5 # Output for client mode (local port to forward from)
    local -n auth_token_ref=$6  # Output: auth token

    print_menu_header "secondary" "Basic Configuration" "Step 3 of N" # N depends on if TLS is needed, step number adjusted

    if [[ "$tunnel_mode" == "server" ]]; then
        print_info "Server Mode: Configure listening port."
        if [[ -z "$SERVER_IP" || "$SERVER_IP" == "N/A" ]]; then get_server_info; fi

        if ! prompt_for_port "port for Backhaul server to listen on" "443" true listen_port_ref; then
            print_error "Failed to get a valid listen port for server."
            return 1
        fi
    else # client mode
        print_info "Client Mode: Configure remote server details." # Updated: removed "and local forwarding port"
        if ! prompt_for_ip "the public IP address of the Backhaul SERVER" "" true remote_ip_ref; then
            print_error "Failed to get a valid remote server IP for client."
            return 1
        fi
        
        if ! prompt_for_port "port the Backhaul SERVER is listening on" "443" false remote_port_ref; then
            print_error "Failed to get a valid remote server port for client."
            return 1
        fi

        # Removed prompt for client_local_fwd_port as it's not a standard backhaul client param
        # Forwarding is now primarily defined by the server's 'ports' array.
        # client_local_fwd_port_ref will remain unset or at its default if passed by nameref.
    fi

    local default_auth_token="EasyBackhaulSecretToken"
    print_info "Set an authentication token (must match on both server and client)."
    while true; do
        read -r -s -p "Enter auth token (min 8 chars, or type 'cancel' to abort this step): " auth_token_val
        echo
        if [[ "$auth_token_val" == "cancel" ]]; then
            print_info "Auth token input cancelled by user."
            return 1 # Signal cancellation of this step to the caller
        fi
        auth_token_val=${auth_token_val:-$default_auth_token}
        if [[ "${#auth_token_val}" -lt 8 ]]; then
            print_warning "Token too short. Please use at least 8 characters for security."
            if ! prompt_yes_no "Try entering token again?" "y"; then
                 print_error "Auth token setup aborted by user."
                 return 1
            fi
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
        return 0 # Not applicable for this transport
    fi

    # Determine Step Number. Could be Step 4 (after Basic) or Step 5 (after Advanced if shown)
    # This is tricky to get exact from within here without knowing if advanced was shown.
    # Let's assume it's called with context, or use a generic "Step X of N"
    print_menu_header "secondary" "TLS Certificate Configuration" "Step 4/5 of N: Secure Protocols"
    print_info "Secure protocols (WSS/WSSMUX) require a TLS certificate and private key."

    local cert_dir_global="${CERT_DIR:-/etc/easybackhaul/certs}"
    ensure_dir "$cert_dir_global" "700"
    
    mapfile -t existing_certs < <(find "$cert_dir_global" -maxdepth 1 -name '*.pem' -o -name '*.crt' 2>/dev/null | sort)
    
    local tls_options=()
    local cert_map=()

    if [[ ${#existing_certs[@]} -gt 0 ]]; then
        print_info "Existing certificates/keys found in $cert_dir_global:"
        local count=1
        for cert_file in "${existing_certs[@]}"; do
            local potential_key_file="${cert_file%.*}.key"
            if [[ ! -f "$potential_key_file" ]]; then potential_key_file="${cert_file%.*}.pem"; fi

            if [[ -f "$potential_key_file" ]]; then
                 tls_options+=("$count. Use: $(basename "$cert_file") + $(basename "$potential_key_file")")
                 cert_map[$count]="$cert_file;$potential_key_file"
                 ((count++))
            else
                print_warning "Certificate $(basename "$cert_file") found without a clearly matching .key file, skipping."
            fi
        done
    fi
    tls_options+=("$((${#cert_map[@]} + 1)). Generate New Self-Signed Certificate")
    local generate_new_opt_num=$((${#cert_map[@]} + 1))
    tls_options+=("$((${#cert_map[@]} + 2)). Skip TLS configuration (NOT RECOMMENDED)")
    local skip_tls_opt_num=$((${#cert_map[@]} + 2))

    _tls_help() {
        print_info "TLS Configuration Help:"
        echo " - Select an existing certificate/key pair if available."
        echo " - Choose 'Generate New' to create a self-signed certificate."
        echo " - 'Skip TLS' will proceed without TLS; WSS/WSSMUX will likely fail."
        echo " - Certificate paths are stored in the tunnel's TOML config file."
        echo "Use 'r' to return to Basic Params, 'c' to cancel configuration."
        press_any_key
    }

    menu_loop "Select TLS certificate option" tls_options "_tls_help"
    local menu_rc=$?
    local user_choice="$MENU_CHOICE" # MENU_CHOICE is set by menu_loop on rc=0

    case "$menu_rc" in
        0) # Numeric choice
            if (( user_choice == generate_new_opt_num )); then
                # Attempt to generate certs. generate_self_signed_tls_cert handles its own user interaction.
                # It returns 0 on success, 1 on failure/cancel.
                if generate_self_signed_tls_cert; then
                    local new_cert=$(find "$cert_dir_global" -name '*.pem' -o -name '*.crt' -print0 | xargs -0 stat -c "%Y %n" | sort -nr | head -n1 | awk '{print $2}')
                    local new_key="${new_cert%.*}.key"
                    if [[ ! -f "$new_key" ]]; then new_key="${new_cert%.*}.pem"; fi

                    if [[ -f "$new_cert" && -f "$new_key" ]]; then
                        tls_cert_path_ref="$new_cert"
                        tls_key_path_ref="$new_key"
                        print_success "Using newly generated cert: $tls_cert_path_ref and key: $tls_key_path_ref"
                        # Fall through to return 0 at the end of the function
                    else
                        handle_error "ERROR" "Failed to identify newly generated certificate/key pair after successful generation."
                        # Offer to retry this step? For now, treat as failure of this step.
                        # This implies a problem with find/stat logic, not user cancellation.
                        if prompt_yes_no "Error identifying generated files. Retry TLS setup step?" "y"; then
                           _prompt_tls_config "$transport" tls_cert_path_ref tls_key_path_ref; return $?
                        else
                           return 1 # Cancel wizard due to internal error
                        fi
                    fi
                else
                    # generate_self_signed_tls_cert failed or was cancelled by user within it.
                    print_warning "Self-signed certificate generation failed or was cancelled."
                    # Ask user if they want to retry the TLS config step or cancel wizard
                    if prompt_yes_no "Retry TLS configuration, or cancel wizard? (Retry/Cancel)" "y"; then
                        _prompt_tls_config "$transport" tls_cert_path_ref tls_key_path_ref; return $?
                    else
                        return 1 # User chose to cancel wizard
                    fi
                fi
            elif (( user_choice == skip_tls_opt_num )); then
                print_warning "Skipping TLS configuration. WSS/WSSMUX will likely not work without it."
                tls_cert_path_ref=""
                tls_key_path_ref=""
                # Fall through to return 0
            elif [[ -n "${cert_map[$user_choice]}" ]]; then
                IFS=';' read -r tls_cert_path_ref tls_key_path_ref <<< "${cert_map[$user_choice]}"
                print_success "Using selected cert: $tls_cert_path_ref and key: $tls_key_path_ref"
                # Fall through to return 0
            else
                handle_error "ERROR" "Invalid TLS certificate selection: $user_choice."
                # Ask user to retry this step
                if prompt_yes_no "Invalid selection. Retry TLS setup step?" "y"; then
                    _prompt_tls_config "$transport" tls_cert_path_ref tls_key_path_ref; return $?
                else
                    return 1 # User chose to cancel wizard
                fi
            fi
            return 0 # Successful numeric choice processing
            ;;
        2) # '?' Help
            _prompt_tls_config "$transport" tls_cert_path_ref tls_key_path_ref; return $? ;; # Re-call current step
        3) # 'm' Main Menu
            print_info "Configuration cancelled: returning to Main Menu."
            return 1 ;; # Signal cancel wizard
        4) # 'x' Exit script
            request_script_exit
            return 1 ;; # Should not be reached
        5) # 'r' Return/Back
            print_info "Going back to previous step from TLS config."
            return 2 ;; # Signal go back one step
        6)  # Invalid input in menu_loop
            # press_any_key handled by menu_loop
            _prompt_tls_config "$transport" tls_cert_path_ref tls_key_path_ref; return $? ;; # Re-call current step
        *) # Includes unexpected menu_loop return codes
            handle_error "ERROR" "Unhandled menu_loop code $menu_rc in _prompt_tls_config"
            # Offer to retry or cancel
            if prompt_yes_no "Unexpected error in TLS config. Retry this step?" "y"; then
                _prompt_tls_config "$transport" tls_cert_path_ref tls_key_path_ref; return $?
            else
                return 1 # Signal cancel wizard
            fi
    esac
    # Should be unreachable if all paths in case either return or re-invoke.
    # However, as a fallback for case 0 if it doesn't return explicitly:
    # This implies a valid selection was made (or skipped).
    return 0
}

_prompt_server_ports_array() {
    local -n rules_array_ref=$1 # Output: array of "listen_port:destination_port" strings
    rules_array_ref=() # Initialize as empty

    print_menu_header "secondary" "Server Port Forwarding" "Step 3b: Configure Forwarding Rules"
    print_info "Configure rules for forwarding traffic from this server to the client."
    print_info "Example: Server listens on public port 80, forwards to client's port 8080."
    echo

    while true; do
        if ! prompt_yes_no "Add a port forwarding rule?" "y"; then
            if [[ ${#rules_array_ref[@]} -eq 0 ]]; then
                print_warning "No port forwarding rules defined. Server will not forward any traffic."
                if ! prompt_yes_no "Are you sure you want to continue without any forwarding rules?" "n"; then
                    # Loop again to ask if they want to add a rule
                    continue
                fi
            fi
            break # Exit loop if user doesn't want to add (more) rules
        fi

        local server_public_port client_dest_port
        if ! prompt_for_port "Port on THIS SERVER to listen on (e.g., 80, 443)" "" true server_public_port; then
            print_warning "Skipping this rule due to invalid server port."
            if ! prompt_yes_no "Try adding a different rule?" "y"; then break; fi
            continue
        fi

        if ! prompt_for_port "Port on the CLIENT where traffic should be forwarded (e.g., 8080)" "" false client_dest_port; then
            print_warning "Skipping this rule due to invalid client port."
            if ! prompt_yes_no "Try adding a different rule?" "y"; then break; fi
            continue
        fi

        local new_rule="${server_public_port}:${client_dest_port}"
        # Check if rule already exists to prevent duplicates, though not strictly necessary by backhaul
        local rule_exists=false
        for existing_rule in "${rules_array_ref[@]}"; do
            if [[ "$existing_rule" == "$new_rule" ]]; then
                rule_exists=true
                break
            fi
        done

        if $rule_exists; then
            print_warning "Rule '$new_rule' already exists."
        else
            rules_array_ref+=("$new_rule")
            print_success "Rule added: $new_rule"
        fi
        echo # Extra line for readability before next prompt_yes_no
    done
    return 0
}


# --- Main Configuration Wizard ---
# Manages the overall flow of tunnel configuration.
# Returns 0 if configuration is completed (even if not saved by user later),
# Returns 1 if user cancels mid-way using navigation keys that bubble up as failure.
configure_tunnel() {
    local current_wizard_step=1

    # Variables to store wizard state, passed by nameref or directly
    local setup_choice_val tunnel_mode transport_protocol
    local server_listen_port client_remote_ip client_remote_port client_local_fwd_port common_auth_token
    local server_port_rules=() # Array to store server port forwarding rules
    local cfg_tls_cert_path cfg_tls_key_path
    local setup_is_advanced=false

    # Default advanced parameters (can be populated if an advanced step is added)
    local cfg_log_level="info" cfg_sniffer="false"
    local cfg_sniffer_log # Example: "/var/log/easybackhaul/${final_tunnel_name}-sniffer.json"
    local cfg_web_port=0 cfg_nodelay="true" cfg_keepalive_period=75
    local cfg_heartbeat=40 cfg_channel_size=2048 cfg_accept_udp="false"
    local cfg_connection_pool=8 cfg_aggressive_pool="false" cfg_retry_interval=3 cfg_dial_timeout=10
    local cfg_mux_con=8 cfg_mux_version=1 cfg_mux_framesize=32768
    local cfg_mux_receivebuffer=4194304 cfg_mux_streambuffer=65536

    # Wizard State Machine
    # Returns 0 if configuration is completed and saved.
    # Returns 1 if user cancels the wizard at any point.
    while true; do # Loop for wizard steps, allowing "back" functionality
        local step_rc=0 # Return code from the prompt functions

        case "$current_wizard_step" in
            1) # Step 1: Setup Type & Mode
                _prompt_setup_type_and_mode setup_choice_val tunnel_mode
                step_rc=$?
                case "$step_rc" in
                    0) # Success
                        [[ "$setup_choice_val" -eq 2 ]] && setup_is_advanced=true
                        log_message "INFO" "Setup type: $(if $setup_is_advanced; then echo "Advanced"; else echo "Quick"; fi), Mode: $tunnel_mode"
                        ((current_wizard_step++))
                        ;;
                    1) # Cancel wizard
                        print_info "Configuration wizard cancelled at Setup Type/Mode."
                        return_from_menu # Ensure menu stack is correct
                        return 1 ;;
                    2) # 'r' Back - from first step, this is equivalent to cancel
                        print_info "Configuration wizard cancelled (back from first step)."
                        return_from_menu
                        return 1 ;;
                    *) handle_error "CRITICAL" "Unknown return code $step_rc from _prompt_setup_type_and_mode." ; return 1 ;;
                esac
                ;;
            2) # Step 2: Transport Protocol
                _prompt_transport_protocol "$setup_is_advanced" transport_protocol # Pass setup_is_advanced status
                step_rc=$?
                case "$step_rc" in
                    0) ((current_wizard_step++));; # Success
                    1) print_info "Configuration wizard cancelled at Transport Protocol selection."; return_from_menu; return 1 ;;
                    2) ((current_wizard_step--)); continue ;; # Go back to Step 1
                    *) handle_error "CRITICAL" "Unknown return code $step_rc from _prompt_transport_protocol." ; return 1 ;;
                esac
                ;;
            3) # Step 3: Basic Configuration Parameters
                _prompt_basic_config_params "$tunnel_mode" \
                    server_listen_port client_remote_ip client_remote_port client_local_fwd_port \
                    common_auth_token
                step_rc=$?
                case "$step_rc" in
                    0) ((current_wizard_step++));; # Success
                    1) # Cancel from basic params (e.g. typed 'cancel')
                       # Decide if this should be "back" or "full cancel"
                       # For now, let's treat explicit 'cancel' within basic_params as full wizard cancel.
                       # 'r' key is not available in these prompts.
                        print_info "Configuration wizard cancelled at Basic Parameters."
                        return_from_menu; return 1 ;;
                    # No '2' (back) returned by _prompt_basic_config_params currently
                    *) handle_error "CRITICAL" "Unknown return code $step_rc from _prompt_basic_config_params." ; return 1 ;;
                esac
                ;;
            # NEW STEP for Server Port Forwarding Rules
            4)
                if [[ "$tunnel_mode" == "server" ]]; then
                    _prompt_server_ports_array server_port_rules # Pass the array by nameref
                    step_rc=$? # _prompt_server_ports_array currently always returns 0, but good practice
                    # It handles its own internal looping and cancellation of adding rules.
                    # If it were to return 1 (cancel wizard) or 2 (back a step), handle here.
                    # For now, assume it completes or user confirms empty rules.
                    if [[ "$step_rc" -eq 0 ]]; then
                        ((current_wizard_step++))
                    else
                        # Handle cancellation/back from _prompt_server_ports_array if implemented
                        # For now, this path isn't taken by _prompt_server_ports_array's current design.
                        print_info "Port forwarding configuration was cancelled or an error occurred."
                        # Decide if this means full wizard cancel or back to basic params
                        # For now, assume it means back to basic params (step 3)
                        current_wizard_step=3
                        continue
                    fi
                else
                    # Not a server, skip this step
                    ((current_wizard_step++))
                fi
                ;;
            5) # Step 5 (Was 4): Advanced Configuration
                if $setup_is_advanced; then
                    # TODO: Implement _prompt_advanced_config_params
                    print_info "Advanced parameter configuration (currently using defaults)."
                    log_message "INFO" "Advanced setup chosen - using default advanced parameters for now."
                    step_rc=0 # Simulate success for now
                    if [[ "$step_rc" -eq 0 ]]; then ((current_wizard_step++)); else return 1; fi
                else
                    ((current_wizard_step++)) # Skip if not advanced setup
                fi
                ;;
            6) # Step 6 (Was 5): TLS Configuration
                cfg_tls_cert_path="" cfg_tls_key_path="" # Reset for this step
                if [[ "$transport_protocol" =~ ^(wss|wssmux)$ ]]; then
                    _prompt_tls_config "$transport_protocol" cfg_tls_cert_path cfg_tls_key_path
                    step_rc=$?
                    case "$step_rc" in
                        0) ((current_wizard_step++));; # Success (includes user skipping TLS)
                        1) print_info "Configuration wizard cancelled at TLS Configuration."; return_from_menu; return 1 ;;
                        2) ((current_wizard_step--)); current_wizard_step=$((current_wizard_step > 0 ? current_wizard_step : 1)); continue ;; # Go back
                        *) handle_error "CRITICAL" "Unknown return code $step_rc from _prompt_tls_config." ; return 1 ;;
                    esac
                else
                    ((current_wizard_step++)) # Skip if not WSS/WSSMUX
                fi
                ;;
            7) # Step 7 (Was 6): Configuration Summary & Confirmation
                print_menu_header "secondary" "Configuration Summary" "Review and Confirm"
                echo "  Mode: $tunnel_mode"
                echo "  Transport: $transport_protocol"
                if [[ "$tunnel_mode" == "server" ]]; then
                    echo "  Server Listen Address (bind_addr): :$server_listen_port" # Updated key name
                    if [[ ${#server_port_rules[@]} -gt 0 ]]; then
                        echo "  Port Forwarding Rules (ports):"
                        for rule in "${server_port_rules[@]}"; do
                            echo "    - \"$rule\""
                        done
                    else
                        echo "  Port Forwarding Rules (ports): [None defined - server will not forward traffic]"
                    fi
                else # client
                    echo "  Remote Server (remote_addr): $client_remote_ip:$client_remote_port" # Updated key name
                    # client_local_fwd_port has been removed from prompts and will be removed from TOML writing.
                fi
                echo "  Token: [set]" # Assuming it's always set if we reach here, updated key name

                if $setup_is_advanced; then
                    echo "  --- Advanced Settings (Defaults Used) ---"
                    echo "  Log Level: $cfg_log_level"
                    # Consider printing other relevant advanced params if they were configurable
                fi
                if [[ -n "$cfg_tls_cert_path" && -n "$cfg_tls_key_path" ]]; then
                    echo "  TLS Certificate: $cfg_tls_cert_path"
                    echo "  TLS Key: $cfg_tls_key_path"
                elif [[ "$transport_protocol" =~ ^(wss|wssmux)$ ]]; then
                    # Only show TLS: Skipped if it was applicable
                    echo "  TLS: Skipped/Not Configured"
                fi

                if ! prompt_yes_no "Proceed with this configuration?" "y"; then
                    # User does NOT want to proceed. Ask to edit from start or cancel wizard.
                    if prompt_yes_no "Edit configuration from the beginning, or cancel wizard? (Enter 'y' to Edit, 'n' to Cancel)" "y"; then
                        current_wizard_step=1 # Restart wizard from Step 1
                        log_message "INFO" "User chose to edit configuration from start."
                        # Consider resetting influential variables if they affect early steps.
                        # For now, assuming _prompt_ functions will correctly overwrite them.
                        # setup_is_advanced=false # Example, if needed for a clean restart.
                        continue # Re-loop the main wizard 'while true' to go to step 1
                    else
                        # User chose to cancel the wizard.
                        print_info "Configuration wizard cancelled at summary."
                        return_from_menu # Ensure menu stack is correct before returning
                        return 1 # Exit configure_tunnel with cancel status
                    fi
                else
                    # User wants to proceed with this configuration.
                    ((current_wizard_step++)) # Proceed to Save step
                fi
                ;;
            8) # Step 8 (Was 7): Generate Tunnel Name and Save Configuration
                local tunnel_name_suffix
                tunnel_name_suffix="${tunnel_mode}-${transport_protocol}-$(date +%s | tail -c 5)"
                local final_tunnel_name="bh-$tunnel_name_suffix"
                cfg_sniffer_log="/var/log/easybackhaul/${final_tunnel_name}-sniffer.json"

                local config_file_path="$CONFIG_DIR/config-${final_tunnel_name}.toml"
                ensure_dir "$CONFIG_DIR"
                : > "$config_file_path" # Create/truncate config file

                # Write [server] or [client] section header
                echo "[$tunnel_mode]" > "$config_file_path"

                # Common parameters (already corrected names)
                update_toml_value "$config_file_path" "transport" "$transport_protocol" "string"
                update_toml_value "$config_file_path" "token" "$common_auth_token" "string"

                if [[ "$tunnel_mode" == "server" ]]; then
                    update_toml_value "$config_file_path" "bind_addr" ":$server_listen_port" "string"
                    # Add the ports array
                    if [[ ${#server_port_rules[@]} -gt 0 ]]; then
                        echo "ports = [" >> "$config_file_path"
                        for rule in "${server_port_rules[@]}"; do
                            echo "  \"$rule\"," >> "$config_file_path"
                        done
                        echo "]" >> "$config_file_path"
                    else
                        echo "ports = [] # No forwarding rules defined" >> "$config_file_path"
                    fi
                else # client mode
                    update_toml_value "$config_file_path" "remote_addr" "${client_remote_ip}:${client_remote_port}" "string" # Name already corrected
                    # The line for `local = ":$client_local_fwd_port"` is now removed.
                fi

                # Advanced parameters are written after basic ones and potentially after the ports array (for server)
                if $setup_is_advanced; then
                    update_toml_value "$config_file_path" "log_level" "$cfg_log_level" "string"
                    update_toml_value "$config_file_path" "sniffer" "$cfg_sniffer" "boolean"
                    if [[ "$cfg_sniffer" == "true" ]]; then
                        update_toml_value "$config_file_path" "sniffer_log" "$cfg_sniffer_log" "string"
                    fi
                    if (( cfg_web_port > 0 )); then
                         update_toml_value "$config_file_path" "web_port" "$cfg_web_port" "numeric"
                    fi
                    if [[ "$transport_protocol" != "udp" ]]; then
                         update_toml_value "$config_file_path" "nodelay" "$cfg_nodelay" "boolean"
                         update_toml_value "$config_file_path" "keepalive_period" "$cfg_keepalive_period" "numeric"
                    fi
                    if [[ "$tunnel_mode" == "server" ]]; then
                        update_toml_value "$config_file_path" "heartbeat" "$cfg_heartbeat" "numeric"
                        update_toml_value "$config_file_path" "channel_size" "$cfg_channel_size" "numeric"
                        if [[ "$transport_protocol" == "tcp" || "$transport_protocol" == "tcpmux" ]]; then # accept_udp for TCP server
                            update_toml_value "$config_file_path" "accept_udp" "$cfg_accept_udp" "boolean"
                        fi
                    else # client
                        update_toml_value "$config_file_path" "connection_pool" "$cfg_connection_pool" "numeric"
                        update_toml_value "$config_file_path" "aggressive_pool" "$cfg_aggressive_pool" "boolean"
                        update_toml_value "$config_file_path" "retry_interval" "$cfg_retry_interval" "numeric"
                        update_toml_value "$config_file_path" "dial_timeout" "$cfg_dial_timeout" "numeric"
                    fi
                    if [[ "$transport_protocol" =~ mux$ ]]; then # MUX specific
                        update_toml_value "$config_file_path" "mux_con" "$cfg_mux_con" "numeric"
                        update_toml_value "$config_file_path" "mux_version" "$cfg_mux_version" "numeric"
                        update_toml_value "$config_file_path" "mux_framesize" "$cfg_mux_framesize" "numeric"
                        update_toml_value "$config_file_path" "mux_receivebuffer" "$cfg_mux_receivebuffer" "numeric" # CORRECTED SPELLING
                        update_toml_value "$config_file_path" "mux_streambuffer" "$cfg_mux_streambuffer" "numeric"
                    fi
                fi

                if [[ -n "$cfg_tls_cert_path" && -n "$cfg_tls_key_path" ]]; then
                    update_toml_value "$config_file_path" "tls_cert" "$cfg_tls_cert_path" "string"
                    update_toml_value "$config_file_path" "tls_key" "$cfg_tls_key_path" "string"
                fi

                set_secure_file_permissions "$config_file_path" "600"
                handle_success "Configuration saved: $config_file_path"
                ((current_wizard_step++))
                ;;
            9) # Step 9 (Was 8): Post-creation (Systemd, Start)
                if type create_systemd_service &>/dev/null; then
                    if create_systemd_service "$final_tunnel_name" "$config_file_path"; then # Pass final_tunnel_name
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
                return_from_menu
                return 0
                ;;
            *)
                handle_error "CRITICAL" "Invalid wizard step in configure_tunnel: $current_wizard_step"
                return 1
                ;;
        esac
    done
}


# --- Decommissioned/Old Functions ---
# update_config_file() { log_message "WARN" "DEPRECATED: update_config_file called. Use TOML-based config."; }
# remove_from_config() { log_message "WARN" "DEPRECATED: remove_from_config called. Use TOML-based config."; }
# backup_configuration() { log_message "WARN" "DEPRECATED: backup_configuration called. Use backup_configuration_path from helpers.sh."; }
# restore_configuration() { log_message "WARN" "DEPRECATED: restore_configuration called."; }
# export_configuration() { log_message "WARN" "DEPRECATED: export_configuration called."; }
# configure_advanced_settings() { log_message "WARN" "DEPRECATED: configure_advanced_settings called."; }


true # Ensure script is valid if sourced.
