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
        while true; do # Inner loop for Mode selection
            print_menu_header "secondary" "Tunnel Mode" "Step 1b: Select Mode"
            local default_mode_val="2" # Default to client typically
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
                    # continue 2 was wrong, now just 'continue' for inner loop
                    continue # Re-prompt Mode selection
                fi
                # Mode selected successfully, break inner loop and then outer loop will be exited by return 0
                break
                ;;
            2) # '?' Help
                # continue 2 was wrong, now just 'continue' for inner loop
                continue # Re-prompt Mode selection (after help)
                ;;
            3) # 'm' Main Menu
                print_info "Configuration cancelled: returning to Main Menu."
                return 1 ;; # Signal cancel wizard (exits function)
            4) # 'x' Exit script
                request_script_exit
                return 1 ;; # Signal cancel wizard (exits function)
            5) # 'r' Return/Back (to Setup Type selection)
                print_info "Going back to Setup Type selection."
                break # Break inner Mode loop, outer Setup Type loop will 'continue 1' implicitly
                ;;
            6)  # Invalid input in menu_loop (including empty Enter)
                # menu_loop handles press_any_key for non-empty invalid input.
                # For empty input, no message from menu_loop, so we don't add one here either.
                # Simply re-prompt Mode.
                continue # Re-prompt Mode selection
                ;;
            *)
                handle_error "ERROR" "Unhandled menu_loop code $menu_rc in _prompt_setup_type_and_mode (Mode)"
                return 1 ;; # Signal cancel wizard (exits function)
        esac
        done # End of inner while true for Mode selection

        # If we broke from Mode selection due to 'r' (Return/Back),
        # we need to continue the outer loop to re-prompt Setup Type.
        if [[ "$menu_rc" == "5" ]]; then # 'r' was chosen for Mode
            continue # Continue outer loop (Setup Type)
        fi

        # If we reached here, it means Mode was successfully selected OR an exit/error occurred.
        # If Mode was successful (rc=0), the 'return 0' from that case already exited.
        # If an error/exit occurred (rc=1, 3, 4), 'return 1' already exited.
        # This part of the code should ideally only be reached if 'r' was selected in Mode,
        # and the outer loop needs to continue.
        # Or, if Mode selection succeeded, we'd have hit `return 0` already.

        # Fallback / Should not be reached if logic above is perfect
        # but as a safeguard, if mode was set, we can assume success.
        if [[ -n "$tunnel_mode_ref" ]]; then
             return 0 # Mode was set, assume overall success for the function
        fi
        # If mode wasn't set and 'r' wasn't the reason for breaking inner loop,
        # it implies an unhandled state or error, loop Setup Type again.
    done # End of outer while true for Setup Type
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

# Validates a single port or a port range (e.g., "80", "400-500")
# Returns 0 if valid, 1 if invalid.
_validate_port_or_range() {
    local port_spec="$1"
    if [[ "$port_spec" =~ ^[0-9]+$ ]]; then # Single port
        validate_port "$port_spec" # Uses existing helper
        return $?
    elif [[ "$port_spec" =~ ^([0-9]+)-([0-9]+)$ ]]; then # Port range
        local start_port="${BASH_REMATCH[1]}"
        local end_port="${BASH_REMATCH[2]}"
        if validate_port "$start_port" && validate_port "$end_port"; then
            if (( start_port < end_port )); then
                return 0
            else
                print_warning "Invalid range: Start port $start_port must be less than end port $end_port."
                return 1
            fi
        else
            # validate_port would have printed specific error
            return 1
        fi
    else
        print_warning "Invalid port/range format: '$port_spec'. Use 'port' or 'start_port-end_port'."
        return 1
    fi
}

# Prompts user for server port forwarding rules with validation for various formats.
# Replaces _prompt_server_ports_array
_configure_server_forwarding_rules() {
    local -n rules_array_ref=$1 # Output: array of rule strings
    rules_array_ref=() # Initialize

    print_menu_header "secondary" "Server Port Forwarding" "Step 4: Configure Forwarding Rules"
    print_info "Define rules for how the server listens for and forwards traffic."
    print_info "Type 'help' for format examples, 'done' when finished."
    echo

    while true; do
        local user_input
        read -r -p "Enter forwarding rule (or 'help'/'done'): " user_input
        user_input=$(echo "$user_input" | tr '[:upper:]' '[:lower:]') # Normalize

        if [[ "$user_input" == "done" ]]; then
            if [[ ${#rules_array_ref[@]} -eq 0 ]]; then
                print_warning "No port forwarding rules defined. Server will not forward any traffic."
                if ! prompt_yes_no "Are you sure you want to continue without any forwarding rules?" "n"; then
                    continue
                fi
            fi
            break
        elif [[ "$user_input" == "help" ]]; then
            echo "Supported rule formats (listen_spec can be port or port-range):"
            echo "  1. listen_spec                  (e.g., '443', '5201/udp', '600-700')"
            echo "     => Forwards from server's listen_spec to client's same port/range."
            echo "  2. listen_spec:dest_port        (e.g., '80:8080', '443-450:3000')"
            echo "     => Forwards from server's listen_spec to client's dest_port."
            echo "  3. listen_spec=dest_ip:dest_port (e.g., '443=10.0.0.5:8443', '1000-1005=10.0.0.5:8000')"
            echo "     => Forwards from server's listen_spec to specific IP and port from client."
            echo "Note: UDP forwarding is specified by appending '/udp' to the listen_spec, e.g., '53/udp'."
            echo
            continue
        fi

        if [[ -z "$user_input" ]]; then
            continue
        fi

        local listen_spec dest_ip dest_port protocol_suffix=""
        local valid_rule=false
        local original_rule_for_adding="$user_input" # Save original input for adding if valid

        # Check for /udp suffix first
        if [[ "$user_input" == */udp ]]; then
            protocol_suffix="/udp"
            user_input="${user_input%/udp}" # Remove /udp for further parsing
        fi

        # Try to parse listen_spec=dest_ip:dest_port format
        if [[ "$user_input" =~ ^([^=]+)=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):([0-9]+)$ ]]; then
            listen_spec="${BASH_REMATCH[1]}"
            dest_ip="${BASH_REMATCH[2]}"
            dest_port="${BASH_REMATCH[3]}"
            if _validate_port_or_range "$listen_spec" && validate_ip "$dest_ip" && validate_port "$dest_port"; then
                valid_rule=true
            fi
        # Try to parse listen_spec:dest_port format
        elif [[ "$user_input" =~ ^([^:]+):([0-9]+)$ ]]; then
            listen_spec="${BASH_REMATCH[1]}"
            dest_port="${BASH_REMATCH[2]}"
            if _validate_port_or_range "$listen_spec" && validate_port "$dest_port"; then
                valid_rule=true
            fi
        # Try to parse listen_spec (single port or range) format
        elif _validate_port_or_range "$user_input"; then # user_input here is listen_spec without /udp
            listen_spec="$user_input"
            valid_rule=true
        else
            # _validate_port_or_range or other regexes would have printed an error.
            # If no specific error printed, give a generic one.
            # This path is less likely if _validate_port_or_range is comprehensive.
            if $valid_rule; then : ; else print_warning "Invalid rule format: '$original_rule_for_adding'"; fi
        fi

        if $valid_rule; then
            # Re-append /udp if it was present
            # The original_rule_for_adding already contains /udp if it was there.
            # No, original_rule_for_adding is the raw input. We need to add protocol_suffix to the validated listen_spec part
            # if we were to reconstruct. Better to add the user's original valid input.
            rules_array_ref+=("$original_rule_for_adding")
            print_success "Rule added: \"$original_rule_for_adding\""
        else
            # Errors should have been printed by validation functions
            print_warning "Rule '$original_rule_for_adding' NOT added due to errors."
        fi
        echo
    done
    return 0
}


# Prompts user for advanced optional parameters
# Populates an associative array with chosen values.
# Usage: _prompt_advanced_parameters params_assoc_array "$tunnel_mode" "$transport_protocol"
_prompt_advanced_parameters() {
    local -n params_ref=$1 # Associative array passed by nameref
    local tunnel_mode="$2"
    local transport_protocol="$3"
    local is_interactive="${4:-true}" # Default to true for interactive prompting

    if [[ "$is_interactive" == "true" ]]; then
        print_menu_header "secondary" "Advanced Configuration" "Customize Optional Parameters"
        print_info "For each parameter, the default value will be shown."
        print_info "You can accept the default by pressing Enter, or provide a new value."
        echo
    else
        log_message "INFO" "Populating advanced parameters with defaults (Quick Setup)."
    fi

    # Helper to prompt for/set a single advanced parameter
    # Usage: _handle_single_adv_param "description" "toml_key" "default_value_var_name"
    _handle_single_adv_param() {
        local desc="$1" toml_key="$2" default_val_var_name="$3"
        local default_val="${!default_val_var_name}" # Indirect expansion
        local input_val

        if [[ "$is_interactive" == "true" ]]; then
            while true; do
                read -r -p "Configure '$desc' ($toml_key) [Default: $default_val]: " input_val
                input_val="${input_val:-$default_val}" # Apply default if empty

                # Basic validation can be added here if needed, e.g., numeric, boolean
                # Example for boolean (can be expanded for numeric ranges too):
                if [[ "$toml_key" == "nodelay" || "$toml_key" == "sniffer" || "$toml_key" == "accept_udp" || "$toml_key" == "aggressive_pool" ]]; then
                    if [[ "$input_val" != "true" && "$input_val" != "false" ]]; then
                        print_warning "Invalid boolean. Must be 'true' or 'false'."
                        continue # Re-prompt
                    fi
                elif [[ "$toml_key" =~ port$ || "$toml_key" =~ _period$ || "$toml_key" =~ _interval$ || "$toml_key" =~ _timeout$ || "$toml_key" =~ _size$ || "$toml_key" =~ _con$ || "$toml_key" =~ _version$ || "$toml_key" =~ buffer$ ]]; then
                     if ! [[ "$input_val" =~ ^[0-9]+$ ]]; then
                        print_warning "Invalid numeric value for $toml_key. Must be an integer."
                        continue
                     fi
                fi
                params_ref["$toml_key"]="$input_val"
                print_success "  $toml_key set to: ${params_ref[$toml_key]}"
                break
            done
            echo
        else # Not interactive, just set the default
            params_ref["$toml_key"]="$default_val"
            log_message "DEBUG" "Quick Setup: $toml_key set to default: $default_val"
        fi
    }

    # General Parameters
    _handle_single_adv_param "Log Level" "log_level" "BH_DEFAULT_LOG_LEVEL"
    _handle_single_adv_param "Enable Traffic Sniffer" "sniffer" "BH_DEFAULT_SNIFFER"
    # sniffer_log is handled during save config if sniffer is true

    if [[ "$transport_protocol" != "udp" ]]; then
        _handle_single_adv_param "TCP NoDelay" "nodelay" "BH_DEFAULT_NODELAY"
        _handle_single_adv_param "Keepalive Period (s)" "keepalive_period" "BH_DEFAULT_KEEPALIVE_PERIOD"
    fi
    _handle_single_adv_param "Web Interface Port (0 to disable)" "web_port" "BH_DEFAULT_WEB_PORT"

    if [[ "$tunnel_mode" == "server" ]]; then
        if [[ "$is_interactive" == "true" ]]; then print_info "--- Server-Specific Advanced Parameters ---"; fi
        _handle_single_adv_param "Heartbeat Interval (s)" "heartbeat" "BH_DEFAULT_HEARTBEAT"
        _handle_single_adv_param "Channel Size" "channel_size" "BH_DEFAULT_CHANNEL_SIZE"
        if [[ "$transport_protocol" == "tcp" || "$transport_protocol" == "tcpmux" ]]; then
            _handle_single_adv_param "Accept UDP over TCP" "accept_udp" "BH_DEFAULT_ACCEPT_UDP"
        fi
    else # client mode
        if [[ "$is_interactive" == "true" ]]; then print_info "--- Client-Specific Advanced Parameters ---"; fi
        _handle_single_adv_param "Connection Pool Size" "connection_pool" "BH_DEFAULT_CONNECTION_POOL"
        _handle_single_adv_param "Aggressive Pool Mgmt" "aggressive_pool" "BH_DEFAULT_AGGRESSIVE_POOL"
        _handle_single_adv_param "Retry Interval (s)" "retry_interval" "BH_DEFAULT_RETRY_INTERVAL"
        _handle_single_adv_param "Dial Timeout (s)" "dial_timeout" "BH_DEFAULT_DIAL_TIMEOUT"

        if [[ "$transport_protocol" == "ws" || "$transport_protocol" == "wss" || "$transport_protocol" == "wsmux" || "$transport_protocol" == "wssmux" ]]; then
            if [[ "$is_interactive" == "true" ]]; then
                local current_edge_ip="" # Default to empty for prompt
                read -r -p "Configure 'Edge IP (for CDN/WebSocket routing)' (edge_ip) [Default: blank]: " input_val
                input_val="${input_val:-$current_edge_ip}"
                if [[ -n "$input_val" ]]; then
                    if validate_ip "$input_val"; then
                        params_ref["edge_ip"]="$input_val"
                        print_success "  edge_ip set to: ${params_ref[edge_ip]}"
                    else
                        print_warning "  Invalid Edge IP: $input_val. Not set."
                    fi
                else
                     print_info "  Edge IP not set (blank)."
                fi
                echo
            else
                # For Quick Setup, edge_ip is not automatically set unless a BH_DEFAULT_EDGE_IP was defined (it's not)
                log_message "DEBUG" "Quick Setup: edge_ip not set by default."
            fi
        fi
    fi

    if [[ "$transport_protocol" =~ mux$ ]]; then # MUX specific
        if [[ "$is_interactive" == "true" ]]; then print_info "--- Multiplexer (MUX) Advanced Parameters ---"; fi
        _handle_single_adv_param "Mux Concurrency" "mux_con" "BH_DEFAULT_MUX_CON"
        _handle_single_adv_param "Mux Version" "mux_version" "BH_DEFAULT_MUX_VERSION"
        _handle_single_adv_param "Mux Frame Size (bytes)" "mux_framesize" "BH_DEFAULT_MUX_FRAMESIZE"
        _handle_single_adv_param "Mux Receive Buffer (bytes)" "mux_receivebuffer" "BH_DEFAULT_MUX_RECEIVEBUFFER"
        _handle_single_adv_param "Mux Stream Buffer (bytes)" "mux_streambuffer" "BH_DEFAULT_MUX_STREAMBUFFER"
    fi

    if [[ "$is_interactive" == "true" ]]; then
        print_info "Advanced parameter configuration complete."
        press_any_key
    else
        log_message "INFO" "Finished populating advanced parameters with defaults for Quick Setup."
    fi
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
    declare -A advanced_params_map # Associative array for advanced parameters

    # NOTE: The old local cfg_* variables are no longer used for storing defaults here.
    # They will be sourced from BH_DEFAULT_* globals within _prompt_advanced_parameters
    # and results stored in advanced_params_map.

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
            # NEW STEP for Server Port Forwarding Rules (Step 4)
            4)
                if [[ "$tunnel_mode" == "server" ]]; then
                    _configure_server_forwarding_rules server_port_rules # Pass the array by nameref
                    step_rc=$? # _configure_server_forwarding_rules returns 0 on 'done'
                    # This function handles its own internal looping, 'help', and 'done'.
                    # It doesn't have a 'back' option to a previous wizard step.
                    # If it needs to signal a full wizard cancel, it would return non-zero.
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
            5) # Step 5 (Was 4): Advanced Configuration Prompts / Default Population
                if $setup_is_advanced; then
                    # Interactive prompting for Advanced Setup
                    _prompt_advanced_parameters advanced_params_map "$tunnel_mode" "$transport_protocol" true
                    step_rc=$?
                    if [[ "$step_rc" -ne 0 ]]; then
                        print_info "Advanced configuration cancelled or failed."
                        return 1 # Exit wizard
                    fi
                else
                    # Non-interactive population of defaults for Quick Setup
                    _prompt_advanced_parameters advanced_params_map "$tunnel_mode" "$transport_protocol" false
                    step_rc=$? # Should always be 0 if logic is correct
                    if [[ "$step_rc" -ne 0 ]]; then
                        handle_error "CRITICAL" "Failed to populate default advanced parameters for Quick Setup."
                        return 1 # Exit wizard
                    fi
                fi
                # Common path after populating advanced_params_map one way or another
                ((current_wizard_step++))
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
                echo "  Token: [set]"

                if $setup_is_advanced && [[ ${#advanced_params_map[@]} -gt 0 ]]; then
                    echo "  --- Advanced Settings ---"
                    # Iterate through advanced_params_map to display them
                    # Sorting keys for consistent display:
                    local key
                    for key in $(echo "${!advanced_params_map[@]}" | tr ' ' '\n' | sort); do
                        # Do not display sensitive or overly verbose params if not desired
                        # For now, display all collected advanced params
                        echo "    $key = ${advanced_params_map[$key]}"
                    done
                    # Display edge_ip if set (it's handled separately for now)
                    # edge_ip is now part of advanced_params_map, so it's displayed by the loop.
                elif $setup_is_advanced; then # Should not be hit if advanced_params_map is populated by default for quick.
                    echo "  --- Advanced Settings: Will use script defaults (prompting was just done) ---"
                else # Quick setup - advanced_params_map still populated with defaults
                    echo "  --- Optional Settings (using script defaults) ---"
                     local key
                    for key in $(echo "${!advanced_params_map[@]}" | tr ' ' '\n' | sort); do
                        echo "    $key = ${advanced_params_map[$key]}"
                    done
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
                    local param_key param_value param_type
                    for param_key in "${!advanced_params_map[@]}"; do
                        param_value="${advanced_params_map[$param_key]}"
                        # Determine data type for update_toml_value (simple heuristic)
                        param_type="string" # Default to string
                        if [[ "$param_value" == "true" || "$param_value" == "false" ]]; then
                            param_type="boolean"
                        elif [[ "$param_value" =~ ^[0-9]+$ ]]; then
                            param_type="numeric"
                        fi

                        # Skip writing sniffer_log if sniffer is false, or handle its path generation here
                        if [[ "$param_key" == "sniffer_log" && "${advanced_params_map[sniffer]}" != "true" ]]; then
                            continue
                        elif [[ "$param_key" == "sniffer_log" && "${advanced_params_map[sniffer]}" == "true" ]]; then
                             # Ensure sniffer_log path is sensible if not customized by user
                             # For now, _prompt_advanced_parameters sets it, or we use a generated one.
                             # The path generation is already: cfg_sniffer_log="/var/log/easybackhaul/${final_tunnel_name}-sniffer.json"
                             # So, if sniffer is true, and sniffer_log is in advanced_params_map, it will be written.
                             # If sniffer_log was not explicitly prompted & changed in _prompt_advanced_parameters,
                             # we might need to set it here based on final_tunnel_name if sniffer is true.
                             # For now, assume _prompt_advanced_parameters populates it correctly if sniffer is true.
                             # Or, more simply, if sniffer is true, ensure sniffer_log gets a value.
                            if [[ "${advanced_params_map[sniffer]}" == "true" && -z "${advanced_params_map[sniffer_log]}" ]] ; then
                                advanced_params_map[sniffer_log]="/var/log/easybackhaul/${final_tunnel_name}-sniffer.json" # Default path if sniffer true but no log path set
                                param_value="${advanced_params_map[sniffer_log]}" # update for current iteration
                            fi
                        fi

                        # Ensure web_port is not written if 0 (disabled), unless backhaul handles web_port=0 correctly
                        if [[ "$param_key" == "web_port" && "$param_value" -eq 0 ]]; then
                            # Optional: explicitly skip writing web_port = 0 if backhaul doesn't like it
                            # log_message "DEBUG" "Skipping web_port = 0 for $config_file_path"
                            continue # Skip writing web_port = 0
                        fi

                        update_toml_value "$config_file_path" "$param_key" "$param_value" "$param_type"
                    done
                # Removed the 'else' block for Quick Setup here, as advanced_params_map is now always populated
                # (either by user input in Advanced mode, or by script defaults in Quick mode).
                # The loop above will handle writing all necessary optional parameters.
                # The log message for Quick Setup using binary defaults is no longer accurate,
                # as we are now writing explicit script defaults.
                fi
                # A general log message for Quick Setup can be added if needed,
                # or rely on the debug messages from _prompt_advanced_parameters.
                # Example:
                if ! $setup_is_advanced; then
                    log_message "INFO" "Quick setup for $final_tunnel_name: All applicable optional parameters written with script defaults."
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
                    # create_systemd_service now handles enabling and the initial start attempt.
                    # It also prompts "Check service status now?".
                    # So, we just call it and report potential errors from it.
                    if ! create_systemd_service "$final_tunnel_name" "$config_file_path"; then
                         handle_error "ERROR" "Systemd service creation or initial start failed for '$final_tunnel_name'. Please check previous messages or use 'Manage Existing Tunnels' to check status and logs."
                         # No redundant start prompt here, create_systemd_service handles the attempt.
                    fi
                else
                    handle_error "WARNING" "Function 'create_systemd_service' not found. Cannot create service automatically."
                fi
                press_any_key
                return_from_menu # Return to the previous menu (likely main menu)
                return 0 # Exit configure_tunnel function
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
