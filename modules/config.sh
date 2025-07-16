# modules/config.sh
# Tunnel configuration wizard and related TOML file management.

# WARNING: Do not use a global CONFIG_FILE variable. All configurations are per-tunnel TOML files.

# --- Helper: Get process information for a port ---
# This is kept here as it's specific to the config wizard's port checking UX
_get_port_process_info() {
    local port_to_check="$1"
    log_message "DEBUG" "Checking process for port $port_to_check"
    
    if command -v ss &>/dev/null; then
        ss -lntupe "sport = :$port_to_check" 2>/dev/null | awk 'NR>1 {printf "  - Process (ss): %s\n", $0}'
    elif command -v netstat &>/dev/null; then
        netstat -tlnp 2>/dev/null | grep ":${port_to_check}[[:space:]]" | awk '{printf "  - Process (netstat): %s\n", $0}'
    elif command -v lsof &>/dev/null; then
        lsof -i ":$port_to_check" -sTCP:LISTEN -P -n -- 2>/dev/null | awk 'NR>1 {printf "  - Process (lsof): %s\n", $0}'
    else
        print_info "  Port $port_to_check is in use, but detailed process info unavailable with current tools."
        return 1
    fi
    return 0
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
                        transport_ref=$(awk '{print $1}' <<< "${transport_options_arr[$(($MENU_CHOICE-1))]}")
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
    local -n local_fwd_port_ref=$5 # Output for client mode (local port to forward from) - NO LONGER USED for prompting/saving
    local -n auth_token_ref=$6  # Output: auth token

    print_menu_header "secondary" "Basic Configuration" "Step 3: Mandatory Settings"

    if [[ "$tunnel_mode" == "server" ]]; then
        print_info "Server Mode: Configure listening address."
        if [[ -z "$SERVER_IP" || "$SERVER_IP" == "N/A" ]]; then get_server_info; fi # Ensure we have an IP for defaults if needed

        if ! prompt_for_port "Port for Backhaul server to listen on (e.g., 443)" "443" true listen_port_ref; then
            print_error "Failed to get a valid listen port for server."
            return 1 # Critical failure
        fi
    else # client mode
        print_info "Client Mode: Configure remote server details."
        if ! prompt_for_ip "Public IP address of the Backhaul SERVER" "" true remote_ip_ref; then
            print_error "Failed to get a valid remote server IP for client."
            return 1 # Critical failure
        fi
        
        if ! prompt_for_port "Port the Backhaul SERVER is listening on" "443" false remote_port_ref; then
            print_error "Failed to get a valid remote server port for client."
            return 1 # Critical failure
        fi
    fi

    local default_auth_token="EasyBackhaulSecretToken" # Example default
    print_info "Set an authentication token (must match on both server and client)."
    while true; do
        read -r -s -p "Enter token (min 8 chars, or type 'cancel'): " auth_token_val
        printf "\n" # Newline after secret input
        if [[ "$auth_token_val" == "cancel" ]]; then
            print_info "Token input cancelled by user."
            return 1 # Signal cancellation
        fi
        # Use default if input is empty AND a default is set (currently not using default_auth_token if empty)
        # Forcing user to enter something or explicitly cancel.
        # auth_token_val=${auth_token_val:-$default_auth_token}
        if [[ -z "$auth_token_val" ]]; then
             print_warning "Token cannot be empty."
             if ! prompt_yes_no "Try entering token again?" "y"; then print_error "Token setup aborted."; return 1; fi
        elif [[ "${#auth_token_val}" -lt 8 ]]; then
            print_warning "Token too short. Please use at least 8 characters for security."
            if ! prompt_yes_no "Try entering token again?" "y"; then print_error "Token setup aborted."; return 1; fi
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

    print_menu_header "secondary" "TLS Certificate Configuration" "Step 6: Secure Protocols (WSS/WSSMUX)" # Adjusted step
    print_info "Secure protocols (WSS/WSSMUX) require a TLS certificate and private key."

    local cert_dir_global="${CERT_DIR:-/etc/easybackhaul/certs}" # CERT_DIR from globals.sh
    ensure_dir "$cert_dir_global" "700" # Ensure it exists
    
    mapfile -t existing_certs < <(find "$cert_dir_global" -maxdepth 1 \( -name '*.pem' -o -name '*.crt' \) 2>/dev/null | sort)
    
    local tls_options=()
    local cert_map=() # Associative array to map choice number to paths

    if [[ ${#existing_certs[@]} -gt 0 ]]; then
        print_info "Existing certificates/keys found in $cert_dir_global:"
        local count=1
        for cert_file in "${existing_certs[@]}"; do
            # Try to find a matching .key file (more specific than just another .pem)
            local potential_key_file_key="${cert_file%.pem}.key"
            if [[ ! -f "$potential_key_file_key" ]]; then potential_key_file_key="${cert_file%.crt}.key"; fi

            # Fallback if .key not found, check for a .pem that could be a key (less ideal)
            local potential_key_file_pem="${cert_file%.crt}.pem" # if cert is .crt, key could be .pem
            if [[ "$cert_file" == *".pem" && -f "${cert_file%.pem}.pem" && "$cert_file" != "${cert_file%.pem}.pem" ]]; then
                 # This case is tricky, could be two .pem files. Assume cert is fullchain.pem, key is privkey.pem
                 # For simplicity, this heuristic might not be perfect.
                 : # Skip complex .pem + .pem logic for now, prefer .crt + .key or .pem + .key
            fi

            local final_key_file=""
            if [[ -f "$potential_key_file_key" ]]; then
                final_key_file="$potential_key_file_key"
            # Add more sophisticated pairing logic if needed, e.g. matching common names
            elif [[ -f "$potential_key_file_pem" && "$cert_file" != "$potential_key_file_pem" ]]; then
                 # Heuristic: if cert is fullchain.pem, key might be privkey.pem
                 if [[ "$(basename "$cert_file")" == "fullchain.pem" && "$(basename "$potential_key_file_pem")" == "privkey.pem" ]]; then
                    final_key_file="$potential_key_file_pem"
                 fi
            fi

            if [[ -n "$final_key_file" ]]; then
                 tls_options+=("$count. Use: $(basename "$cert_file") & $(basename "$final_key_file")")
                 cert_map[$count]="$cert_file;$final_key_file" # Store paths
                 ((count++))
            else
                # If only a single .pem or .crt is found without a clear pair, list it as possibly incomplete
                # For now, we only list clear pairs.
                # print_warning "Certificate $(basename "$cert_file") found without a clearly matching .key file, skipping for auto-pairing."
                :
            fi
        done
    fi
    tls_options+=("$((${#cert_map[@]} + 1)). Generate New Self-Signed Certificate")
    local generate_new_opt_num=$((${#cert_map[@]} + 1))
    tls_options+=("$((${#cert_map[@]} + 2)). Manually Enter Paths for Certificate and Key")
    local manual_paths_opt_num=$((${#cert_map[@]} + 2))
    tls_options+=("$((${#cert_map[@]} + 3)). Skip TLS configuration (NOT RECOMMENDED)")
    local skip_tls_opt_num=$((${#cert_map[@]} + 3))


    _tls_help() {
        print_info "TLS Configuration Help:"
        echo " - Select an existing certificate/key pair if found."
        echo " - Choose 'Generate New' to create a self-signed certificate."
        echo " - 'Manually Enter Paths' if your cert/key are elsewhere."
        echo " - 'Skip TLS' will proceed without TLS; WSS/WSSMUX will likely fail."
        echo " - Certificate paths are stored in the tunnel's TOML config file."
        echo "Use 'r' to return to previous step, 'm' for main menu."
        press_any_key
    }

    menu_loop "Select TLS certificate option" tls_options "_tls_help"
    local menu_rc=$?
    local user_choice="$MENU_CHOICE"

    case "$menu_rc" in
        0) # Numeric choice
            if (( user_choice == generate_new_opt_num )); then
                # generate_self_signed_tls_cert now takes namerefs to store the paths
                local generated_cert_path=""
                local generated_key_path=""
                if generate_self_signed_tls_cert generated_cert_path generated_key_path; then
                    if [[ -n "$generated_cert_path" && -n "$generated_key_path" ]]; then
                        tls_cert_path_ref="$generated_cert_path"
                        tls_key_path_ref="$generated_key_path"
                        print_success "Using newly generated cert: $tls_cert_path_ref and key: $tls_key_path_ref"
                    else
                        handle_error "ERROR" "Certificate generation function completed but did not return paths. Please enter manually."
                        # Fallback to manual entry
                        read -e -r -p "Enter full path to TLS certificate file (.crt or .pem): " tls_cert_path_ref
                        read -e -r -p "Enter full path to TLS private key file (.key or .pem): " tls_key_path_ref
                        if [[ ! -f "$tls_cert_path_ref" || ! -f "$tls_key_path_ref" ]]; then
                            handle_error "ERROR" "One or both manually entered TLS file paths are invalid."; return 1;
                        fi
                    fi
                else
                    print_warning "Self-signed certificate generation failed or was cancelled."
                    if prompt_yes_no "Retry TLS configuration?" "y"; then
                        _prompt_tls_config "$transport" tls_cert_path_ref tls_key_path_ref
                        return $?
                    else
                        return 1
                    fi
                fi
            elif (( user_choice == manual_paths_opt_num )); then
                read -e -r -p "Enter full path to TLS certificate file (.crt or .pem): " tls_cert_path_ref
                read -e -r -p "Enter full path to TLS private key file (.key or .pem): " tls_key_path_ref
                if [[ ! -f "$tls_cert_path_ref" || ! -f "$tls_key_path_ref" ]]; then
                    handle_error "ERROR" "One or both manually entered TLS file paths are invalid."
                    if prompt_yes_no "Retry entering paths?" "y"; then _prompt_tls_config "$transport" tls_cert_path_ref tls_key_path_ref; return $?; else return 1; fi
                fi
                print_success "Using manually specified cert: $tls_cert_path_ref and key: $tls_key_path_ref"
            elif (( user_choice == skip_tls_opt_num )); then
                print_warning "Skipping TLS configuration. WSS/WSSMUX will likely not work without it."
                tls_cert_path_ref=""; tls_key_path_ref=""
            elif [[ -n "${cert_map[$user_choice]}" ]]; then
                IFS=';' read -r tls_cert_path_ref tls_key_path_ref <<< "${cert_map[$user_choice]}"
                print_success "Using selected cert: $tls_cert_path_ref and key: $tls_key_path_ref"
            else
                handle_error "ERROR" "Invalid TLS certificate selection: $user_choice."
                if prompt_yes_no "Retry TLS setup step?" "y"; then _prompt_tls_config "$transport" tls_cert_path_ref tls_key_path_ref; return $?; else return 1; fi
            fi
            return 0
            ;;
        2) _prompt_tls_config "$transport" tls_cert_path_ref tls_key_path_ref; return $? ;;
        3) print_info "Configuration cancelled: returning to Main Menu."; return 1 ;;
        4) request_script_exit; return 1 ;;
        5) print_info "Going back to previous step from TLS config."; return 2 ;;
        6) _prompt_tls_config "$transport" tls_cert_path_ref tls_key_path_ref; return $? ;;
        *)
            handle_error "ERROR" "Unhandled menu_loop code $menu_rc in _prompt_tls_config"
            if prompt_yes_no "Unexpected error in TLS config. Retry this step?" "y"; then _prompt_tls_config "$transport" tls_cert_path_ref tls_key_path_ref; return $?; else return 1; fi
    esac
    return 0
}

# Validates a single port or a port range (e.g., "80", "400-500").
# Also handles optional /udp suffix on the port/range string.
# Output: Sets global array _VALIDATED_PORT_RANGE_PARTS to (type, port1, port2, protocol_suffix) on success.
# Returns 0 if valid, 1 if invalid.
_VALIDATED_PORT_RANGE_PARTS=()
_validate_port_or_range_with_udp() {
    local port_spec_full="$1"
    local port_spec_no_udp="$port_spec_full"
    local protocol_suffix=""

    _VALIDATED_PORT_RANGE_PARTS=() # Reset

    if [[ "$port_spec_full" == */udp ]]; then
        protocol_suffix="/udp"
        port_spec_no_udp="${port_spec_full%/udp}"
    fi

    if [[ "$port_spec_no_udp" =~ ^[0-9]+$ ]]; then # Single port
        if validate_port "$port_spec_no_udp"; then # validate_port is from helpers.sh
            _VALIDATED_PORT_RANGE_PARTS=("single" "$port_spec_no_udp" "" "$protocol_suffix")
            return 0
        fi
        # validate_port prints its own error
        return 1
    elif [[ "$port_spec_no_udp" =~ ^([0-9]+)-([0-9]+)$ ]]; then # Port range
        local start_port="${BASH_REMATCH[1]}"
        local end_port="${BASH_REMATCH[2]}"
        if validate_port "$start_port" && validate_port "$end_port"; then
            if (( start_port <= end_port )); then # Allow start_port == end_port for single port range
                _VALIDATED_PORT_RANGE_PARTS=("range" "$start_port" "$end_port" "$protocol_suffix")
                return 0
            else
                print_warning "Invalid range: Start port $start_port must be less than or equal to end port $end_port."
                return 1
            fi
        fi
        # validate_port prints its own error
        return 1
    else
        print_warning "Invalid port/range format: '$port_spec_full'. Use 'port', 'port/udp', 'start-end', or 'start-end/udp'."
        return 1
    fi
}


# Prompts user for server port forwarding rules using a single comma-separated input.
# Arguments:
#   $1 (nameref): Output array for TOML-formatted rule strings.
#   $2 (nameref): Output flag (boolean string "true"/"false") indicating if any UDP rules were specified.
# Returns: 0 on success (rules processed, could be empty), 1 on unrecoverable input error or cancellation.
_configure_server_forwarding_rules() {
    local -n out_rules_array_ref=$1
    local -n out_any_udp_rules_ref=$2

    out_rules_array_ref=() # Initialize output array
    out_any_udp_rules_ref="false" # Initialize UDP flag

    print_menu_header "secondary" "Server Port Forwarding" "Step 4: Configure Forwarding Rules"
    echo "Define how the server forwards incoming traffic to the client."
    echo "You can specify multiple rules separated by commas."
    echo
    print_info "Rule Formats:"
    echo "  - Port Forwarding: <server_port>:<client_port>"
    echo "    e.g., '8080:80' forwards TCP traffic from server's port 8080 to client's port 80."
    echo "  - Port Range Forwarding: <start>-<end>:<client_start>"
    echo "    e.g., '7000-7010:7000' forwards server ports 7000-7010 to client ports 7000-7010."
    echo "  - Simple Port Forwarding: <port>"
    echo "    e.g., '443' is a shortcut for '443:443'."
    echo "  - UDP Forwarding: Add '/udp' to the server port."
    echo "    e.g., '53/udp' forwards UDP traffic from server's port 53 to client's port 53."
    echo "    (Requires 'accept_udp = true' in advanced options for non-UDP transports)."
    echo "  - Forward to Specific Client IP: <server_port>=<client_ip>:<client_port>"
    echo "    e.g., '2222=192.168.0.10:22' forwards to a specific IP on the client's network."
    echo
    print_info "Example Entry:"
    echo "  80, 443:8443, 7000-7010:7000, 53/udp, 2222=10.0.0.5:22"
    echo
    echo "Leave blank for no forwarding."
    echo

    local user_input_str
    read -r -p "Enter forwarding rules: " user_input_str

    if [[ -z "$user_input_str" ]]; then
        print_info "No port forwarding rules entered."
        return 0 # Success, but no rules
    fi

    local IFS=',' # Set Internal Field Separator to comma for splitting
    read -ra raw_rules <<< "$user_input_str" # Split into array
    local IFS=$' \t\n' # Reset IFS

    local rule_valid
    for rule_str_raw in "${raw_rules[@]}"; do
        local rule_str
        rule_str=$(xargs <<< "$rule_str_raw") # Trim whitespace

        if [[ -z "$rule_str" ]]; then continue; fi # Skip empty rules if user entered ",,"

        local listen_spec listen_type listen_port1 listen_port2 listen_protocol_suffix
        local dest_ip dest_port
        local toml_rule=""
        rule_valid=false

        # Try to parse listen_spec=dest_ip:dest_port format
        if [[ "$rule_str" =~ ^([^=]+)=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):([0-9]+(/udp)?)$ ]]; then
            listen_spec="${BASH_REMATCH[1]}"
            dest_ip="${BASH_REMATCH[2]}"
            local dest_port_full="${BASH_REMATCH[3]}" # e.g., "22" or "22/udp"

            local dest_port_no_udp="$dest_port_full"
            local dest_protocol_suffix=""
            if [[ "$dest_port_full" == */udp ]]; then
                dest_protocol_suffix="/udp"
                dest_port_no_udp="${dest_port_full%/udp}"
            fi

            if _validate_port_or_range_with_udp "$listen_spec" && \
               validate_ip "$dest_ip" && \
               validate_port "$dest_port_no_udp"; then

                listen_type="${_VALIDATED_PORT_RANGE_PARTS[0]}"
                listen_port1="${_VALIDATED_PORT_RANGE_PARTS[1]}"
                listen_port2="${_VALIDATED_PORT_RANGE_PARTS[2]}"
                listen_protocol_suffix="${_VALIDATED_PORT_RANGE_PARTS[3]}"

                if [[ "$listen_protocol_suffix" == "/udp" || "$dest_protocol_suffix" == "/udp" ]]; then
                    out_any_udp_rules_ref="true"
                    # Backhaul's `ports` array does not seem to use /udp. `accept_udp=true` handles it.
                fi

                local toml_listen_part="$listen_port1"
                if [[ "$listen_type" == "range" ]]; then toml_listen_part="${listen_port1}-${listen_port2}"; fi

                toml_rule="${toml_listen_part}=${dest_ip}:${dest_port_no_udp}" # UDP suffix not part of TOML rule string
                rule_valid=true
            fi

        # Try to parse listen_spec:dest_port format
        elif [[ "$rule_str" =~ ^([^:]+):([0-9]+(/udp)?)$ ]]; then
            listen_spec="${BASH_REMATCH[1]}"
            local dest_port_full="${BASH_REMATCH[2]}"

            local dest_port_no_udp="$dest_port_full"
            local dest_protocol_suffix=""
            if [[ "$dest_port_full" == */udp ]]; then
                dest_protocol_suffix="/udp"
                dest_port_no_udp="${dest_port_full%/udp}"
            fi

            if _validate_port_or_range_with_udp "$listen_spec" && \
               validate_port "$dest_port_no_udp"; then

                listen_type="${_VALIDATED_PORT_RANGE_PARTS[0]}"
                listen_port1="${_VALIDATED_PORT_RANGE_PARTS[1]}"
                listen_port2="${_VALIDATED_PORT_RANGE_PARTS[2]}"
                listen_protocol_suffix="${_VALIDATED_PORT_RANGE_PARTS[3]}"

                if [[ "$listen_protocol_suffix" == "/udp" || "$dest_protocol_suffix" == "/udp" ]]; then
                    out_any_udp_rules_ref="true"
                fi

                local toml_listen_part="$listen_port1"
                if [[ "$listen_type" == "range" ]]; then toml_listen_part="${listen_port1}-${listen_port2}"; fi

                toml_rule="${toml_listen_part}:${dest_port_no_udp}" # UDP suffix not part of TOML rule string
                rule_valid=true
            fi

        # Try to parse listen_spec (single port or range, with optional /udp)
        elif _validate_port_or_range_with_udp "$rule_str"; then
            listen_type="${_VALIDATED_PORT_RANGE_PARTS[0]}"
            listen_port1="${_VALIDATED_PORT_RANGE_PARTS[1]}"
            listen_port2="${_VALIDATED_PORT_RANGE_PARTS[2]}"
            listen_protocol_suffix="${_VALIDATED_PORT_RANGE_PARTS[3]}"

            if [[ "$listen_protocol_suffix" == "/udp" ]]; then
                out_any_udp_rules_ref="true"
            fi

            # For 'local_port' or 'local_range' shorthand, Backhaul expects just the port/range.
            # Example: "443" implies "443:443". "443-600" implies "443-600:443-600" (effectively).
            if [[ "$listen_type" == "single" ]]; then
                toml_rule="$listen_port1"
            elif [[ "$listen_type" == "range" ]]; then
                toml_rule="${listen_port1}-${listen_port2}"
            fi
            rule_valid=true
        fi

        if $rule_valid; then
            out_rules_array_ref+=("$toml_rule")
            print_success "  Rule parsed: \"$rule_str\" -> TOML: \"$toml_rule\""
        else
            print_warning "  Invalid rule format or component: '$rule_str'. Skipping."
            # Optionally, ask user to retry this specific rule or continue?
            # For now, just skip invalid parts of the comma-separated string.
        fi
    done

    if [[ ${#out_rules_array_ref[@]} -eq 0 && -n "$user_input_str" ]]; then
        print_warning "No valid forwarding rules were extracted from the input."
        # No 'return 1' here, let it proceed with empty rules if all were invalid.
    elif [[ ${#out_rules_array_ref[@]} -gt 0 ]]; then
        print_success "All rules processed. Total valid rules: ${#out_rules_array_ref[@]}"
    fi

    if [[ "$out_any_udp_rules_ref" == "true" ]]; then
        print_info "Note: UDP rules specified. Ensure 'accept_udp = true' is set in server's advanced options if not using UDP transport directly."
    fi

    press_any_key # Allow user to see results before continuing wizard
    return 0
}

# Prompts user for advanced optional parameters
# Populates an associative array with chosen values.
# Usage: _prompt_advanced_parameters params_assoc_array "$tunnel_mode" "$transport_protocol" "$is_interactive"
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
        # Default value can be pre-set in params_ref (e.g. accept_udp by configure_tunnel)
        # or fallback to BH_DEFAULT_* global.
        local current_default_val="${params_ref[$toml_key]:-${!default_val_var_name}}"
        local input_val

        if [[ "$is_interactive" == "true" ]]; then
            # Special handling for accept_udp prompt if it was pre-set
            if [[ "$toml_key" == "accept_udp" && "${params_ref[$toml_key]}" == "true" ]]; then
                print_info "Note: UDP port forwarding rules were specified, so 'accept_udp = true' is recommended."
            fi

            while true; do
                read -r -p "Configure '$desc' ($toml_key) [Default: $current_default_val]: " input_val
                input_val="${input_val:-$current_default_val}" # Apply default if empty

                # Basic validation
                if [[ "$toml_key" == "nodelay" || "$toml_key" == "sniffer" || "$toml_key" == "accept_udp" || "$toml_key" == "aggressive_pool" ]]; then
                    if [[ "$input_val" != "true" && "$input_val" != "false" ]]; then
                        print_warning "Invalid boolean. Must be 'true' or 'false'."
                        continue
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
        else # Not interactive
            # If params_ref[$toml_key] is already set (e.g. accept_udp from UDP rules), keep it.
            # Otherwise, set the BH_DEFAULT_* global.
            if [[ -z "${params_ref[$toml_key]}" ]]; then
                 params_ref["$toml_key"]="${!default_val_var_name}"
            fi
            log_message "DEBUG" "Advanced Param: $toml_key set to: ${params_ref[$toml_key]}"
        fi
    }

    # General Parameters
    _handle_single_adv_param "Log Level" "log_level" "BH_DEFAULT_LOG_LEVEL"
    _handle_single_adv_param "Enable Traffic Sniffer" "sniffer" "BH_DEFAULT_SNIFFER"
    # sniffer_log is handled during save config if sniffer is true

    if [[ "$transport_protocol" != "udp" ]]; then # These don't apply to raw UDP transport
        _handle_single_adv_param "TCP NoDelay" "nodelay" "BH_DEFAULT_NODELAY"
        _handle_single_adv_param "Keepalive Period (s)" "keepalive_period" "BH_DEFAULT_KEEPALIVE_PERIOD"
    fi
    _handle_single_adv_param "Web Interface Port (0 to disable)" "web_port" "BH_DEFAULT_WEB_PORT"

    if [[ "$tunnel_mode" == "server" ]]; then
        if [[ "$is_interactive" == "true" ]]; then print_info "--- Server-Specific Advanced Parameters ---"; fi
        if [[ "$transport_protocol" != "udp" ]]; then # Heartbeat not in UDP server example
             _handle_single_adv_param "Heartbeat Interval (s)" "heartbeat" "BH_DEFAULT_HEARTBEAT"
        fi
        _handle_single_adv_param "Channel Size" "channel_size" "BH_DEFAULT_CHANNEL_SIZE"

        # accept_udp is only relevant if the main transport is TCP-based (tcp, tcpmux, ws, wss, wsmux, wssmux)
        # If main transport is "udp", then accept_udp is not a valid parameter for backhaul server.
        if [[ "$transport_protocol" != "udp" ]]; then
            # `accept_udp` might have been pre-set to "true" by configure_tunnel if UDP port rules were added.
            # _handle_single_adv_param will use this pre-set value as the current_default_val.
            _handle_single_adv_param "Accept UDP over non-UDP transport" "accept_udp" "BH_DEFAULT_ACCEPT_UDP"
        elif [[ -n "${params_ref[accept_udp]}" ]]; then
            # If transport is UDP, but accept_udp was somehow set (e.g. by earlier UDP rules before transport change), unset it.
            unset params_ref["accept_udp"]
            log_message "DEBUG" "Removed accept_udp as transport is UDP."
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
                    local any_udp_rules_specified="false" # Initialize local flag
                    # _configure_server_forwarding_rules now takes the rules array and the udp flag nameref
                    # It will prompt the user for a comma-separated string of rules.
                    _configure_server_forwarding_rules server_port_rules any_udp_rules_specified
                    step_rc=$? # This function now returns 0 for success (even if no rules), 1 for critical error.
                               # It handles its own user interaction including 'press_any_key'.

                    if [[ "$step_rc" -ne 0 ]]; then
                        print_error "Failed to configure server port forwarding rules. Aborting wizard."
                        return_from_menu; return 1
                    fi

                    # If UDP rules were specified, and transport is not UDP itself,
                    # pre-set accept_udp to true in advanced_params_map.
                    # This will be picked up by _prompt_advanced_parameters later.
                    if [[ "$any_udp_rules_specified" == "true" && "$transport_protocol" != "udp" ]]; then
                        print_info "UDP port rules detected. Setting 'accept_udp = true' as a recommended default."
                        advanced_params_map["accept_udp"]="true"
                        # This ensures that even in Quick Setup, if UDP rules are added, accept_udp is true.
                        # In Advanced Setup, _prompt_advanced_parameters will see this and can use it as default.
                    fi
                    ((current_wizard_step++))
                else
                    # Not a server, skip this step
                    ((current_wizard_step++))
                fi
                ;;
            5) # Step 5: Advanced Configuration Prompts / Default Population
                # For Quick Setup (is_interactive=false), this populates advanced_params_map with script defaults.
                # For Advanced Setup (is_interactive=true), this prompts user for each.
                # It needs to be aware of any pre-set values in advanced_params_map (like accept_udp).
                _prompt_advanced_parameters advanced_params_map "$tunnel_mode" "$transport_protocol" "$setup_is_advanced"
                step_rc=$?
                if [[ "$step_rc" -ne 0 ]]; then
                    print_info "Advanced parameter configuration cancelled or failed."
                    return_from_menu; return 1 # Exit wizard
                fi
                ((current_wizard_step++))
                ;;
            6) # Step 6: TLS Configuration
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

                if [[ ${#advanced_params_map[@]} -gt 0 ]]; then # Check if map has entries, will be true for both Quick and Advanced
                    if $setup_is_advanced; then
                        echo "  --- Advanced Settings (User Customized/Confirmed Defaults) ---"
                    else # Quick Setup
                        echo "  --- Optional Settings (Using Script Defaults) ---"
                    fi
                    local key
                    for key in $(echo "${!advanced_params_map[@]}" | tr ' ' '\n' | sort); do
                        # Conditional display for sniffer_log and web_port=0
                        if [[ "$key" == "sniffer_log" && "${advanced_params_map[sniffer]}" != "true" ]]; then
                            # Only display sniffer_log if sniffer is true
                            continue
                        fi
                        if [[ "$key" == "web_port" && "${advanced_params_map[$key]}" == "0" ]]; then
                             echo "    $key = ${advanced_params_map[$key]} (Disabled)"
                             continue
                        fi
                        echo "    $key = ${advanced_params_map[$key]}"
                    done
                fi
                # Note: edge_ip is now part of advanced_params_map and will be displayed by the loop above if set.

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
                # cfg_sniffer_log is now populated in advanced_params_map if sniffer is true

                local config_file_path="$CONFIG_DIR/config-${final_tunnel_name}.toml"
                ensure_dir "$CONFIG_DIR" "755" # Ensure CONFIG_DIR is traversable
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

                # Write all parameters from advanced_params_map (populated for both Quick and Advanced)
                local param_key param_value param_type
                for param_key in "${!advanced_params_map[@]}"; do
                    param_value="${advanced_params_map[$param_key]}"
                    param_type="string" # Default
                    if [[ "$param_value" == "true" || "$param_value" == "false" ]]; then
                        param_type="boolean"
                    elif [[ "$param_value" =~ ^[0-9]+$ ]]; then
                        param_type="numeric"
                    fi

                    if [[ "$param_key" == "sniffer_log" && "${advanced_params_map[sniffer]}" != "true" ]]; then
                        continue # Skip sniffer_log if sniffer is not true
                    fi
                    if [[ "$param_key" == "sniffer_log" && "${advanced_params_map[sniffer]}" == "true" && -z "$param_value" ]]; then
                        # If sniffer is true but sniffer_log is empty in map (e.g. Quick setup didn't set it)
                        # then assign the generated default path.
                        param_value="/var/log/easybackhaul/${final_tunnel_name}-sniffer.json"
                    fi

                    if [[ "$param_key" == "web_port" && "$param_value" == "0" ]]; then
                        # Optional: Do not write 'web_port = 0' if backhaul binary defaults to disabled when key is absent.
                        # For explicitness, we are writing it. Backhaul should handle '0' as disabled.
                        # If it causes issues, this 'continue' can be un-commented.
                        # log_message "DEBUG" "Skipping web_port = 0 for $config_file_path"
                        # continue
                        : # Explicitly do nothing, will write web_port = 0
                    fi
                     # Skip empty edge_ip
                    if [[ "$param_key" == "edge_ip" && -z "$param_value" ]]; then
                        continue
                    fi

                    update_toml_value "$config_file_path" "$param_key" "$param_value" "$param_type"
                done

                if ! $setup_is_advanced; then
                    log_message "INFO" "Quick setup for $final_tunnel_name: All applicable optional parameters written with script defaults."
                fi

                if [[ -n "$cfg_tls_cert_path" && -n "$cfg_tls_key_path" ]]; then
                    update_toml_value "$config_file_path" "tls_cert" "$cfg_tls_cert_path" "string"
                    update_toml_value "$config_file_path" "tls_key" "$cfg_tls_key_path" "string"
                fi

                set_secure_file_permissions "$config_file_path" "600" # Will be chowned by create_systemd_service
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
