# modules/tunnel_mgmt.sh
# List/manage tunnels, single tunnel management, connection test.

# --- Main Tunnel Listing and Management Menu ---
manage_tunnels_menu() {
    # This function is the entry point for managing all tunnels.
    # It will use the new menu navigation system.

    _manage_tunnels_menu_help() {
        print_menu_header "secondary" "Tunnel Management Help"
        echo "This menu lists all configured Backhaul tunnels."
        echo "Select a tunnel number to manage its operations (start, stop, logs, etc.)."
        echo
        print_info "Status Indicators:"
        echo "  - Running: The tunnel's systemd service is active."
        echo "  - Stopped: The service is inactive or not found."
        echo "  - Failed: The service encountered an error."
        echo
        print_info "Navigation:"
        echo "  - Use number keys to select a tunnel."
        echo "  - '0' or 'x' or 'm' will behave as per the footer." # 'x' is alias for 'e' in menu_loop
        press_any_key
    }

    while true; do
        if [[ -z "$CONFIG_DIR" ]]; then
            handle_critical_error "CONFIG_DIR is not defined. Cannot list tunnels."
            # This is a critical error, usually means globals.sh didn't source.
            # Standard navigation might not be appropriate. However, to be safe:
            request_script_exit; return 1;
        fi

        mapfile -t config_files < <(find "$CONFIG_DIR" -maxdepth 1 -name "config-bh-*.toml" -type f 2>/dev/null | sort)

        local tunnel_options=()
        local service_name_map=()
        local tunnel_suffix_map=()

        if [[ ${#config_files[@]} -eq 0 ]]; then
            # No tunnels configured, present a simplified menu
            print_menu_header "primary" "Manage Tunnels" "No Tunnels Found"
            print_warning "No Backhaul tunnels configured yet."
            print_info "Use 'Configure a New Tunnel' from the main menu to create one."

            # local no_tunnel_exit_options=("0. Back to Main Menu") # No longer needed
            local no_tunnel_choice no_tunnel_rc

            # Prompt is empty as options are self-explanatory or covered by footer
            # Pass empty options array, menu_loop handles it.
            menu_loop "" tunnel_options "_manage_tunnels_menu_help"
            no_tunnel_choice="$MENU_CHOICE" # Will be a nav key
            no_tunnel_rc=$?

            case "$no_tunnel_rc" in
                # Case 0 (numeric choice) is not possible if tunnel_options is empty.
                # menu_loop will only return nav key codes.
                2) # '?' Help shown
                    continue ;;
                3) # 'm' Main Menu
                    go_to_main_menu; return 0 ;;
                4) # 'x' Exit script
                    request_script_exit; return 0 ;;
                5) # 'r' Return/Back (to main menu)
                    return_from_menu; return 0 ;;
                6) # 'c' Cancel (to main menu)
                    return_from_menu; return 0 ;;
                *)
                    print_warning "Unexpected choice/return code: $no_tunnel_rc / $no_tunnel_choice"; press_any_key; continue ;;
            esac
            #This continue should not be reached if all nav keys are handled properly above.
            # continue
        fi
        
        print_menu_header "primary" "Manage Tunnels" "Select a Tunnel"

        local idx=1
        for cfg_file in "${config_files[@]}"; do
            local current_tunnel_suffix
            current_tunnel_suffix=$(basename "$cfg_file" .toml | sed 's/^config-//')
            local current_service_name="backhaul-${current_tunnel_suffix}.service"

            local status_str="Unknown"
            local status_color="$COLOR_YELLOW"

            if systemctl list-units --full --all --type=service --no-legend "$current_service_name" | grep -q "$current_service_name"; then
                if systemctl is-active --quiet "$current_service_name"; then
                    status_str="Running"
                    status_color="$COLOR_GREEN"
                elif systemctl is-failed --quiet "$current_service_name"; then
                    status_str="Failed"
                    status_color="$COLOR_RED"
                else
                    status_str="Stopped"
                    status_color="$COLOR_YELLOW"
                fi
            else
                 status_str="No Service"
                 status_color="$COLOR_RED"
            fi

            tunnel_options+=("$idx. $current_tunnel_suffix [${status_color}${status_str}${COLOR_RESET}]")
            service_name_map[$idx]="$current_service_name"
            tunnel_suffix_map[$idx]="$current_tunnel_suffix"
            ((idx++))
        done

        # local exit_options=("0. Back to Main Menu") # No longer needed
        local user_choice menu_rc

        menu_loop "Select tunnel to manage" tunnel_options "_manage_tunnels_menu_help"
        user_choice="$MENU_CHOICE"
        menu_rc=$?

        case "$menu_rc" in
            0) # Numeric choice
                if [[ -n "${service_name_map[$user_choice]}" ]]; then
                    local selected_service="${service_name_map[$user_choice]}"
                    local selected_suffix="${tunnel_suffix_map[$user_choice]}"
                    navigate_to_menu "manage_specific_tunnel_menu \"$selected_service\" \"$selected_suffix\""
                    return 0 # Let main loop call the new menu function
                else
                    # This case should ideally not be reached if menu_loop validates numeric range
                    print_warning "Invalid numeric selection: $user_choice. Please try again."
                    press_any_key
                fi
                ;;
            2) # '?' Help shown
                continue ;;
            3) # 'm' Main Menu
                go_to_main_menu; return 0 ;;
            4) # 'x' Exit script
                request_script_exit; return 0 ;;
            5) # 'r' Return/Back (to main menu)
                return_from_menu; return 0 ;;
            6) # 'c' Cancel (to main menu)
                return_from_menu; return 0 ;;
            *)
                print_warning "Unexpected menu_loop return in manage_tunnels_menu: $menu_rc, choice: $user_choice"
                press_any_key
                ;;
        esac
    done
}

# --- Specific Tunnel Management Menu ---
manage_specific_tunnel_menu() {
    local service_name="$1"
    local tunnel_suffix="$2"
    local config_file_path="$CONFIG_DIR/config-${tunnel_suffix}.toml"

    _specific_tunnel_menu_help() {
        print_menu_header "secondary" "Tunnel Menu Help" "Tunnel: $tunnel_suffix"
        echo "Manage individual operations for the selected tunnel."
        echo "  1. Start: Starts the tunnel service."
        echo "  2. Stop: Stops the tunnel service."
        echo "  3. Restart: Restarts the tunnel service."
        echo "  4. View Logs: Access logs for this tunnel (journalctl)."
        echo "  5. View Config: Display the tunnel's TOML configuration."
        echo "  6. Edit Config: Manually edit TOML (requires restart to apply)."
        echo "  7. Change Log Level: Modify 'log_level' in TOML (requires restart)."
        echo "  8. Hot Reload Config: Send SIGHUP (if binary supports it)."
        echo "  9. Test Connection: Basic reachability test."
        echo " 10. Manage Watcher: Configure coordinated restart watcher." # Changed from Validate
        echo " 11. Validate Config: Check TOML syntax and parameters."   # Changed from Show Info
        echo " 12. Delete Tunnel: Permanently remove this tunnel."
        press_any_key
    }

    local menu_options=(
        "1. Start Tunnel"
        "2. Stop Tunnel"
        "3. Restart Tunnel"
        "4. View Logs (journalctl)"
        "5. View Configuration"
        "6. Edit Configuration (nano/vi)"
        "7. Change Log Level"
        "8. Hot Reload Config (SIGHUP)"
        "9. Test Connection"
        "10. Manage Restart Watcher" # Updated
        "11. Validate Configuration" # Updated
        "12. Delete Tunnel"
    )
    # local exit_options=("0. Back to Tunnel List") # No longer needed
    local user_choice menu_rc

    while true; do
        local current_status_str="Unknown"
        local current_status_color="$COLOR_YELLOW"
        if systemctl is-active --quiet "$service_name" 2>/dev/null; then
            current_status_str="Running"
            current_status_color="$COLOR_GREEN"
        elif systemctl is-failed --quiet "$service_name" 2>/dev/null; then
            current_status_str="Failed"
            current_status_color="$COLOR_RED"
        else # Not active and not failed -> stopped or not found
            if systemctl list-units --full --all --type=service --no-legend "$service_name" | grep -q "$service_name"; then
                 current_status_str="Stopped"
            else
                 current_status_str="No Service" # Service file might be missing
                 current_status_color="$COLOR_RED"
            fi
        fi
        
        print_menu_header "secondary" "Managing Tunnel: $tunnel_suffix" "Service: $service_name" "Status: ${current_status_color}${current_status_str}${COLOR_RESET}"
        
        menu_loop "Select action" menu_options "_specific_tunnel_menu_help"
        user_choice="$MENU_CHOICE"
        menu_rc=$?

        # local action_performed_and_continue=false # May not be needed if all actions handle their own flow

        case "$menu_rc" in
            0) # Numeric choice
                case "$user_choice" in
                    "1") _mng_start_tunnel "$service_name" ;;
                    "2") _mng_stop_tunnel "$service_name" ;;
                    "3") _mng_restart_tunnel "$service_name" ;;
                    "4")
                        # view_system_log is a self-contained menu, use navigate_to_menu
                        navigate_to_menu "view_system_log \"journalctl\" \"$service_name\" \"Logs for $tunnel_suffix\""
                        return 0 ;;
                    "5") _mng_view_configuration "$config_file_path" "$tunnel_suffix" ;;
                    "6") _mng_edit_configuration "$config_file_path" "$service_name" ;;
                    "7")
                        # _mng_change_log_level is a self-contained menu, use navigate_to_menu
                        navigate_to_menu "_mng_change_log_level \"$config_file_path\" \"$service_name\""
                        return 0 ;;
                    "8") _mng_hot_reload_service "$service_name" ;;
                    "9") _mng_test_connection "$config_file_path" ;;
                    "10")
                         if type manage_tunnel_watcher &>/dev/null; then
                            navigate_to_menu "manage_tunnel_watcher \"$service_name\" \"$tunnel_suffix\" \"$config_file_path\""
                            return 0
                         else
                            handle_error "ERROR" "Watcher management module not loaded correctly."
                            press_any_key
                         fi
                         ;;
                    "11")
                        if type validate_tunnel_config &>/dev/null; then # Assuming this is the correct validation function
                            validate_tunnel_config "$config_file_path" # Or validate_specific_tunnel_config if it exists
                        else
                            handle_error "INFO" "Config validation function not available."
                        fi
                        press_any_key
                        ;;
                    "12")
                        if _mng_delete_tunnel "$service_name" "$tunnel_suffix" "$config_file_path"; then
                            return_from_menu # Deletion successful, return to tunnel list
                            return 0
                        fi
                        # If deletion cancelled, _mng_delete_tunnel handles press_any_key and returns 1
                        # The loop will continue to re-display this menu.
                        ;;
                    *) print_warning "Invalid option: $user_choice"; press_any_key ;;
                esac
                ;;
            2) # '?' Help shown
                continue ;;
            3) # 'm' Main Menu
                go_to_main_menu; return 0 ;;
            4) # 'x' Exit script
                request_script_exit; return 0 ;;
            5) # 'r' Return/Back (to tunnel list)
                return_from_menu; return 0 ;;
            6) # 'c' Cancel (acts like 'r' here, back to tunnel list)
                return_from_menu; return 0 ;;
            *)
                print_warning "Unexpected menu_loop return in manage_specific_tunnel_menu: $menu_rc, choice: $user_choice"
                press_any_key
                ;;
        esac
    done
}

_mng_start_tunnel() {
    local service_to_start="$1"
    log_message "INFO" "Attempting to start service: $service_to_start"
    if run_with_spinner "Starting $service_to_start..." systemctl start "$service_to_start"; then
        handle_success "Service $service_to_start started."
    else
        handle_error "ERROR" "Failed to start $service_to_start. Check logs: journalctl -u $service_to_start -n 50"
    fi
    press_any_key
}

_mng_stop_tunnel() {
    local service_to_stop="$1"
    log_message "INFO" "Attempting to stop service: $service_to_stop"
    if run_with_spinner "Stopping $service_to_stop..." systemctl stop "$service_to_stop"; then
        handle_success "Service $service_to_stop stopped."
    else
        handle_error "ERROR" "Failed to stop $service_to_stop."
    fi
    press_any_key
}

_mng_restart_tunnel() {
    local service_to_restart="$1"
    log_message "INFO" "Attempting to restart service: $service_to_restart"
    if run_with_spinner "Restarting $service_to_restart..." systemctl restart "$service_to_restart"; then
        handle_success "Service $service_to_restart restarted."
    else
        handle_error "ERROR" "Failed to restart $service_to_restart. Check logs: journalctl -u $service_to_restart -n 50"
    fi
    press_any_key
}

_mng_view_configuration() {
    local cfg_file="$1"
    local suffix="$2"
    if [[ ! -f "$cfg_file" ]]; then
        handle_error "ERROR" "Configuration file not found for tunnel $suffix: $cfg_file"
        press_any_key; return 1;
    fi
    # Header is printed by calling menu. This function shows content then returns.
    # clear # Optional: if you want only the config shown.
    print_info "Displaying: $cfg_file (Press 'q' to quit 'less')"
    echo "----------------------------------------------------------------"
    if ! less "$cfg_file"; then
        # Even if less fails (e.g. redirected output), we might want a pause
        print_warning "Could not display configuration with 'less'. File might be empty or less is unavailable."
        press_any_key
    fi
    # No press_any_key here, less handles its own exit. If less fails, we might need one.
}

_mng_edit_configuration() {
    local cfg_file="$1"
    local service_to_restart="$2" # Tunnel suffix or service name
     if [[ ! -f "$cfg_file" ]]; then
        handle_error "ERROR" "Configuration file not found: $cfg_file"
        press_any_key; return 1;
    fi
    
    backup_configuration_path "$cfg_file" "tunnel-config-$(basename "$service_to_restart" .service)" # Use a clean name for backup
    
    if command -v nano &>/dev/null; then
        nano "$cfg_file"
    elif command -v vi &>/dev/null; then
        vi "$cfg_file"
    else
        handle_error "ERROR" "Neither 'nano' nor 'vi' found. Cannot edit configuration."
        press_any_key; return 1;
    fi

    print_info "Configuration file edit complete."
    if prompt_yes_no "Restart tunnel $service_to_restart to apply changes?" "y"; then
        _mng_restart_tunnel "$service_to_restart"
    else
        press_any_key # Pause if not restarting
    fi
}

_mng_change_log_level() {
    local cfg_file="$1"
    local service_to_restart="$2" # Tunnel suffix or service name
    
    if [[ ! -f "$cfg_file" ]]; then
        handle_error "ERROR" "Configuration file not found: $cfg_file"
        press_any_key; return 1;
    fi

    # This function now acts as its own sub-menu loop
    _log_level_help() {
        # Header printed by the loop
        print_info "Log Level Help:"
        echo " - debug: Verbose, for troubleshooting."
        echo " - info: Standard operational messages (default)."
        echo " - warn: Important warnings only."
        echo " - error: Only critical errors."
        press_any_key
    }
    
    while true; do
        print_menu_header "tertiary" "Change Log Level" "Service: $service_to_restart" # Or secondary
        
        local current_level="info"
        if grep -q 'log_level[[:space:]]*=' "$cfg_file"; then
            current_level=$(grep 'log_level[[:space:]]*=' "$cfg_file" | head -n1 | sed 's/.*=[[:space:]]*"\(.*\)"/\1/')
        fi
        print_info "Current log level in $(basename "$cfg_file"): ${COLOR_CYAN}$current_level${COLOR_RESET}"

        local log_level_options=("1. debug" "2. info" "3. warn" "4. error")
        # local log_level_exit_options=("0. Cancel and Back") # No longer needed
        local user_choice menu_rc

        menu_loop "Select new log level" log_level_options "_log_level_help"
        user_choice="$MENU_CHOICE"
        menu_rc=$?

        local new_level=""
        case "$menu_rc" in
            0) # Numeric choice
                case "$user_choice" in
                    "1") new_level="debug" ;;
                    "2") new_level="info" ;;
                    "3") new_level="warn" ;;
                    "4") new_level="error" ;;
                    *) print_warning "Invalid numeric selection: $user_choice"; press_any_key; continue ;;
                esac
                ;;
            2) # '?' Help shown
                continue ;;
            3) # 'm' Main Menu
                go_to_main_menu; return ;;
            4) # 'x' Exit script
                request_script_exit; return ;;
            5) # 'r' Return/Back
                print_info "Log level change cancelled via 'r'."; press_any_key; return_from_menu; return ;;
            6) # 'c' Cancel
                print_info "Log level change cancelled via 'c'."; press_any_key; return_from_menu; return ;;
            *)
                print_warning "Unexpected menu return in log level: $menu_rc, choice: $user_choice"; press_any_key; continue ;;
        esac

        if [[ -n "$new_level" ]]; then
            # Use the unified backup function before modifying
            backup_configuration_path "$cfg_file" "log-level-change-$(basename "$service_to_restart" .service)"

            if update_toml_value "$cfg_file" "log_level" "$new_level" "string"; then
                handle_success "Log level set to '$new_level' in $cfg_file."
                if prompt_yes_no "Restart tunnel $service_to_restart to apply new log level?" "y"; then
                    _mng_restart_tunnel "$service_to_restart" # This calls press_any_key
                else
                    press_any_key # Pause if not restarting
                fi
                return # Successfully changed, return to specific tunnel menu
            else
                handle_error "ERROR" "Failed to update log level in $cfg_file."
                press_any_key # Pause on error
                # Loop again or return? For now, loop again.
            fi
        fi
    done
}

_mng_hot_reload_service() {
    local service_to_reload="$1"
    log_message "INFO" "Attempting to send SIGHUP to $service_to_reload for hot reload."
    if run_with_spinner "Sending SIGHUP to $service_to_reload..." systemctl kill -s HUP "$service_to_reload"; then
        handle_success "Hot reload signal (SIGHUP) sent to $service_to_reload."
        print_info "If the Backhaul binary supports hot reload, configuration changes should be applied."
    else
        handle_error "ERROR" "Failed to send SIGHUP to $service_to_reload. Binary or system may not support this."
    fi
    press_any_key
}

_mng_test_connection() {
    local cfg_file="$1"
    if [[ ! -f "$cfg_file" ]]; then handle_error "ERROR" "Config file not found: $cfg_file"; press_any_key; return 1; fi

    # Header is printed by the calling menu. This function shows info then returns.
    print_info "--- Connection Test for $(basename "$cfg_file") ---" # Simple sub-header
    
    local tunnel_mode listen_addr remote_addr target_ip target_port
    
    if grep -q 'mode[[:space:]]*=[[:space:]]*"server"' "$cfg_file"; then
        tunnel_mode="server"
    elif grep -q 'mode[[:space:]]*=[[:space:]]*"client"' "$cfg_file"; then
        tunnel_mode="client"
    else
        handle_error "ERROR" "Cannot determine tunnel mode from $cfg_file."
        press_any_key; return 1;
    fi

    log_message "INFO" "Testing connection for $tunnel_mode tunnel defined in $cfg_file"

    if [[ "$tunnel_mode" == "server" ]]; then
        listen_addr=$(grep 'listen[[:space:]]*=' "$cfg_file" | sed 's/.*=[[:space:]]*"\(.*\)"/\1/')
        if [[ "$listen_addr" == :* ]]; then
            target_ip="localhost" # Or 0.0.0.0 if you want to test external reachability to it
            target_port="${listen_addr#:}"
        else
            target_ip=$(echo "$listen_addr" | cut -d':' -f1)
            target_port=$(echo "$listen_addr" | cut -d':' -f2)
        fi
        if [[ -z "$target_ip" || "$target_ip" == "0.0.0.0" ]]; then target_ip="localhost"; fi
        print_info "Server mode: Testing listen address $target_ip on port $target_port..."
    else # client
        remote_addr=$(grep 'server[[:space:]]*=' "$cfg_file" | sed 's/.*=[[:space:]]*"\(.*\)"/\1/')
        target_ip=$(echo "$remote_addr" | cut -d':' -f1)
        target_port=$(echo "$remote_addr" | cut -d':' -f2)
        print_info "Client mode: Testing connection to remote server $target_ip on port $target_port..."
    fi

    if ! validate_ip "$target_ip" || ! validate_port "$target_port"; then
        handle_error "ERROR" "Invalid IP ($target_ip) or Port ($target_port) parsed from config."
        press_any_key; return 1;
    fi
    
    ensure_netcat_installed
    if [[ "${NC_COMPATIBLE:-false}" != "true" ]]; then
         handle_error "WARNING" "Netcat may not be fully compatible. Test result might be unreliable."
    fi

    if run_with_spinner "Testing connectivity to $target_ip:$target_port..." nc -z -w 5 "$target_ip" "$target_port"; then
        handle_success "Successfully connected to $target_ip:$target_port."
    else
        handle_error "ERROR" "Could not connect to $target_ip:$target_port. Check service status, firewall, and configuration."
    fi
    press_any_key
}

_mng_delete_tunnel() {
    local service_name="$1"
    local tunnel_suffix="$2"
    local config_file_path="$3"

    # Header printed by calling menu. This function provides specific prompts.
    print_warning "--- Delete Tunnel: $tunnel_suffix ---"
    print_warning "WARNING: This will PERMANENTLY delete the tunnel and all associated data!"
    echo "This includes:"
    echo "  - Systemd service: $service_name"
    echo "  - TOML Configuration: $config_file_path"
    echo "  - Associated UFW rules (comment: EasyBackhaul: tunnel-${tunnel_suffix})"
    echo "  - Associated watcher scripts, logs, and PID files in $EASYBACKHAUL_TMP_DIR and $LOG_DIR" # Use globals

    if ! prompt_yes_no "Are you ABSOLUTELY SURE you want to delete tunnel '$tunnel_suffix'?" "n"; then
        print_info "Tunnel deletion cancelled."
        press_any_key
        return 1 # Indicate cancellation, stay in specific tunnel menu
    fi
    
    local confirmation_text_expected="DELETE $tunnel_suffix"
    local user_confirmation
    read -r -p "To confirm, type exactly '$confirmation_text_expected': " user_confirmation
    if [[ "$user_confirmation" != "$confirmation_text_expected" ]]; then
        handle_error "ERROR" "Confirmation text did not match. Deletion aborted."
        press_any_key
        return 1 # Indicate cancellation
    fi

    log_message "WARN" "Proceeding with deletion of tunnel: $tunnel_suffix"

    # 1. Stop and disable the service
    if systemctl list-units --full --all --type=service --no-legend "$service_name" | grep -q "$service_name"; then
        run_with_spinner "Stopping service $service_name..." systemctl stop "$service_name"
        run_with_spinner "Disabling service $service_name..." systemctl disable "$service_name"
    else
        log_message "INFO" "Service $service_name not found or already removed."
    fi

    # 2. Remove systemd service file
    local systemd_service_file_path="$SERVICE_DIR/$service_name"
    if [[ -f "$systemd_service_file_path" ]]; then
        if secure_delete "$systemd_service_file_path"; then
            log_message "INFO" "Removed systemd service file: $systemd_service_file_path"
        else
            handle_error "ERROR" "Failed to remove systemd service file: $systemd_service_file_path"
        fi
    fi
    
    run_with_spinner "Reloading systemd daemon..." systemctl daemon-reload

    if [[ -f "$config_file_path" ]]; then
        if secure_delete "$config_file_path"; then
            log_message "INFO" "Removed configuration file: $config_file_path"
        else
            handle_error "ERROR" "Failed to remove configuration file: $config_file_path"
        fi
    fi

    if type delete_ufw_rules_for_tunnel &>/dev/null; then
        delete_ufw_rules_for_tunnel "$tunnel_suffix"
    else
        log_message "WARN" "delete_ufw_rules_for_tunnel function not found. Skipping UFW rule deletion."
    fi

    cleanup_watcher_files "$tunnel_suffix"

    handle_success "Tunnel '$tunnel_suffix' and its associated files/rules have been deleted."
    press_any_key
    return 0 # Indicate successful deletion, return from specific tunnel menu
}

# Decommissioned functions that created standalone scripts for tunnels.
# These are replaced by systemd services directly running the backhaul binary with a config file.
# create_tunnel() { log_message "WARN" "DEPRECATED: create_tunnel function called. Tunnel creation is now part of configure_tunnel."; }
# create_tunnel_impl() { log_message "WARN" "DEPRECATED: create_tunnel_impl function called."; }
# start_tunnel() { log_message "WARN" "DEPRECATED: start_tunnel function called. Use systemctl via _mng_start_tunnel."; }
# start_tunnel_impl() { log_message "WARN" "DEPRECATED: start_tunnel_impl function called."; }
# stop_tunnel() { log_message "WARN" "DEPRECATED: stop_tunnel function called. Use systemctl via _mng_stop_tunnel."; }
# stop_tunnel_impl() { log_message "WARN" "DEPRECATED: stop_tunnel_impl function called."; }

true # Ensure script is valid if sourced.