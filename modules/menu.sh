# modules/menu.sh
# Main menu logic, script entry point, installation wizard, and uninstallation.

# --- Installation Wizard ---
# This function guides the user through installing the Backhaul binary.
# It now directly calls 'download_backhaul_binary_workflow'.
_initial_installation_wizard() {
    print_menu_header "primary" "EasyBackhaul Initial Setup" "Backhaul Binary Installation Required"
    print_warning "The Backhaul binary is not found or is invalid at the configured path: $BIN_PATH"
    print_info "The following workflow will guide you through the installation."
    press_any_key

    # Directly call the consolidated workflow function from backhaul_core.sh
    # download_backhaul_binary_workflow will handle its own menu and logic.
    # It returns 0 on success (binary installed and verified), 1 on failure/cancellation.
    if download_backhaul_binary_workflow; then
        # verify_binary_installation is called within install_downloaded_binary,
        # which is called by the helpers in download_backhaul_binary_workflow.
        # So, if download_backhaul_binary_workflow returns 0, it implies success.
        handle_success "Backhaul binary installed and verified successfully!"
        press_any_key
        return 0 # Successful installation
    else
        handle_error "ERROR" "Backhaul binary installation was cancelled or failed."
        print_warning "EasyBackhaul may not function correctly without the binary."
        press_any_key
        return 1 # Indicate failure/cancellation of initial setup step
    fi
}

system_health_monitor_menu() {
    _health_monitor_menu_help() {
        print_menu_header "secondary" "System Health Monitor Help" "System Overview"
        echo "This screen provides an overview of system resources, tunnel health, and performance."
        echo "Options:"
        echo "  1. Refresh: Reloads all the displayed health information."
        echo "  2. Clean Stale Processes & Temp Files: Attempts to remove known temporary files or orphaned processes."
        echo "  3. View System Logs: Access logs like easybackhaul.log or performance.log."
        press_any_key
    }

    local health_menu_options=(
        "1. Refresh Health Status"
        "2. Clean Stale Processes & Temp Files"
        "3. View System Logs (e.g., easybackhaul.log, performance.log)"
    )
    local user_choice menu_rc

    while true; do
        print_menu_header "primary" "System Health & Performance Monitor" "Overview"
        display_system_resources; echo
        print_info "--- Tunnel Health Status ---"
        mapfile -t tunnel_config_files < <(find "$CONFIG_DIR" -maxdepth 1 -name "config-bh-*.toml" -type f 2>/dev/null | sort)
        if [[ ${#tunnel_config_files[@]} -eq 0 ]]; then print_warning "  No tunnels configured."; else
            local healthy_tunnels=0
            for cfg_file in "${tunnel_config_files[@]}"; do
                local suffix status_color status_text service
                suffix=$(basename "$cfg_file" .toml | sed 's/^config-//'); service="backhaul-${suffix}.service"
                if systemctl is-active --quiet "$service" 2>/dev/null; then status_text="Running"; status_color="$COLOR_GREEN"; ((healthy_tunnels++));
                elif systemctl is-failed --quiet "$service" 2>/dev/null; then status_text="Failed"; status_color="$COLOR_RED";
                else status_text="Stopped/Inactive"; status_color="$COLOR_YELLOW"; fi
                echo -e "  Tunnel: $suffix - Status: ${status_color}${status_text}${COLOR_RESET}"; done
            print_info "  Summary: $healthy_tunnels / ${#tunnel_config_files[@]} tunnels appear healthy."; fi; echo
        print_info "--- Recent Performance Log ---"
        if [[ -n "$PERFORMANCE_LOG_FILE" && -f "$PERFORMANCE_LOG_FILE" ]]; then tail -n 5 "$PERFORMANCE_LOG_FILE" | sed 's/^/    /' || print_warning "  Could not read performance log."; else print_warning "  Performance log file not configured or not found."; fi; echo
        print_info "--- Active Watcher Processes (Summary) ---"
        if pgrep -f "${EASYBACKHAUL_TMP_DIR:-/tmp}/backhaul-watcher-.*\.sh" >/dev/null; then pgrep -af "${EASYBACKHAUL_TMP_DIR:-/tmp}/backhaul-watcher-.*\.sh" | sed 's/^/    /'; else print_info "  No active watcher processes found."; fi

        menu_loop "Select action" health_menu_options "_health_monitor_menu_help"
        local menu_rc=$?
        local user_choice="$MENU_CHOICE" # Capture MENU_CHOICE after $? is captured

        case "$menu_rc" in
            0) # Numeric choice
                case "$user_choice" in
                    "1") continue ;; # Refresh by re-looping
                    "2") run_with_spinner "Cleaning stale processes and files..." cleanup_stale_processes_and_files; press_any_key ;;
                    "3")
                        if [[ -n "$LOG_DIR" ]]; then
                            # navigate_to_menu will push to stack, then current function returns 0
                            # main loop will pick up the new function from stack.
                            navigate_to_menu "view_system_log \"file\" \"$LOG_DIR/easybackhaul.log\" \"EasyBackhaul Main Log\""
                            return 0 # Return to main script loop to process navigation
                        else
                            handle_error "WARNING" "LOG_DIR not defined."
                            press_any_key
                        fi
                        ;;
                    *) print_warning "Invalid option: $user_choice"; press_any_key ;;
                esac
                ;;
            2) # '?' Help
                # Help function already called by menu_loop. Loop again to show menu.
                continue ;;
            3) # 'm' Main Menu
                go_to_main_menu
                return 0 ;; # Return to main script loop
            4) # 'x' Exit script
                request_script_exit
                return 0 ;; # Return to main script loop
            5) # 'r' Return/Back/Cancel (to previous menu, likely main menu)
                return_from_menu
                return 0 ;; # Return to main script loop
            6) # Invalid input in menu_loop (warning already printed by menu_loop)
                # press_any_key was already handled by menu_loop before returning 6.
                # Loop again to show the health monitor menu.
                continue ;;
            *)
                print_warning "Unexpected menu_loop return code in system_health_monitor_menu: $menu_rc (Choice: $user_choice)"
                press_any_key
                continue ;; # Re-draw menu on unexpected code
        esac
    done
}

_perform_full_uninstall() {
    print_menu_header "primary" "Uninstall EasyBackhaul" "Irreversible Action"
    print_warning "WARNING: This will PERMANENTLY REMOVE EasyBackhaul and ALL related data!"
    echo "This includes:"
    echo "  - The Backhaul binary ($BIN_PATH)"
    echo "  - All tunnel configurations (from $CONFIG_DIR, likely /etc/easybackhaul/configs)"
    echo "  - The main configuration directory structure (e.g., /etc/easybackhaul)"
    echo "  - All systemd services (e.g., backhaul-*.service in $SERVICE_DIR)"
    echo "  - All UFW rules managed by EasyBackhaul (if UFW is used)"
    echo "  - All EasyBackhaul-managed cron jobs."
    echo "  - Temporary files and watcher scripts (typically in ${EASYBACKHAUL_TMP_DIR:-/tmp})"
    echo "  - Backup files ($BACKUP_DIR)"
    echo "  - Log files and directory (from $LOG_DIR, likely /var/log/easybackhaul) - you will be asked about this."
    echo "  - Logrotate configuration (/etc/logrotate.d/easybackhaul)"
    
    if ! prompt_yes_no "Are you absolutely sure you want to proceed with uninstallation?" "n"; then
        print_info "Uninstallation cancelled."; press_any_key; return 1; fi
    
    local confirm_uninstall_text="UNINSTALL EASYBACKHAUL NOW"
    local user_confirmation
    read -r -p "To confirm, type '$confirm_uninstall_text': " user_confirmation
    if [[ "$user_confirmation" != "$confirm_uninstall_text" ]]; then
        handle_error "ERROR" "Confirmation text did not match. Uninstallation aborted."; press_any_key; return 1; fi
    
    log_message "WARN" "Starting full uninstallation of EasyBackhaul..."
    
    print_info "Stopping and disabling all Backhaul services..."
    mapfile -t service_files < <(systemctl list-unit-files --type=service "backhaul-bh-*.service" "backhaul-watcher-*.service" --no-legend --full --all | awk '{print $1}')
    if [[ ${#service_files[@]} -gt 0 ]]; then
        for service_name in "${service_files[@]}"; do
            run_with_spinner "Stopping $service_name..." systemctl stop "$service_name"
            run_with_spinner "Disabling $service_name..." systemctl disable "$service_name"
            local suffix_to_clean
            if [[ "$service_name" == backhaul-bh-*.service ]]; then
                suffix_to_clean=${service_name#backhaul-}
                suffix_to_clean=${suffix_to_clean%.service}
                cleanup_watcher_files "$suffix_to_clean" "true"
            elif [[ "$service_name" == backhaul-watcher-*.service ]]; then
                suffix_to_clean=${service_name#backhaul-watcher-}
                suffix_to_clean=${suffix_to_clean%.service}
                cleanup_watcher_files "$suffix_to_clean" "true"
            fi
        done
    else
        print_info "No 'backhaul-bh-*.service' or 'backhaul-watcher-*.service' services found."
    fi
    
    log_message "INFO" "Performing general watcher file cleanup from ${EASYBACKHAUL_TMP_DIR:-/tmp}..."
    find "${EASYBACKHAUL_TMP_DIR:-/tmp}" -maxdepth 1 \( -name 'backhaul-watcher-*' -o -name 'restart_ack_*' \) -print -exec rm -rf {} \; &>/dev/null
    if [[ -n "$EASYBACKHAUL_TMP_DIR" && "$EASYBACKHAUL_TMP_DIR" != "/tmp" && "$EASYBACKHAUL_TMP_DIR" != "/tmp/" ]]; then # Check if it's a different dir
        find "/tmp" -maxdepth 1 \( -name 'backhaul-watcher-*' -o -name 'restart_ack_*' \) -print -exec rm -rf {} \; &>/dev/null
    fi

    print_info "Removing systemd service files..."
    if [[ -d "$SERVICE_DIR" ]]; then
        secure_delete "${SERVICE_DIR}/backhaul-bh-*.service"
        secure_delete "${SERVICE_DIR}/backhaul-watcher-*.service"
        secure_delete "${SERVICE_DIR}/backhaul-*.service"
    fi
    run_with_spinner "Reloading systemd daemon..." systemctl daemon-reload
    
    print_info "Removing UFW rules..."
    if type delete_all_easybackhaul_ufw_rules &>/dev/null; then
        delete_all_easybackhaul_ufw_rules
    else
        log_message "WARN" "'delete_all_easybackhaul_ufw_rules' not found. Attempting pattern based deletion."
        mapfile -t ufw_rules_to_delete < <(ufw status numbered 2>/dev/null | grep -iE "EasyBackhaul:|Backhaul-" | awk -F'[][]' '{print $2}' | sort -nr)
        if [[ ${#ufw_rules_to_delete[@]} -gt 0 ]]; then
            print_info "Found ${#ufw_rules_to_delete[@]} UFW rules to delete..."
            for rule_num in "${ufw_rules_to_delete[@]}"; do
                run_with_spinner "Deleting UFW rule #$rule_num..." sh -c "echo y | ufw delete $rule_num"
            done
            run_with_spinner "Reloading UFW..." ufw reload
        else
            print_info "No specific EasyBackhaul UFW rules found by common patterns."
        fi
    fi
    
    print_info "Removing EasyBackhaul cron jobs..."
    if command -v crontab &>/dev/null && [[ -n "$CRON_COMMENT_TAG" ]]; then
        (crontab -l 2>/dev/null | grep -vF "# $CRON_COMMENT_TAG") | crontab -
        log_message "INFO" "Removed cron jobs tagged with '$CRON_COMMENT_TAG'."
    else
        log_message "WARN" "Cannot remove cron jobs (crontab not found or CRON_COMMENT_TAG empty)."
    fi
    
    print_info "Removing files and directories..."
    if [[ -n "$BIN_PATH" && -f "$BIN_PATH" ]]; then secure_delete "$BIN_PATH"; fi
    # CONFIG_DIR is now /etc/easybackhaul/configs. Remove its parent /etc/easybackhaul as well.
    if [[ -n "$CONFIG_DIR" && -d "$(dirname "$CONFIG_DIR")" ]]; then # Check parent dir
        secure_delete "$(dirname "$CONFIG_DIR")" # This removes /etc/easybackhaul (and configs within)
        log_message "INFO" "Removed main config directory structure: $(dirname "$CONFIG_DIR")"
    elif [[ -n "$CONFIG_DIR" && -d "$CONFIG_DIR" ]]; then # Fallback if parent wasn't as expected
         secure_delete "$CONFIG_DIR"
         log_message "INFO" "Removed config directory: $CONFIG_DIR"
    fi

    if [[ -n "$BACKUP_DIR" && -d "$BACKUP_DIR" ]]; then secure_delete "$BACKUP_DIR"; fi
    if [[ -n "$EASYBACKHAUL_TMP_DIR" && -d "$EASYBACKHAUL_TMP_DIR" && "$EASYBACKHAUL_TMP_DIR" != "/tmp" && "$EASYBACKHAUL_TMP_DIR" != "/tmp/" ]]; then
        secure_delete "$EASYBACKHAUL_TMP_DIR"
    fi

    # Remove logrotate configuration
    local logrotate_conf_file="/etc/logrotate.d/easybackhaul"
    if [[ -f "$logrotate_conf_file" ]]; then
        secure_delete "$logrotate_conf_file"
        log_message "INFO" "Removed logrotate configuration file: $logrotate_conf_file"
    fi

    # LOG_DIR is now /var/log/easybackhaul
    if [[ -n "$LOG_DIR" && -d "$LOG_DIR" ]]; then
        if prompt_yes_no "Also delete the main log directory ($LOG_DIR) and all its contents?" "n"; then
            secure_delete "$LOG_DIR"
            handle_success "Log directory $LOG_DIR deleted."
        else
            print_info "Log directory $LOG_DIR preserved."
        fi
    fi
    
    handle_success "EasyBackhaul uninstallation completed."
    print_info "Some manual cleanup of system logs (journalctl) might be desired if services were problematic."
    print_info "Exiting now."
    exit 0
}

# --- Global Ctrl+C Handler ---
_global_ctrl_c_handler() {
    print_error "\n\nCtrl+C pressed. Exiting EasyBackhaul script."
    log_message "WARN" "Ctrl+C interrupt received. Exiting script."
    if type request_script_exit &>/dev/null; then
        request_script_exit
    fi
    exit 130
}

main_menu_entry() {
    local binary_status_msg="Binary Status: "
    if [[ -f "$BIN_PATH" ]]; then
        if [[ ! -x "$BIN_PATH" ]]; then binary_status_msg+="${COLOR_YELLOW}Found but NOT EXECUTABLE${COLOR_RESET} at $BIN_PATH"
        else
            local version_info; version_info=$("$BIN_PATH" --version 2>/dev/null || "$BIN_PATH" -v 2>/dev/null | head -n1)
            if [[ -n "$version_info" ]]; then binary_status_msg+="${COLOR_GREEN}OK ($version_info)${COLOR_RESET}"
            else binary_status_msg+="${COLOR_GREEN}OK (Version unknown)${COLOR_RESET}"; fi
        fi
    else binary_status_msg+="${COLOR_RED}NOT INSTALLED${COLOR_RESET} (Expected: $BIN_PATH)"; fi
    
    print_menu_header "primary" "EasyBackhaul Management Menu" "$binary_status_msg"
    
    local main_menu_options=(
        "1. Configure a New Tunnel"
        "2. Manage Existing Tunnels"
        "3. Update/Re-install Backhaul Binary"
        "4. Generate Self-Signed TLS Certificate"
        "5. System Health & Performance Monitor"
        "6. Clean Stale Processes & Temp Files"
        "7. Manage UFW Firewall (if installed)"
        "8. Uninstall EasyBackhaul"
    )
    local user_choice menu_rc

    local help_func_name="show_main_application_help"
    if ! type "$help_func_name" &>/dev/null; then
        _generic_main_menu_help() {
            print_menu_header "secondary" "Main Menu Help"
            echo "This is the main control panel for EasyBackhaul."
            echo "Use the number keys to select an option from the menu."
            echo "Follow prompts for each section."
            echo "The footer shows navigation keys: [?] Help | [c] Cancel Op | [r] Return/Back | [m] Main Menu | [x] Exit Script."
            press_any_key
        }
        help_func_name="_generic_main_menu_help"
    fi

    menu_loop "Select option" main_menu_options "$help_func_name"
    local menu_rc=$?
    local user_choice="$MENU_CHOICE" # Capture MENU_CHOICE after $? is captured
    
    case "$menu_rc" in
        0) # Numeric choice
            case "$user_choice" in
                "1") navigate_to_menu "configure_tunnel" ;;
                "2") navigate_to_menu "manage_tunnels_menu" ;;
                "3")
                    # download_backhaul_binary_workflow handles its own user feedback and press_any_key.
                    # It returns 0 for actual install success, 1 for failure/cancel,
                    # and will be updated to return 2 if only diagnostics were run then cancelled.
                    local workflow_rc
                    download_backhaul_binary_workflow
                    workflow_rc=$?
                    if [[ "$workflow_rc" -eq 0 ]]; then
                        # Optionally, a very brief confirmation here if needed, but primary feedback is in workflow.
                        log_message "INFO" "Backhaul binary workflow completed successfully (main_menu_entry)."
                    elif [[ "$workflow_rc" -eq 1 ]]; then
                        log_message "WARN" "Backhaul binary workflow cancelled or failed (main_menu_entry)."
                    # else # e.g. rc=2, diagnostics run then cancelled - no specific message here needed yet
                    fi
                    # No generic handle_success/error or press_any_key here.
                    ;;
                "4")
                    # generate_self_signed_tls_cert handles its own user feedback and press_any_key.
                    generate_self_signed_tls_cert
                    # No generic handle_success/error or press_any_key here.
                    ;;
                "5") navigate_to_menu "system_health_monitor_menu" ;;
                "6") run_with_spinner "Cleaning stale processes and temporary files..." cleanup_stale_processes_and_files; press_any_key ;;
                "7")
                    if command -v ufw &>/dev/null; then
                        navigate_to_menu "manage_ufw_main_menu"
                    else
                        handle_error "WARNING" "UFW is not installed or not found in PATH."
                        press_any_key
                    fi
                    ;;
                "8")
                    _perform_full_uninstall
                    # If uninstallation was cancelled (returns 1), we want to stay in the main menu loop.
                    # main_menu_entry will be called again by the main script loop.
                    if [[ $? -eq 1 ]]; then return 0; fi
                    # If uninstallation happened (returns 0), script exits, so this path isn't critical.
                    ;;
                 *) print_warning "Invalid selection from main_menu_entry: $user_choice"; press_any_key ;;
            esac
            ;;
        2) # '?' Help
            # Help function was already called by menu_loop.
            # Loop again to show the main menu.
            return 0 ;;
        3) # 'm' Main Menu
            # Already in main menu, so just re-display.
            return 0 ;;
        4) # 'x' Exit Script
            request_script_exit
            return 0 ;;
        5) # 'r' Return/Back/Cancel
            # In main menu, 'r' acts as 'x' (exit).
            request_script_exit
            return 0 ;;
        6)  # Invalid input from menu_loop (warning and press_any_key already done by menu_loop)
            # Just need to ensure main_menu_entry is re-displayed.
            return 0 ;; # Fall through to the end of function's return 0 is fine.
        *)
            print_warning "Unexpected menu_loop return code in main_menu_entry: $menu_rc (Choice: $user_choice)"
            press_any_key ;; # Fall through to the end of function's return 0.
    esac
    return 0
}

main_script_entry_point() {
    # Initialize logging as the very first step
    if type init_logging &>/dev/null; then
        init_logging
    else
        echo "FATAL ERROR: init_logging function not found. Cannot proceed." >&2
        exit 1
    fi

    # Set up a global trap for Ctrl+C
    trap '_global_ctrl_c_handler' INT

    log_message "INFO" "EasyBackhaul script started."

    # --- Variable Definitions ---
    # Define the base application directory. Default to /usr/local/share/easybackhaul if not set.
    # This is a more appropriate default location for shared application data.
    : "${EASYBACKHAUL_APP_DIR:=/usr/local/share/easybackhaul}"

    # All other paths are derived from globals.sh defaults, which are now set early.
    # The : a=b syntax is a fallback, but globals.sh should have already set these.
    # We ensure they are not empty.
    : "${CONFIG_DIR:?CONFIG_DIR not set by globals.sh}"
    : "${BACKUP_DIR:?BACKUP_DIR not set by globals.sh}"
    : "${BIN_PATH:?BIN_PATH not set by globals.sh}"
    : "${LOG_DIR:?LOG_DIR not set by globals.sh}"
    : "${SERVICE_DIR:=/etc/systemd/system}" # This one is standard system path
    : "${CRON_COMMENT_TAG:=EasyBackhaul}"   # This is a script constant

    # --- Directory and Permission Setup ---
    # This wrapper is a temporary solution for ensuring directories exist.
    # It will be removed once the logic is fully integrated into init_logging and other setup functions.
    ensure_dir_wrapper() {
        local dir_path="$1"
        local permissions="${2:-750}" # Default to 750
        if [[ -z "$dir_path" ]]; then
            log_message "WARN" "ensure_dir_wrapper: Directory path is empty. Skipping."
            return
        fi

        # Use the robust ensure_dir from helpers.sh if available
        if type ensure_dir &>/dev/null; then
            ensure_dir "$dir_path" "$permissions"
        else
            # Fallback for unexpected cases where helpers.sh might not be sourced
            mkdir -p "$dir_path" && chmod "$permissions" "$dir_path"
            log_message "WARN" "ensure_dir function not found. Used basic mkdir -p."
        fi
    }

    # With variables now properly defined, create the necessary directories.
    # These calls are now safe from the "Directory path is empty" warning.
    ensure_dir_wrapper "$(dirname "$BIN_PATH")" "755"
    # Config, Backup, and Log directories are handled by their respective setup functions
    # (e.g., _globals_ensure_config_dir_for_secret, init_logging).
    # Explicit calls here can be removed if those functions are guaranteed to run first.
    # For safety during refactoring, we can leave them.
    ensure_dir_wrapper "$CONFIG_DIR" # Uses default 750
    ensure_dir_wrapper "$BACKUP_DIR" "700"
    ensure_dir_wrapper "$LOG_DIR"    # Uses default 750, init_logging will refine permissions

    # --- Prerequisite Checks ---
    if [[ $EUID -ne 0 ]]; then handle_critical_error "This script must be run as root or with sudo."; fi
    
    if type check_dependencies &>/dev/null; then check_dependencies;
    else handle_critical_error "check_dependencies function not found."; fi

    if type get_server_info &>/dev/null; then get_server_info; else log_message "WARN" "get_server_info not found."; fi

    if [[ ! -f "$BIN_PATH" ]] || ! verify_binary_installation "quiet"; then
        log_message "WARN" "Backhaul binary not found or failed verification at $BIN_PATH. Starting installation wizard."
        if ! _initial_installation_wizard; then
            if [[ ! -f "$BIN_PATH" ]] || ! verify_binary_installation "quiet"; then
                 handle_critical_error "Backhaul binary installation was not completed or is invalid. Exiting."
            else
                 log_message "INFO" "Binary found and verified after wizard exit. Proceeding."
            fi
        fi
    fi

    CURRENT_MENU_FUNCTION="main_menu_entry"
    MENU_STACK=("main_menu_entry")

    log_message "DEBUG" "Menu system initialized. Starting main loop for $CURRENT_MENU_FUNCTION"

    while [[ -n "$CURRENT_MENU_FUNCTION" ]]; do
        log_message "DEBUG" "Main loop - Current Menu: $CURRENT_MENU_FUNCTION, Stack: [${MENU_STACK[*]}]"

        local func_name_to_check
        # Extract the first word as the function name for 'type' command
        read -r func_name_to_check _ <<< "$CURRENT_MENU_FUNCTION"

        if type "$func_name_to_check" &>/dev/null; then
            eval "$CURRENT_MENU_FUNCTION" # Use eval to correctly parse function and its arguments
        else
            handle_critical_error "Menu function '$func_name_to_check' (from command string '$CURRENT_MENU_FUNCTION') not found. Stack: [${MENU_STACK[*]}]."
        fi

        if [[ ${#MENU_STACK[@]} -eq 0 ]]; then
            log_message "DEBUG" "Menu stack is empty. Exiting main loop."
            CURRENT_MENU_FUNCTION=""
        fi
    done

    log_message "INFO" "EasyBackhaul script finished."
    if type print_info &>/dev/null; then
        print_info "Exiting EasyBackhaul."
    else
        echo "Exiting EasyBackhaul."
    fi
}

true # Ensure script is valid if sourced

# <<< START OF SCRIPT EXECUTION >>>
# This call should be the very last thing in the concatenated easybh.sh
# Ensure all necessary files are sourced before this point by build.sh
main_script_entry_point