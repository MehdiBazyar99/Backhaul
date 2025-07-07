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
        # ... (full help text)
        press_any_key
    }

    local health_menu_options=(
        "1. Refresh Health Status"
        "2. Clean Stale Processes & Temp Files"
        "3. View System Logs (e.g., easybackhaul.log, performance.log)"
    )
    # local health_exit_details=("0" "Back to Main Menu") # No longer needed
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
        print_info "--- Active Watcher Processes (Summary) ---" # Corrected from Chinese characters
        if pgrep -f "$EASYBACKHAUL_TMP_DIR/backhaul-watcher-.*\.sh" >/dev/null; then pgrep -af "$EASYBACKHAUL_TMP_DIR/backhaul-watcher-.*\.sh" | sed 's/^/    /'; else print_info "  No active watcher processes found."; fi

        menu_loop "Select action" health_menu_options health_exit_details "_health_monitor_menu_help"
        user_choice="$MENU_CHOICE"; menu_rc=$?

        case "$menu_rc" in
            0) # Numeric or "0"
                case "$user_choice" in
                    "1") continue ;; # Refresh by re-looping
                    "2") run_with_spinner "Cleaning stale processes and files..." cleanup_stale_processes_and_files; press_any_key ;;
                    "3")
                        if [[ -n "$LOG_DIR" ]]; then
                            # This should ideally be a navigable menu if there are multiple logs.
                            # For now, just view one. If view_system_log becomes a menu, use navigate_to_menu.
                            view_system_log "file" "$LOG_DIR/easybackhaul.log" "EasyBackhaul Main Log"
                        else
                            handle_error "WARNING" "LOG_DIR not defined."
                            press_any_key
                        fi
                        ;;
                    "0") return_from_menu; return 0 ;; # Back to Main Menu
                    *) print_warning "Invalid option."; press_any_key ;;
                esac
                ;;
            1) print_warning "Invalid selection."; press_any_key ;;
            2) continue ;; # Help shown
            3) go_to_main_menu; return 0 ;;
            4) request_script_exit; return 0 ;;
            5) return_from_menu; return 0 ;; # 'r' (Back) is same as "0" here
            *) print_warning "Unexpected menu_loop return."; press_any_key ;;
        esac
    done
}

_perform_full_uninstall() {
    print_menu_header "primary" "Uninstall EasyBackhaul" "Irreversible Action"
    print_warning "WARNING: This will PERMANENTLY REMOVE EasyBackhaul and ALL related data!"
    echo "This includes:"
    echo "  - The Backhaul binary ($BIN_PATH)"
    echo "  - All tunnel configurations ($CONFIG_DIR)"
    echo "  - All systemd services (e.g., backhaul-*.service in $SERVICE_DIR)"
    echo "  - All UFW rules managed by EasyBackhaul (if UFW is used)"
    echo "  - All EasyBackhaul-managed cron jobs."
    echo "  - Temporary files and watcher scripts (typically in $EASYBACKHAUL_TMP_DIR or /tmp)"
    echo "  - Backup files ($BACKUP_DIR)"
    echo "  - Potentially log files ($LOG_DIR) - you will be asked about this."
    
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
                suffix_to_clean=${service_name#backhaul-} # bh-server-tcp-xxxx.service
                suffix_to_clean=${suffix_to_clean%.service} # bh-server-tcp-xxxx
                 # Also clean up watcher files for this main tunnel suffix
                cleanup_watcher_files "$suffix_to_clean" "true" # Quietly
            elif [[ "$service_name" == backhaul-watcher-*.service ]]; then
                suffix_to_clean=${service_name#backhaul-watcher-} # server-tcp-xxxx.service (example)
                suffix_to_clean=${suffix_to_clean%.service} # server-tcp-xxxx
                cleanup_watcher_files "$suffix_to_clean" "true" # Quietly
            fi
        done
    else
        print_info "No 'backhaul-bh-*.service' or 'backhaul-watcher-*.service' services found."
    fi
    
    log_message "INFO" "Performing general watcher file cleanup from $EASYBACKHAUL_TMP_DIR (and /tmp for legacy)..."
    find "${EASYBACKHAUL_TMP_DIR:-/tmp}" -maxdepth 1 \( -name 'backhaul-watcher-*' -o -name 'restart_ack_*' \) -print -exec rm -rf {} \; &>/dev/null
    # Legacy /tmp cleanup if EASYBACKHAUL_TMP_DIR is different and not /tmp
    if [[ -n "$EASYBACKHAUL_TMP_DIR" && "$EASYBACKHAUL_TMP_DIR" != "/tmp" ]]; then
        find "/tmp" -maxdepth 1 \( -name 'backhaul-watcher-*' -o -name 'restart_ack_*' \) -print -exec rm -rf {} \; &>/dev/null
    fi

    print_info "Removing systemd service files..."
    if [[ -d "$SERVICE_DIR" ]]; then
        secure_delete "${SERVICE_DIR}/backhaul-bh-*.service"
        secure_delete "${SERVICE_DIR}/backhaul-watcher-*.service" # Remove watcher services too
        # General cleanup for any other backhaul service that might have been missed.
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
    if [[ -n "$CONFIG_DIR" && -d "$CONFIG_DIR" ]]; then secure_delete "$CONFIG_DIR"; fi
    if [[ -n "$BACKUP_DIR" && -d "$BACKUP_DIR" ]]; then secure_delete "$BACKUP_DIR"; fi
    # Remove EASYBACKHAUL_TMP_DIR if it was set and is a directory
    if [[ -n "$EASYBACKHAUL_TMP_DIR" && -d "$EASYBACKHAUL_TMP_DIR" && "$EASYBACKHAUL_TMP_DIR" != "/tmp" ]]; then
        secure_delete "$EASYBACKHAUL_TMP_DIR"
    fi


    if [[ -n "$LOG_DIR" && -d "$LOG_DIR" ]]; then
        if prompt_yes_no "Also delete the main log directory $LOG_DIR and its contents?" "n"; then
            secure_delete "$LOG_DIR"
            handle_success "Log directory $LOG_DIR deleted."
        else
            print_info "Log directory $LOG_DIR preserved."
        fi
    fi
    
    handle_success "EasyBackhaul uninstallation completed."
    print_info "Some manual cleanup of system logs (journalctl) might be desired."
    print_info "Exiting now."
    exit 0 # Successful exit after uninstallation
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
    # local main_exit_details=("0" "Exit EasyBackhaul") # No longer needed
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
    user_choice="$MENU_CHOICE"; menu_rc=$?
    
    case "$menu_rc" in
        0) # Numeric choice
            case "$user_choice" in
                "1") navigate_to_menu "configure_tunnel" ;;
                "2") navigate_to_menu "manage_tunnels_menu" ;;
                "3")
                    if download_backhaul_binary_workflow; then
                        handle_success "Backhaul binary update/re-install process completed."
                    else
                        handle_error "WARNING" "Backhaul binary update/re-install was cancelled or failed."
                    fi
                    press_any_key
                    ;;
                "4")
                    if generate_self_signed_tls_cert; then
                        handle_success "TLS certificate generation process completed."
                    else
                        handle_error "WARNING" "TLS certificate generation was cancelled or failed."
                    fi
                    press_any_key
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
                    # If _perform_full_uninstall is cancelled, it returns 1.
                    # If it completes, it exits the script.
                    # If it returns 1, we want to re-display the main menu.
                    if [[ $? -eq 1 ]]; then main_menu_entry; return 0; fi
                    ;;
                 *) print_warning "Invalid selection from main_menu_entry: $user_choice"; press_any_key ;;
            esac
            ;;
        2) # '?' Help shown
            return 0 ;; # Re-render main menu
        3) # 'm' Main Menu - effectively a refresh
            go_to_main_menu; return 0 ;;
        4) # 'x' Exit script
            request_script_exit; return 0 ;;
        5) # 'r' Return/Back from main menu also means exit
            request_script_exit; return 0 ;;
        6) # 'c' Cancel from main menu also means exit
            request_script_exit; return 0;;
        *)
            print_warning "Unexpected menu_loop return in main_menu_entry: $menu_rc, choice: $user_choice"
            press_any_key ;;
    esac
    return 0 # Allow the main script loop to call this function again if not exited
}

main_script_entry_point() {
# --- Global Ctrl+C Handler ---
_global_ctrl_c_handler() {
    print_error "\n\nCtrl+C pressed. Exiting EasyBackhaul script."
    log_message "WARN" "Ctrl+C interrupt received. Exiting script."
    # Perform any essential cleanup if needed here, though individual functions might have their own.
    # For a clean exit via the menu system's exit path:
    if type request_script_exit &>/dev/null; then
        request_script_exit # This will clear MENU_STACK and CURRENT_MENU_FUNCTION
    fi
    # The main loop in main_script_entry_point will then terminate.
    # Directly exiting here might bypass some cleanup or final messages from main loop.
    # However, for an explicit Ctrl+C, immediate clean exit is often desired.
    # Let's ensure the main loop's exit condition is met.
    # Setting CURRENT_MENU_FUNCTION to empty should be sufficient if request_script_exit was called.
    exit 130 # Standard exit code for Ctrl+C
}

main_script_entry_point() {
    # Initialize logging as the very first step
    if type init_logging &>/dev/null; then
        init_logging # Sets up LOG_FILE, EASYBACKHAUL_TMP_DIR etc.
    else
        echo "FATAL ERROR: init_logging function not found. Cannot proceed." >&2
        exit 1
    fi

    # Global Ctrl+C trap
    trap '_global_ctrl_c_handler' INT

    log_message "INFO" "EasyBackhaul script started."

    # Default global variables (some might be overridden by init_logging or user config later)
    # These are fallbacks if not set by init_logging from a config file or defaults.
    : "${CONFIG_DIR:=$EASYBACKHAUL_APP_DIR/config}"
    : "${BACKUP_DIR:=$EASYBACKHAUL_APP_DIR/backup}"
    : "${BIN_PATH:=$EASYBACKHAUL_APP_DIR/bin/easybackhaul_binary}"
    : "${SERVICE_DIR:=/etc/systemd/system}" # Standard systemd location
    # LOG_DIR, LOG_LEVEL, LOG_FORMAT should be definitively set by init_logging
    : "${CRON_COMMENT_TAG:=EasyBackhaul}"
    # HEALTH_LOG_FILE and PERFORMANCE_LOG_FILE path depends on LOG_DIR
    : "${HEALTH_LOG_FILE:=${LOG_DIR:-/var/log/easybackhaul}/easybackhaul_health.log}"
    : "${PERFORMANCE_LOG_FILE:=${LOG_DIR:-/var/log/easybackhaul}/easybackhaul_performance.log}"

    # Ensure critical directories exist after globals are established
    # This needs to happen after init_logging which sets EASYBACKHAUL_APP_DIR
    # and potentially custom CONFIG_DIR, LOG_DIR.
    ensure_dir_wrapper() {
        local dir_path="$1"
        local permissions="${2:-700}" # Default permissions
        if [[ -z "$dir_path" ]]; then
            log_message "WARN" "ensure_dir_wrapper: Directory path is empty. Skipping."
            return
        fi
        if type ensure_dir &>/dev/null; then
            ensure_dir "$dir_path" "$permissions"
        else
            # Basic fallback if ensure_dir is missing (should not happen if helpers are sourced)
            mkdir -p "$dir_path" && chmod "$permissions" "$dir_path"
            log_message "WARN" "ensure_dir function not found. Used basic mkdir -p."
        fi
    }
    
    ensure_dir_wrapper "$EASYBACKHAUL_APP_DIR" "755" # Main app dir
    ensure_dir_wrapper "$(dirname "$BIN_PATH")" "755" # Binary directory
    ensure_dir_wrapper "$CONFIG_DIR" "700"
    ensure_dir_wrapper "$BACKUP_DIR" "700"
    ensure_dir_wrapper "$LOG_DIR" "700" # Log directory

    if [[ $EUID -ne 0 ]]; then handle_critical_error "This script must be run as root or with sudo."; fi # Exits
    
    if type check_dependencies &>/dev/null; then check_dependencies; # Exits on critical missing deps
    else handle_critical_error "check_dependencies function not found."; fi

    if type get_server_info &>/dev/null; then get_server_info; else log_message "WARN" "get_server_info not found."; fi

    # Binary installation check
    if [[ ! -f "$BIN_PATH" ]] || ! verify_binary_installation "quiet"; then
        log_message "WARN" "Backhaul binary not found or failed verification at $BIN_PATH. Starting installation wizard."
        # _initial_installation_wizard returns 0 on success, 1 on failure/cancel
        if ! _initial_installation_wizard; then
            # Check again, as user might have cancelled but binary exists from previous attempt
            if [[ ! -f "$BIN_PATH" ]] || ! verify_binary_installation "quiet"; then
                 handle_critical_error "Backhaul binary installation was not completed or is invalid. Exiting."
            else
                 log_message "INFO" "Binary found and verified after wizard exit. Proceeding."
            fi
        fi
    fi

    # Initialize menu navigation stack
    CURRENT_MENU_FUNCTION="main_menu_entry"
    MENU_STACK=("main_menu_entry") # Stack of menu function names

    log_message "DEBUG" "Menu system initialized. Starting main loop for $CURRENT_MENU_FUNCTION"

    # Main menu loop
    while [[ -n "$CURRENT_MENU_FUNCTION" ]]; do
        log_message "DEBUG" "Main loop - Current Menu: $CURRENT_MENU_FUNCTION, Stack: [${MENU_STACK[*]}]"
        if type "$CURRENT_MENU_FUNCTION" &>/dev/null; then
            "$CURRENT_MENU_FUNCTION" # Execute the current menu function
        else
            handle_critical_error "Menu function '$CURRENT_MENU_FUNCTION' not found. Stack: [${MENU_STACK[*]}]."
        fi

        # After a menu function returns, CURRENT_MENU_FUNCTION might have been changed by navigation functions
        # If MENU_STACK is empty, it means request_script_exit or similar was called.
        if [[ ${#MENU_STACK[@]} -eq 0 ]]; then
            log_message "DEBUG" "Menu stack is empty. Exiting main loop."
            CURRENT_MENU_FUNCTION="" # Ensure loop terminates
        fi
        # If CURRENT_MENU_FUNCTION was set by navigate_to_menu, loop continues with new function.
        # If it was cleared by return_from_menu and stack became empty, loop terminates.
        # If it was cleared by return_from_menu and stack is not empty, CURRENT_MENU_FUNCTION is already set to top of stack.
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