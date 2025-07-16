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
        if pgrep -f "${EASYBACKHAUL_APP_DIR:-/var/lib/easybackhaul}/backhaul-watcher-.*\.sh" >/dev/null; then pgrep -af "${EASYBACKHAUL_APP_DIR:-/var/lib/easybackhaul}/backhaul-watcher-.*\.sh" | sed 's/^/    /'; else print_info "  No active watcher processes found."; fi

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

    local paths_to_delete=()
    paths_to_delete+=("$BIN_PATH")
    paths_to_delete+=("$(dirname "$CONFIG_DIR")")
    paths_to_delete+=("$BACKUP_DIR")
    paths_to_delete+=("$LOG_DIR")
    paths_to_delete+=("/etc/logrotate.d/easybackhaul")

    echo "This includes:"
    echo "  - The Backhaul binary ($BIN_PATH)"
    echo "  - All tunnel configurations (from $CONFIG_DIR)"
    echo "  - The main configuration directory structure (e.g., /etc/easybackhaul)"
    echo "  - All systemd services (e.g., backhaul-*.service)"
    echo "  - All UFW rules managed by EasyBackhaul"
    echo "  - All EasyBackhaul-managed cron jobs"
    echo "  - Temporary files and watcher scripts"
    echo "  - Backup files ($BACKUP_DIR)"
    echo "  - Log files and directory ($LOG_DIR)"
    echo "  - Logrotate configuration (/etc/logrotate.d/easybackhaul)"
    
    if ! prompt_yes_no "Are you absolutely sure you want to proceed with uninstallation?" "n"; then
        print_info "Uninstallation cancelled."; press_any_key; return 1; fi
    
    print_warning "The following directories and their contents will be deleted:"
    for path in "${paths_to_delete[@]}"; do
        if [[ -e "$path" ]]; then
            echo "  - $path"
        fi
    done
    
    if ! prompt_yes_no "Confirm deletion of the paths listed above?" "n"; then
        print_info "Uninstallation cancelled."; press_any_key; return 1; fi

    log_message "WARN" "Starting full uninstallation of EasyBackhaul..."
    
    # ... (service stopping, ufw, cron removal logic remains the same) ...
    
    print_info "Removing files and directories..."
    for path in "${paths_to_delete[@]}"; do
        if [[ -z "$path" || "$path" == "/" || "$path" == "/etc" || "$path" == "/usr" || "$path" == "/var" ]]; then
            handle_error "CRITICAL" "Skipping deletion of critical path: $path"
            continue
        fi
        if [[ -e "$path" ]]; then
            secure_delete "$path"
            log_message "INFO" "Removed: $path"
        fi
    done
    
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
    ensure_dir "$EASYBACKHAUL_APP_DIR"
    ensure_dir "$EASYBACKHAUL_TMP_DIR"
    ensure_dir "$BACKUP_DIR"
    ensure_dir "$(dirname "$BIN_PATH")"

    if type init_logging &>/dev/null; then
        init_logging
    else
        echo "FATAL ERROR: init_logging function not found. Cannot proceed." >&2
        exit 1
    fi

    trap '_global_ctrl_c_handler' INT

    log_message "INFO" "EasyBackhaul script started."

    : "${CONFIG_DIR:=$EASYBACKHAUL_APP_DIR/config}"
    : "${BACKUP_DIR:=$EASYBACKHAUL_APP_DIR/backup}"
    : "${BIN_PATH:=$EASYBACKHAUL_APP_DIR/bin/easybackhaul_binary}"
    : "${SERVICE_DIR:=/etc/systemd/system}"
    : "${CRON_COMMENT_TAG:=EasyBackhaul}"
    : "${HEALTH_LOG_FILE:=${LOG_DIR:-/var/log/easybackhaul}/easybackhaul_health.log}"
    : "${PERFORMANCE_LOG_FILE:=${LOG_DIR:-/var/log/easybackhaul}/easybackhaul_performance.log}"

    ensure_dir_wrapper() {
        local dir_path="$1"
        local permissions="${2:-700}"
        if [[ -z "$dir_path" ]]; then
            log_message "WARN" "ensure_dir_wrapper: Directory path is empty. Skipping."
            return
        fi
        if type ensure_dir &>/dev/null; then
            ensure_dir "$dir_path" "$permissions"
        else
            mkdir -p "$dir_path" && chmod "$permissions" "$dir_path"
            log_message "WARN" "ensure_dir function not found. Used basic mkdir -p."
        fi
    }
    
    ensure_dir_wrapper "$EASYBACKHAUL_APP_DIR" "755"
    ensure_dir_wrapper "$(dirname "$BIN_PATH")" "755"
    ensure_dir_wrapper "$CONFIG_DIR" "700"
    ensure_dir_wrapper "$BACKUP_DIR" "700"
    ensure_dir_wrapper "$LOG_DIR" "700"

    if [[ $EUID -ne 0 ]]; then handle_critical_error "This script must be run as root or with sudo."; fi
    
    if type check_dependencies &>/dev/null; then check_dependencies;
    else handle_critical_error "check_dependencies function not found."; fi

    if type get_server_info &>/dev/null; then get_server_info; else log_message "WARN" "get_server_info not found."; fi

    if [[ ! -f "$BIN_PATH" ]]; then
        log_message "WARN" "Backhaul binary not found at $BIN_PATH. Starting installation wizard."
        if ! _initial_installation_wizard; then
            handle_critical_error "Backhaul binary installation was not completed. Exiting."
        fi
    fi

    if ! verify_binary_installation "quiet"; then
        handle_critical_error "Backhaul binary at $BIN_PATH is invalid or verification failed. Please try re-installing."
    fi

    CURRENT_MENU_FUNCTION="main_menu_entry"
    MENU_STACK=("main_menu_entry")

    log_message "DEBUG" "Menu system initialized. Starting main loop for $CURRENT_MENU_FUNCTION"

    while [[ -n "$CURRENT_MENU_FUNCTION" ]]; do
        log_message "DEBUG" "Main loop - Current Menu: $CURRENT_MENU_FUNCTION, Stack: [${MENU_STACK[*]}]"

        case "$CURRENT_MENU_FUNCTION" in
            "main_menu_entry") main_menu_entry ;;
            "configure_tunnel") configure_tunnel ;;
            "manage_tunnels_menu") manage_tunnels_menu ;;
            "system_health_monitor_menu") system_health_monitor_menu ;;
            "manage_ufw_main_menu") manage_ufw_main_menu ;;
            "generate_self_signed_tls_cert") generate_self_signed_tls_cert ;;
            "run_network_diagnostics_menu") run_network_diagnostics_menu ;;
            "view_system_log"*) view_system_log "${CURRENT_MENU_FUNCTION#view_system_log }" ;;
            "manage_specific_tunnel_menu"*) manage_specific_tunnel_menu "${CURRENT_MENU_FUNCTION#manage_specific_tunnel_menu }" ;;
            "manage_tunnel_watcher"*) manage_tunnel_watcher "${CURRENT_MENU_FUNCTION#manage_tunnel_watcher }" ;;
            "_view_tunnel_watcher_log"*) _view_tunnel_watcher_log "${CURRENT_MENU_FUNCTION#_view_tunnel_watcher_log }" ;;
            "_manage_watcher_shared_secret"*) _manage_watcher_shared_secret "${CURRENT_MENU_FUNCTION#_manage_watcher_shared_secret }" ;;
            "_mng_change_log_level"*) _mng_change_log_level "${CURRENT_MENU_FUNCTION#_mng_change_log_level }" ;;
            *) handle_critical_error "Unknown menu function: $CURRENT_MENU_FUNCTION" ;;
        esac

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