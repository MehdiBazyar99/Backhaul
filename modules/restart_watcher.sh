# modules/restart_watcher.sh
# Coordinated restart watcher for EasyBackhaul tunnels.

# This script defines functions for the watcher's core logic (executed by a background process)
# and for managing watcher instances (enabling, disabling, configuring from the main UI).

# --- Watcher Core Logic (for background process) ---

# Main entry point for the background watcher process.
# This function is NOT called directly by the main EasyBackhaul script's UI flow.
# It's intended to be run by the launcher script created by 'enable_tunnel_watcher'.
# Required environment variables (set by the launcher script from the .conf file):
#   SERVICE_NAME, LOG_PATTERN, REMOTE_HOST, REMOTE_PORT, RESTART_SECRET,
#   RESTART_DELAY_LOCAL, RESTART_DELAY_REMOTE, MAX_RETRIES, ROLE, LISTEN_PORT
_run_watcher_process() {
    # Source the main helpers to get log_message, etc.
    # This assumes helpers.sh is available in a known location relative to the main script,
    # or that build.sh makes it available. For now, assume globals and helpers are sourced by easybh.sh.
    # If this script were truly standalone, it would need its own minimal logging.

    # Use local copies of env vars or defaults if not set (though they should be by launcher)
    local service_name_local="${SERVICE_NAME:?SERVICE_NAME is required for watcher process}"
    local log_pattern_local="${LOG_PATTERN:-ERROR|FATAL|connection.*failed|timeout}"
    local remote_host_local="${REMOTE_HOST:?REMOTE_HOST is required}"
    local remote_port_local="${REMOTE_PORT:-45680}" # Default if not set by conf
    local restart_secret_local="${RESTART_SECRET:?RESTART_SECRET is required}"
    local delay_local="${RESTART_DELAY_LOCAL:-10}"
    local delay_remote="${RESTART_DELAY_REMOTE:-10}"
    local max_retries_local="${MAX_RETRIES:-3}"
    local role_local="${ROLE:-unknown_watcher_role}"
    local listen_port_local="${LISTEN_PORT:-45679}" # Default if not set by conf
    local ack_file_path="/tmp/restart_ack_${service_name_local}" # Standardized ACK file path

    log_message "INFO" "[Watcher:$role_local] Starting for service: $service_name_local. Listening on $listen_port_local. Remote: $remote_host_local:$remote_port_local."

    # Start listener in background (within this watcher process)
    _watcher_listen_for_requests "$listen_port_local" "$remote_host_local" "$remote_port_local" \
                                "$restart_secret_local" "$role_local" "$delay_remote" \
                                "$service_name_local" "$ack_file_path" &
    local listener_bg_pid=$!

    # Trap signals for cleanup
    trap '_watcher_cleanup $listener_bg_pid; exit 0' SIGINT SIGTERM

    # Start log monitoring (this will block)
    _watcher_monitor_logs "$service_name_local" "$log_pattern_local" \
                          "$remote_host_local" "$remote_port_local" \
                          "$restart_secret_local" "$role_local" "$delay_local" \
                          "$max_retries_local" "$ack_file_path"

    _watcher_cleanup $listener_bg_pid # Cleanup if monitor_logs exits
    log_message "INFO" "[Watcher:$role_local] Exiting for service: $service_name_local."
}

_watcher_cleanup() {
    local listener_pid_to_kill="$1"
    log_message "INFO" "[Watcher] Cleaning up listener PID $listener_pid_to_kill..."
    if [[ -n "$listener_pid_to_kill" ]] && kill -0 "$listener_pid_to_kill" 2>/dev/null; then
        kill "$listener_pid_to_kill" 2>/dev/null && sleep 0.1 && kill -9 "$listener_pid_to_kill" 2>/dev/null
    fi
    # Ack file is specific to an event, usually removed after processing.
}

_watcher_listen_for_requests() {
    local listen_port="$1" remote_host="$2" remote_port="$3" secret_val="$4" \
          current_role="$5" remote_delay="$6" service_to_restart="$7" ack_file="$8"

    # Check nc compatibility once at the start of listener
    if [[ "${NC_COMPATIBLE:-false}" != "true" ]]; then
        log_message "ERROR" "[Watcher:$current_role] Netcat incompatible. Listener for $service_to_restart cannot reliably start."
        return 1
    fi

    while true; do
        local received_msg
        # Use timeout with nc if available and compatible, otherwise nc might block indefinitely
        if command -v timeout &>/dev/null; then
            received_msg=$(timeout 65s nc -l -p "$listen_port" -w 60 2>/dev/null)
        else
            # Less reliable without timeout, -w might not work with -l on all nc versions
            received_msg=$(nc -l -p "$listen_port" -w 60 2>/dev/null)
        fi

        if [[ -z "$received_msg" ]]; then # Timeout or empty message
            sleep 1 # Prevent tight loop on continuous timeouts/errors
            continue
        fi

        log_message "DEBUG" "[Watcher:$current_role] Received on $listen_port: $received_msg"

        if [[ "$received_msg" =~ ^RESTART_REQUEST:([^:]+):([^:]+)$ ]]; then
            local received_secret="${BASH_REMATCH[1]}"
            local sender_role="${BASH_REMATCH[2]}"
            if [[ "$received_secret" == "$secret_val" ]]; then
                log_message "INFO" "[Watcher:$current_role] Auth OK. Received RESTART_REQUEST from $sender_role for $service_to_restart."
                log_message "INFO" "[Watcher:$current_role] Sending ACK to $remote_host:$remote_port and scheduling restart in $remote_delay s."
                echo "RESTART_ACK:$secret_val:$current_role" | nc "$remote_host" "$remote_port" -w 3 # Short timeout for ACK

                ( # Subshell for delayed restart
                    sleep "$remote_delay"
                    log_message "INFO" "[Watcher:$current_role] Executing restart for $service_to_restart (triggered by remote)."
                    systemctl restart "$service_to_restart"
                ) & # Run in background
            else
                log_message "WARN" "[Watcher:$current_role] Received RESTART_REQUEST with INVALID secret from $sender_role. Ignoring."
            fi
        elif [[ "$received_msg" =~ ^RESTART_ACK:([^:]+):([^:]+)$ ]]; then
            local received_secret="${BASH_REMATCH[1]}"
            # local ack_sender_role="${BASH_REMATCH[2]}" # Can log this if needed
            if [[ "$received_secret" == "$secret_val" ]]; then
                log_message "INFO" "[Watcher:$current_role] Received RESTART_ACK for $service_to_restart. Storing in $ack_file."
                touch "$ack_file" # Signal that ACK was received
            else
                 log_message "WARN" "[Watcher:$current_role] Received RESTART_ACK with INVALID secret. Ignoring."
            fi
        else
            log_message "WARN" "[Watcher:$current_role] Received unknown message on $listen_port: $received_msg"
        fi
    done
}

_watcher_monitor_logs() {
    local service_to_monitor="$1" pattern="$2" r_host="$3" r_port="$4" secret_val="$5" \
          current_role="$6" local_delay="$7" max_tries="$8" ack_file="$9"

    log_message "INFO" "[Watcher:$current_role] Monitoring logs for $service_to_monitor (Pattern: '$pattern')."

    # Ensure nc compatibility for sending requests
    if [[ "${NC_COMPATIBLE:-false}" != "true" ]]; then
        log_message "ERROR" "[Watcher:$current_role] Netcat incompatible. Cannot reliably send restart requests for $service_to_monitor."
        # Could choose to only do local restarts or exit. For now, will proceed but log error.
    fi

    journalctl -u "$service_to_monitor" -f --no-pager | while IFS= read -r log_line; do
        if echo "$log_line" | grep -qE "$pattern"; then
            log_message "WARN" "[Watcher:$current_role] Error detected in logs for $service_to_monitor: $log_line"
            log_message "INFO" "[Watcher:$current_role] Initiating coordinated restart procedure for $service_to_monitor."

            local attempt_num=1
            local ack_is_received=false
            while (( attempt_num <= max_tries )); do
                log_message "INFO" "[Watcher:$current_role] Sending RESTART_REQUEST to $r_host:$r_port for $service_to_monitor (Attempt $attempt_num/$max_tries)."
                # Clear any old ACK file before sending request
                rm -f "$ack_file"
                echo "RESTART_REQUEST:$secret_val:$current_role" | nc "$r_host" "$r_port" -w 3 # Short timeout for send

                # Wait for ACK (e.g., up to 5 seconds)
                for (( i=0; i<5; i++ )); do
                    if [[ -f "$ack_file" ]]; then
                        log_message "INFO" "[Watcher:$current_role] RESTART_ACK received for $service_to_monitor."
                        rm -f "$ack_file" # Consume ACK
                        ack_is_received=true
                        break # Break inner loop (wait for ACK)
                    fi
                    sleep 1
                done

                if $ack_is_received; then
                    break # Break outer loop (retry attempts)
                fi

                log_message "WARN" "[Watcher:$current_role] No ACK received for $service_to_monitor (Attempt $attempt_num). Retrying if attempts remain."
                ((attempt_num++))
            done

            if $ack_is_received; then
                log_message "INFO" "[Watcher:$current_role] Coordinated restart approved. Restarting $service_to_monitor locally in $local_delay seconds."
            else
                log_message "ERROR" "[Watcher:$current_role] Failed to coordinate restart for $service_to_monitor after $max_tries attempts. Proceeding with local restart only in $local_delay seconds."
            fi

            ( # Subshell for delayed local restart
                sleep "$local_delay"
                log_message "INFO" "[Watcher:$current_role] Executing local restart for $service_to_monitor."
                systemctl restart "$service_to_monitor"
            ) &

            # IMPORTANT: If monitor_and_restart is part of the main watcher script that gets backgrounded,
            # this 'return' will exit the 'while read' loop from journalctl, effectively stopping monitoring
            # for this particular error instance. The watcher process itself would then exit due to _run_watcher_process structure.
            # This is usually the desired behavior: detect error, attempt restart, then the new service instance's logs will be monitored.
            return
        fi
    done
    # If journalctl -f exits (e.g. service stopped manually and journalctl terminated), this loop ends.
    log_message "INFO" "[Watcher:$current_role] Log monitoring for $service_to_monitor ended (journalctl -f exited)."
}


# --- Watcher UI Management Functions (called by main EasyBackhaul script) ---

_tunnel_watcher_menu_help() {
    local service_name_ctx="$1" # Context for help
    print_menu_header "secondary" "Restart Watcher Help" "Service: $service_name_ctx"
    echo "The Coordinated Restart Watcher monitors a tunnel service for errors."
    echo "If an error is detected (based on a log pattern), it attempts to"
    echo "coordinate a restart with the remote end of the tunnel."
    echo
    print_info "Key Features:"
    echo "  - Error Detection: Monitors service logs using 'journalctl -f'."
    echo "  - Coordinated Restart: Communicates with the remote watcher via netcat."
    echo "  - Secure Communication: Uses a shared secret for authentication."
    echo "  - Configurable: Delays, retries, ports, and log patterns can be set."
    echo
    print_info "Setup:"
    echo "  1. Enable watcher on one side (e.g., server)."
    echo "  2. A shared secret is generated/used. Note this secret."
    echo "  3. Enable watcher on the other side (e.g., client), providing the SAME secret."
    echo "  4. Configure IP addresses and ports for communication between watchers."
    echo
    print_info "Important:"
    echo "  - Requires a compatible 'nc' (netcat) version (netcat-openbsd recommended)."
    echo "  - Ensure firewall rules allow communication on the watcher ports."
    press_any_key
}

manage_tunnel_watcher() {
    local main_service_name="$1" # e.g., backhaul-bh-server-tcp-xxxxx
    local tunnel_short_suffix="$2" # e.g., bh-server-tcp-xxxxx
    local tunnel_config_file="$3"  # Path to the main tunnel's TOML config

    # Construct paths for watcher-specific files (convention)
    local watcher_launcher_script="/tmp/backhaul-watcher-${tunnel_short_suffix}.sh"
    local watcher_conf_file="/tmp/backhaul-watcher-${tunnel_short_suffix}.conf"
    local watcher_pid_file="/tmp/backhaul-watcher-${tunnel_short_suffix}.pid"
    # Watcher log is managed by nohup redirection in _enable_tunnel_watcher

    local menu_options=(
        "1. Enable Watcher"
        "2. Disable Watcher"
        "3. Show Watcher Status"
        "4. View Watcher Log"
        "5. Edit Watcher Configuration"
        "6. Test Watcher Communication (experimental)"
        "7. Manage Watcher Shared Secret"
    )
    # local current_exit_details=("0" "Back to Tunnel Management") # No longer needed
    local user_choice menu_rc

    while true; do
        local watcher_status="Disabled/Not Running"
        if [[ -f "$watcher_pid_file" ]]; then
            local pid_val
            pid_val=$(cat "$watcher_pid_file" 2>/dev/null)
            if [[ -n "$pid_val" ]] && ps -p "$pid_val" > /dev/null 2>&1; then
                watcher_status="Running (PID: $pid_val)"
            fi
        fi
        print_menu_header "secondary" "Restart Watcher Management" "Tunnel: $tunnel_short_suffix" "Watcher: $watcher_status"

        menu_loop "Select watcher option" menu_options "_tunnel_watcher_menu_help \"$tunnel_short_suffix\""
        local menu_rc=$?
        local user_choice="$MENU_CHOICE" # Capture MENU_CHOICE after $?

        case "$menu_rc" in
            0) # Numeric choice
                case "$user_choice" in
                    "1") _enable_tunnel_watcher "$main_service_name" "$tunnel_short_suffix" "$tunnel_config_file" ;;
                    "2") _disable_tunnel_watcher "$tunnel_short_suffix" "$tunnel_config_file" ;;
                    "3") _show_tunnel_watcher_status "$tunnel_short_suffix" ;;
                    "4")
                        # _view_tunnel_watcher_log calls view_system_log which is a menu
                        navigate_to_menu "_view_tunnel_watcher_log \"$tunnel_short_suffix\""
                        return 0 ;;
                    "5") _edit_tunnel_watcher_config "$tunnel_short_suffix" "$tunnel_config_file" ;;
                    "6") _test_tunnel_watcher_comm "$tunnel_short_suffix" ;;
                    "7")
                        # _manage_watcher_shared_secret is a menu
                        navigate_to_menu "_manage_watcher_shared_secret \"$tunnel_config_file\""
                        return 0 ;;
                    *) print_warning "Invalid option: $user_choice"; press_any_key ;;
                esac
                ;;
            2) # '?' Help shown
                continue ;;
            3) # 'm' Main Menu
                go_to_main_menu; return 0 ;;
            4) # 'x' Exit script
                request_script_exit; return 0 ;;
            5) # 'r' Return/Back (to specific tunnel menu)
                return_from_menu; return 0 ;;
            6) # Invalid input in menu_loop (warning and press_any_key handled by menu_loop)
                continue ;; # Re-display this menu
            *)
                handle_error "ERROR" "Unhandled menu_loop code $menu_rc in manage_tunnel_watcher"; press_any_key
                continue;; # Ensure redraw on unexpected error
        esac
    done
}

_enable_tunnel_watcher() {
    local service_name="$1" tunnel_suffix="$2" config_file="$3"
    print_menu_header "secondary" "Enable Restart Watcher" "Tunnel: $tunnel_suffix"

    # Check for nc compatibility first
    ensure_netcat_installed # From helpers.sh, also runs check_nc_compatibility
    if [[ "${NC_COMPATIBLE:-false}" != "true" ]]; then
        handle_error "ERROR" "Netcat is not compatible. Watcher cannot be reliably enabled."
        press_any_key
        return 1
    fi
    
    # Default watcher config values
    local w_role w_remote_host w_listen_port w_remote_port w_secret w_log_pattern
    local w_delay_local=10 w_delay_remote=10 w_max_retries=3

    # Determine role and pre-fill some values based on tunnel config
    if grep -q '\[server\]' "$config_file"; then
        w_role="server"
        print_info "This is a SERVER tunnel. You need the CLIENT's public IP for watcher communication."
        read -r -p "Enter CLIENT's public IP address: " w_remote_host
        if ! validate_ip "$w_remote_host"; then handle_error "ERROR" "Invalid IP address for remote host."; press_any_key; return 1; fi
        w_listen_port="${WATCHER_SERVER_LISTEN_PORT:-45679}" # Server listens on one port
        w_remote_port="${WATCHER_CLIENT_LISTEN_PORT:-45680}" # Server sends to client's listen port
    elif grep -q '\[client\]' "$config_file"; then
        w_role="client"
        w_remote_host=$(grep 'remote_addr[[:space:]]*=' "$config_file" | sed 's/.*=[[:space:]]*"\(.*\):.*"/\1/')
        if ! validate_ip "$w_remote_host"; then handle_error "ERROR" "Could not parse server IP from tunnel config."; press_any_key; return 1; fi
        print_info "This is a CLIENT tunnel. Remote server IP for watcher: $w_remote_host"
        w_listen_port="${WATCHER_CLIENT_LISTEN_PORT:-45680}" # Client listens on one port
        w_remote_port="${WATCHER_SERVER_LISTEN_PORT:-45679}" # Client sends to server's listen port
    else
        handle_error "ERROR" "Cannot determine tunnel mode (server/client) from config: $config_file"
        press_any_key
        return 1
    fi

    # Get/Generate Shared Secret
    w_secret=$(_get_or_set_watcher_secret "$config_file" "$w_role")
    if [[ -z "$w_secret" ]]; then return 1; fi # Error handled in _get_or_set_watcher_secret

    w_log_pattern=$(grep 'log_pattern[[:space:]]*=' "$config_file" | sed 's/.*=[[:space:]]*"\(.*\)"/\1/' 2>/dev/null || echo "ERROR|FATAL|connection.*failed|timeout|reset by peer")

    print_info "--- Watcher Configuration ---"
    echo "  Role: $w_role"
    echo "  Service to Monitor: $service_name"
    echo "  Log Pattern for Errors: $w_log_pattern"
    echo "  This Watcher Listens on Port: $w_listen_port"
    echo "  Remote Watcher Host: $w_remote_host"
    echo "  Remote Watcher Port: $w_remote_port"
    echo "  Shared Secret: [set]" # Don't display

    if ! prompt_yes_no "Proceed with these watcher settings?" "y"; then
        print_info "Watcher enablement cancelled."
        press_any_key
        return 1
    fi

    # Create watcher configuration file (e.g., /tmp/backhaul-watcher-suffix.conf)
    local watcher_conf_file_path="/tmp/backhaul-watcher-${tunnel_suffix}.conf"
    cat > "$watcher_conf_file_path" <<EOL
# Watcher configuration for tunnel: $tunnel_suffix
SERVICE_NAME="$service_name"
LOG_PATTERN="$w_log_pattern"
REMOTE_HOST="$w_remote_host"
REMOTE_PORT="$w_remote_port"
RESTART_SECRET="$w_secret"
RESTART_DELAY_LOCAL="$w_delay_local"
RESTART_DELAY_REMOTE="$w_delay_remote"
MAX_RETRIES="$w_max_retries"
ROLE="$w_role"
LISTEN_PORT="$w_listen_port"
EOL
    chmod 600 "$watcher_conf_file_path"
    log_message "INFO" "Watcher config file created: $watcher_conf_file_path"

    # Create watcher launcher script (e.g., /tmp/backhaul-watcher-suffix.sh)
    local watcher_launcher_script_path="/tmp/backhaul-watcher-${tunnel_suffix}.sh"

    # The main easybh.sh script's location is needed to reliably source modules.
    # We assume it's in the user's PATH and find it.
    local main_script_path
    main_script_path=$(command -v easybh.sh)
    if [[ -z "$main_script_path" ]]; then
        # Fallback if not in PATH: check common locations.
        if [[ -f "/usr/local/bin/easybh.sh" ]]; then
            main_script_path="/usr/local/bin/easybh.sh"
        elif [[ -f "./easybh.sh" ]]; then
            main_script_path="./easybh.sh"
        else
            handle_error "ERROR" "Could not locate the main 'easybh.sh' script. Watcher cannot be started."
            press_any_key
            return 1
        fi
    fi

    cat > "$watcher_launcher_script_path" <<EOLSCRIPT
#!/bin/bash
# Launcher for EasyBackhaul Watcher: ${tunnel_suffix}

# The main easybh.sh script is a single file containing all modules.
# We can source it directly to get access to all necessary functions.
MAIN_SCRIPT_PATH="$main_script_path"

if [[ ! -f "\$MAIN_SCRIPT_PATH" ]]; then
    echo "FATAL: Main script not found at \$MAIN_SCRIPT_PATH" >&2
    exit 1
fi

# Source the entire easybh.sh script. This makes all functions available.
# We add a guard to prevent the main_script_entry_point from running.
export EASYBACKHAUL_SOURCED=true
source "\$MAIN_SCRIPT_PATH"
unset EASYBACKHAUL_SOURCED

# Load the specific configuration for this watcher instance
source "$watcher_conf_file_path"

# Now, call the watcher's main execution function, which was loaded
# from the main script.
_run_watcher_process

EOLSCRIPT
    chmod +x "$watcher_launcher_script_path"
    log_message "INFO" "Watcher launcher script created: $watcher_launcher_script_path"

    # Start the watcher in the background
    local watcher_log_file="/var/log/easybackhaul/watcher-${tunnel_suffix}.log" # Log to main log dir
    ensure_dir "$(dirname "$watcher_log_file")"
    
    nohup "$watcher_launcher_script_path" >> "$watcher_log_file" 2>&1 &
    local watcher_pid=$!
    sleep 1 # Give it a moment to start or fail

    local watcher_pid_file_path="/tmp/backhaul-watcher-${tunnel_suffix}.pid"
    if ps -p $watcher_pid > /dev/null 2>&1; then
        echo "$watcher_pid" > "$watcher_pid_file_path"
        chmod 600 "$watcher_pid_file_path"
        update_toml_value "$config_file" "restart_watcher_enabled" "true" "boolean"
        update_toml_value "$config_file" "restart_watcher_pid" "$watcher_pid" "numeric"
        # Store other watcher params in the main tunnel config for visibility/editing later
        update_toml_value "$config_file" "watcher_role" "$w_role" "string"
        update_toml_value "$config_file" "watcher_listen_port" "$w_listen_port" "numeric"
        update_toml_value "$config_file" "watcher_remote_host" "$w_remote_host" "string"
        update_toml_value "$config_file" "watcher_remote_port" "$w_remote_port" "numeric"
        update_toml_value "$config_file" "watcher_log_pattern" "$w_log_pattern" "string"

        handle_success "Watcher enabled and started for $service_name (PID: $watcher_pid)."
        print_info "Watcher log: $watcher_log_file"
    else
        handle_error "ERROR" "Watcher process failed to start for $service_name. Check $watcher_log_file for details."
        # Cleanup temp files if start failed
        rm -f "$watcher_conf_file_path" "$watcher_launcher_script_path"
    fi
    press_any_key
}

_disable_tunnel_watcher() {
    local tunnel_suffix="$1" config_file="$2"
    print_menu_header "secondary" "Disable Restart Watcher" "Tunnel: $tunnel_suffix"

    # cleanup_watcher_files (from helpers.sh) handles stopping the process and removing tmp files
    if cleanup_watcher_files "$tunnel_suffix"; then
        update_toml_value "$config_file" "restart_watcher_enabled" "false" "boolean"
        update_toml_value "$config_file" "restart_watcher_pid" "0" "numeric" # Clear PID
        handle_success "Watcher disabled and files cleaned up for tunnel: $tunnel_suffix."
    else
        handle_error "WARNING" "Watcher cleanup reported issues, but proceeding to mark as disabled in config."
        update_toml_value "$config_file" "restart_watcher_enabled" "false" "boolean"
    fi
    press_any_key
}

_show_tunnel_watcher_status() {
    local tunnel_suffix="$1"
    print_menu_header "secondary" "Watcher Status" "Tunnel: $tunnel_suffix"
    
    local watcher_pid_file_path="/tmp/backhaul-watcher-${tunnel_suffix}.pid"
    local watcher_conf_file_path="/tmp/backhaul-watcher-${tunnel_suffix}.conf"

    if [[ -f "$watcher_pid_file_path" ]]; then
        local pid_val
        pid_val=$(cat "$watcher_pid_file_path" 2>/dev/null)
        if [[ -n "$pid_val" ]] && ps -p "$pid_val" > /dev/null 2>&1; then
            print_success "Watcher is RUNNING (PID: $pid_val)."
            echo "  Launcher: /tmp/backhaul-watcher-${tunnel_suffix}.sh"
            echo "  Config: $watcher_conf_file_path"
            echo "  Log: /var/log/easybackhaul/watcher-${tunnel_suffix}.log"
            if [[ -f "$watcher_conf_file_path" ]]; then
                echo "  --- Configuration from $watcher_conf_file_path ---"
                grep -v "RESTART_SECRET" "$watcher_conf_file_path" | sed 's/^/    /' # Hide secret
            fi
        else
            print_error "Watcher is NOT RUNNING (PID file found but process dead or PID invalid)."
            print_info "Consider disabling and re-enabling the watcher."
        fi
    else
        print_warning "Watcher is DISABLED or its PID file is missing."
        print_info "To enable, use the 'Enable Watcher' option."
    fi
    press_any_key
}

_view_tunnel_watcher_log() {
    local tunnel_suffix="$1"
    local watcher_log_file="/var/log/easybackhaul/watcher-${tunnel_suffix}.log"
    if [[ -f "$watcher_log_file" ]]; then
        view_system_log "file" "$watcher_log_file" "Watcher Log: $tunnel_suffix"
    else
        handle_error "WARNING" "Watcher log file not found: $watcher_log_file"
        press_any_key
    fi
}

_edit_tunnel_watcher_config() {
    local tunnel_suffix="$1" main_tunnel_config_file="$2"
    local watcher_conf_file_path="/tmp/backhaul-watcher-${tunnel_suffix}.conf" # This is the live config for the running watcher
    
    print_menu_header "secondary" "Edit Watcher Configuration" "Tunnel: $tunnel_suffix"

    if [[ ! -f "$watcher_conf_file_path" ]]; then
        handle_error "ERROR" "Watcher process config file not found: $watcher_conf_file_path. Enable watcher first or check /tmp."
        press_any_key
        return 1
    fi

    # Display current settings from the watcher's .conf file
    print_info "Current settings from $watcher_conf_file_path (effective on next watcher restart):"
    # Exclude secret for display security
    grep -v "RESTART_SECRET" "$watcher_conf_file_path" | sed 's/^/  /'
    echo
    print_info "Editing these values requires the watcher process to be restarted to take effect."
    print_info "The main tunnel config ($main_tunnel_config_file) also stores some of these for UI display."

    # For simplicity, prompt for common fields. Direct edit of .conf for full power.
    # This is a simplified editor.
    local new_log_pattern new_delay_local new_delay_remote new_max_retries

    # Example: Edit Log Pattern
    read -r -p "New Log Pattern (leave blank to keep current '$(grep LOG_PATTERN "$watcher_conf_file_path" | cut -d'=' -f2- | tr -d '"')'): " new_log_pattern
    if [[ -n "$new_log_pattern" ]]; then
        sed -i "s|^LOG_PATTERN=.*|LOG_PATTERN=\"$new_log_pattern\"|" "$watcher_conf_file_path"
        update_toml_value "$main_tunnel_config_file" "watcher_log_pattern" "$new_log_pattern" "string"
        print_success "Log pattern updated in $watcher_conf_file_path and main config."
    fi
    
    # Add more fields similarly... (RESTART_DELAY_LOCAL, etc.)

    print_info "Configuration in $watcher_conf_file_path updated."
    print_warning "Restart the watcher for tunnel '$tunnel_suffix' for changes to take effect."
    press_any_key
}

_test_tunnel_watcher_comm() {
    local tunnel_suffix="$1"
    local watcher_conf_file_path="/tmp/backhaul-watcher-${tunnel_suffix}.conf"
    print_menu_header "secondary" "Test Watcher Communication" "Tunnel: $tunnel_suffix"

    if [[ ! -f "$watcher_conf_file_path" ]]; then
        handle_error "ERROR" "Watcher config file not found: $watcher_conf_file_path. Cannot perform test."
        press_any_key; return 1;
    fi
    source "$watcher_conf_file_path" # Load REMOTE_HOST, REMOTE_PORT, RESTART_SECRET, ROLE

    if [[ -z "$REMOTE_HOST" || -z "$REMOTE_PORT" || -z "$RESTART_SECRET" || -z "$ROLE" ]]; then
        handle_error "ERROR" "Watcher config is incomplete. Cannot perform test."
        press_any_key; return 1;
    fi
    
    ensure_netcat_installed
    if [[ "${NC_COMPATIBLE:-false}" != "true" ]]; then
        handle_error "ERROR" "Netcat is not compatible. Watcher communication test cannot be reliably performed."
        press_any_key; return 1;
    fi

    print_info "Testing communication with remote watcher at $REMOTE_HOST:$REMOTE_PORT"
    print_info "Sending a TEST_PING message..."
    local test_message="TEST_PING:$RESTART_SECRET:$ROLE"
    local ack_file_path="/tmp/test_ack_${SERVICE_NAME:-$tunnel_suffix}" # SERVICE_NAME might not be in scope here from conf
    rm -f "$ack_file_path"

    echo "$test_message" | nc "$REMOTE_HOST" "$REMOTE_PORT" -w 5 # Send with timeout

    print_info "Waiting for TEST_ACK (up to 5 seconds)..."
    local i
    for i in {1..5}; do
        if [[ -f "$ack_file_path" ]]; then
            local ack_content
            ack_content=$(cat "$ack_file_path")
            handle_success "TEST_ACK received! Content: $ack_content"
            rm -f "$ack_file_path"
            press_any_key; return 0;
        fi
        sleep 1
    done

    handle_error "WARNING" "No TEST_ACK received. Check remote watcher, firewall, and secret."
    press_any_key
}

_get_or_set_watcher_secret() {
    local main_tunnel_config_file="$1"
    local current_tunnel_role="$2" # "server" or "client"
    local existing_secret

    # Try to get secret from the main tunnel config file first
    if [[ -f "$main_tunnel_config_file" ]]; then
        existing_secret=$(grep 'watcher_shared_secret' "$main_tunnel_config_file" | sed 's/.*=[[:space:]]*"\(.*\)"/\1/' 2>/dev/null)
    fi

    # If not in tunnel config, try global watcher secret file (usually for first server setup)
    if [[ -z "$existing_secret" && -f "$CONFIG_DIR/watcher_secret" ]]; then
        existing_secret=$(cat "$CONFIG_DIR/watcher_secret")
        # If found globally, also save it to the tunnel config for consistency
        if [[ -n "$existing_secret" && -f "$main_tunnel_config_file" ]]; then
             update_toml_value "$main_tunnel_config_file" "watcher_shared_secret" "$existing_secret" "string"
        fi
    fi

    if [[ -n "$existing_secret" ]]; then
        print_info "Using existing shared secret: [hidden]"
        if prompt_yes_no "Use this existing secret?" "y"; then
            echo "$existing_secret"
            return 0
        fi
    fi

    # If no existing secret or user wants to change/set one
    if [[ "$current_tunnel_role" == "server" ]]; then
        print_info "This is a SERVER. You can generate a new secret or enter one if you have it."
        if prompt_yes_no "Generate a new random secret for this watcher pair?" "y"; then
            local new_generated_secret
            new_generated_secret=$(generate_random_secret 32) # From helpers.sh
            print_info "Generated new secret: $new_generated_secret"
            print_warning "IMPORTANT: You MUST use this exact secret when configuring the CLIENT watcher."
            if prompt_yes_no "Use this generated secret?" "y"; then
                # Save to global and tunnel config
                echo "$new_generated_secret" > "$CONFIG_DIR/watcher_secret"
                set_secure_file_permissions "$CONFIG_DIR/watcher_secret" "600"
                if [[ -f "$main_tunnel_config_file" ]]; then
                    update_toml_value "$main_tunnel_config_file" "watcher_shared_secret" "$new_generated_secret" "string"
                fi
                echo "$new_generated_secret"
                return 0
            fi
        fi
    fi
    
    # Prompt to enter manually (always for client if not found, or if server chose not to generate)
    print_info "Please enter the shared watcher secret."
    if [[ "$current_tunnel_role" == "client" ]]; then
        print_info "This MUST match the secret on the SERVER side watcher."
    else # server, but chose not to generate
        print_info "This secret will be used for this watcher pair."
    fi

    local entered_secret
    while true; do
        read -r -s -p "Enter Shared Secret (min 8 chars): " entered_secret; echo
        if [[ "${#entered_secret}" -ge 8 ]]; then
            if [[ -f "$main_tunnel_config_file" ]]; then
                 update_toml_value "$main_tunnel_config_file" "watcher_shared_secret" "$entered_secret" "string"
            fi
            # Also update global if this is the server setting it for the first time potentially
            if [[ "$current_tunnel_role" == "server" ]]; then
                 echo "$entered_secret" > "$CONFIG_DIR/watcher_secret"
                 set_secure_file_permissions "$CONFIG_DIR/watcher_secret" "600"
            fi
            echo "$entered_secret"
            return 0
        else
            print_warning "Secret too short. Must be at least 8 characters."
            if prompt_yes_no "Try entering secret again?" "y"; then continue; else return 1; fi
        fi
    done
}


_manage_watcher_shared_secret() {
    local main_tunnel_config_file="$1"
    print_menu_header "secondary" "Watcher Shared Secret" "Manage"

    local current_secret # This will be populated by _get_or_set_watcher_secret if it exists
    current_secret=$(_get_or_set_watcher_secret "$main_tunnel_config_file" "unknown") # Role unknown just for display
    
    if [[ -n "$current_secret" ]]; then
        print_success "Current shared secret is set."
        print_info "(Secret is hidden for security. Choose 'View/Copy' to see it.)"
    else
        print_warning "No shared secret is currently set in the tunnel config."
    fi
    echo

    local secret_menu_options=(
        "1. View/Copy Current Secret"
        "2. Set/Update Secret Manually"
        "3. Generate New Secret (Server Role Recommended)"
    )
    # local secret_exit_details=("0" "Back") # No longer needed
    local user_choice menu_rc

    _secret_menu_help() {
        print_info "Shared Secret Help:"
        echo " - The watcher secret MUST be identical on both client and server watchers."
        echo " - View/Copy: Shows current secret (use 'xclip' or 'pbcopy' if available)."
        echo " - Set/Update: Manually enter or change the secret."
        echo " - Generate New: Creates a new random secret. If this is a server,"
        echo "   you must then update the client with this new secret."
        press_any_key
    }

    menu_loop "Select secret option" secret_menu_options "_secret_menu_help"
    local menu_rc=$?
    local user_choice="$MENU_CHOICE"

    case "$menu_rc" in
        0) # Numeric choice
            case "$user_choice" in
                "1") # View/Copy
                    local secret_to_show
                    secret_to_show=$(grep 'watcher_shared_secret' "$main_tunnel_config_file" | sed 's/.*=[[:space:]]*"\(.*\)"/\1/' 2>/dev/null || cat "$CONFIG_DIR/watcher_secret" 2>/dev/null || echo "${RESTART_WATCHER_SECRET}")
                    if [[ -n "$secret_to_show" ]]; then
                        print_info "Current Secret: $secret_to_show"
                        if command -v xclip &>/dev/null; then
                            echo -n "$secret_to_show" | xclip -selection clipboard
                            print_success "Secret copied to clipboard (xclip)."
                        elif command -v pbcopy &>/dev/null; then # macOS
                            echo -n "$secret_to_show" | pbcopy
                            print_success "Secret copied to clipboard (pbcopy)."
                        fi
                    else
                        print_warning "No secret found to display/copy."
                    fi
                    ;;
                "2") # Set manually
                    local role_for_set="client"
                    if grep -q 'mode[[:space:]]*=[[:space:]]*"server"' "$main_tunnel_config_file" 2>/dev/null; then role_for_set="server"; fi
                    local new_secret_val
                    new_secret_val=$(_get_or_set_watcher_secret "$main_tunnel_config_file" "$role_for_set")
                    if [[ -n "$new_secret_val" ]]; then
                        handle_success "Watcher secret process completed."
                    else
                        handle_warning "Watcher secret process cancelled or failed."
                    fi
                    ;;
                "3") # Generate new
                     if prompt_yes_no "Generate a new random secret? This will overwrite existing." "n"; then
                        local new_s
                        new_s=$(generate_random_secret 32)
                        print_info "New Generated Secret: $new_s"
                        print_warning "You MUST update the other side of the tunnel with this secret."
                        if prompt_yes_no "Use this new secret?" "y"; then
                            if [[ -z "$RESTART_WATCHER_SECRET" && -n "$GLOBAL_WATCHER_SECRET_FILE" ]]; then
                                echo "$new_s" > "$GLOBAL_WATCHER_SECRET_FILE"
                                set_secure_file_permissions "$GLOBAL_WATCHER_SECRET_FILE"
                            fi
                            update_toml_value "$main_tunnel_config_file" "watcher_shared_secret" "$new_s" "string"
                            handle_success "New secret set and saved."
                        else
                            print_info "New secret generation cancelled."
                        fi
                    fi
                    ;;
                *) print_warning "Invalid option: $user_choice";;
            esac
            ;;
        2) # '?' Help shown
            _manage_watcher_shared_secret "$main_tunnel_config_file"; return $? ;; # Re-call current function
        3) # 'm' Main Menu
            go_to_main_menu; return 0 ;;
        4) # 'x' Exit script
            request_script_exit; return 0 ;;
        5) # 'r' Return/Back (to manage_tunnel_watcher menu)
            return_from_menu; return 0 ;;
        6) # Invalid input
            _manage_watcher_shared_secret "$main_tunnel_config_file"; return $? ;;
        *)
            handle_error "ERROR" "Unhandled menu_loop code $menu_rc in _manage_watcher_shared_secret"; press_any_key;
            _manage_watcher_shared_secret "$main_tunnel_config_file"; return $? ;;
    esac
    press_any_key
}
true # Ensure script is valid if sourced.