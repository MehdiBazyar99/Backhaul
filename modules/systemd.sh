# modules/systemd.sh
# Systemd service creation and management 

# --- Systemd Service Management ---
# Creates and manages a systemd service for a given tunnel.
# Parameters:
#   $1: name_suffix - The unique suffix for the tunnel (e.g., server-tcp-timestamp)
#   $2: config_path - Full path to the tunnel's TOML configuration file
#   $3: (Optional) user - User to run the service as (defaults to current user or root if not specified)
#   $4: (Optional) group - Group to run the service as (defaults to current user or root if not specified)
create_systemd_service() {
    local name_suffix="$1"
    local config_path="$2"
    local service_user="${3:-}" # User to run as
    local service_group="${4:-}" # Group to run as

    # Ensure SERVICE_DIR and BIN_PATH are available (should be from globals.sh)
    if [[ -z "$SERVICE_DIR" || -z "$BIN_PATH" ]]; then
        handle_error "CRITICAL" "SERVICE_DIR or BIN_PATH not defined. Cannot create systemd service."
        return 1
    fi

    local service_name="backhaul-${name_suffix}.service"
    local service_file_path="${SERVICE_DIR}/${service_name}"

    # Ensure CONFIG_DIR and LOG_DIR are available (should be from globals.sh)
    # These are now needed for ReadWritePaths
    if [[ -z "$CONFIG_DIR" || -z "$LOG_DIR" ]]; then
        handle_error "CRITICAL" "CONFIG_DIR or LOG_DIR not defined. Cannot create systemd service with proper paths."
        return 1
    fi

    if ! command -v systemctl &>/dev/null; then
        handle_error "WARNING" "Systemd (systemctl) not found on this system."
        print_info "A persistent service cannot be automatically created."
        print_info "To run the tunnel manually (for testing), you can use:"
        print_info "  $BIN_PATH -c \"$config_path\""
        print_info "For persistence without systemd, consider 'nohup', 'screen', 'tmux', or your system's init."
        if prompt_yes_no "Run the tunnel in the foreground for this session (for testing)?" "n"; then
            log_message "INFO" "Attempting to run tunnel in foreground: $BIN_PATH -c \"$config_path\""
            "$BIN_PATH" -c "$config_path" # This will block until Ctrl+C
        fi
        return 1 # Indicate service was not created
    fi

    log_message "INFO" "Creating systemd service file: $service_file_path for tunnel $name_suffix"

    # Determine User and Group for the service
    local effective_user="$service_user"
    local effective_group="$service_group"

    if [[ "$(id -u)" -eq 0 ]]; then # Running as root
        if [[ -z "$effective_user" ]]; then effective_user="nobody"; fi
        if [[ -z "$effective_group" ]]; then effective_group="nogroup"; fi

        if ! id -u "$effective_user" >/dev/null 2>&1; then
            log_message "WARN" "User '$effective_user' not found, service will run as root. Consider creating a dedicated user."
            effective_user="root"
            effective_group="root"
        elif ! getent group "$effective_group" >/dev/null 2>&1; then
             log_message "WARN" "Group '$effective_group' not found, service will run as root. Consider creating a dedicated group or using an existing one."
            effective_user="root" # Revert user to root too if group is invalid for nobody
            effective_group="root"
        fi
    elif [[ -n "$effective_user" ]]; then
         log_message "WARN" "Running as non-root. Service User/Group might not be applied effectively by systemd unless root manages it."
    fi

    # Ensure the service configuration file has correct ownership and permissions
    # The CONFIG_DIR (/etc/easybackhaul/configs) itself should be root:nogroup 0770 (set by globals.sh)
    # This allows 'nobody' (if in 'nogroup') to read files within it.
    if [[ -f "$config_path" ]] && [[ "$(id -u)" -eq 0 ]]; then
        log_message "DEBUG" "Setting ownership of $config_path to $effective_user:$effective_group"
        chown "${effective_user}:${effective_group}" "$config_path" || handle_error "WARN" "Failed to chown $config_path to $effective_user:$effective_group"

        log_message "DEBUG" "Setting permissions of $config_path to 0640"
        chmod 0640 "$config_path" || handle_error "WARN" "Failed to chmod $config_path to 0640"
    elif [[ ! -f "$config_path" ]]; then
        handle_error "ERROR" "Configuration file $config_path not found. Cannot set permissions or create service."
        return 1
    fi

    # Ensure the directory for systemd service files exists
    ensure_dir "$(dirname "$service_file_path")" "0755" # Systemd service dir usually root owned

    # Create the service file content
    # Added User and Group. Increased LimitNOFILE.
    # Added ReadWritePaths for the new CONFIG_DIR and LOG_DIR.
    # Set PrivateTmp=false explicitly.
    cat > "$service_file_path" <<EOL || { handle_error "ERROR" "Failed to write to service file: $service_file_path"; return 1; }
[Unit]
Description=Backhaul Tunnel Service (${name_suffix})
Documentation=https://github.com/Musixal/Backhaul
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=simple
ExecStart=${BIN_PATH} -c "${config_path}"
Restart=always
RestartSec=5s
TimeoutStopSec=10s
LimitNOFILE=1048576
$( [[ -n "$effective_user" ]] && printf "User=%s\n" "$effective_user" )
$( [[ -n "$effective_group" ]] && printf "Group=%s\n" "$effective_group" )

# Security Hardening Options (optional, but good practice)
# Security Hardening Options
ProtectSystem=strict
ProtectHome=true
PrivateTmp=false # Set to false as we are managing config access explicitly.
NoNewPrivileges=true
ReadWritePaths=${CONFIG_DIR} # Allow reading from the config directory
ReadWritePaths=${LOG_DIR}    # Allow writing to the log directory
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW # Adjust to minimum required

[Install]
WantedBy=multi-user.target
EOL

    if ! run_with_spinner "Reloading systemd daemon..." systemctl daemon-reload; then
        handle_error "ERROR" "Failed to reload systemd daemon. Service file might be invalid: $service_file_path. Check permissions and syntax."
        if [[ -f "$service_file_path" ]]; then
            cat "$service_file_path" # Show the generated service file for debugging
        fi
        return 1
    fi

    log_message "INFO" "Enabling service $service_name..."
    if ! run_with_spinner "Enabling service $service_name..." systemctl enable "$service_name"; then
        handle_error "ERROR" "Failed to enable service $service_name. Check systemd logs (journalctl -xe) and service file."
        journalctl -u "$service_name" -n 20 --no-pager
        return 1
    fi

    log_message "INFO" "Attempting to start service $service_name..."
    # Before starting, let's try to stat the config file as the service user to check access
    if [[ "$effective_user" != "root" ]] && command -v sudo &>/dev/null && command -v stat &>/dev/null; then
        log_message "DEBUG" "Pre-start check: Attempting to stat '$config_path' as user '$effective_user'..."
        if sudo -u "$effective_user" stat "$config_path" >/dev/null 2>&1; then
            log_message "INFO" "Pre-start check: User '$effective_user' can access '$config_path'."
        else
            log_message "WARN" "Pre-start check: User '$effective_user' may NOT be able to access '$config_path'. Stat command failed."
            # Log ls -ld output for the config directory and the file itself
            ls -ld "$CONFIG_DIR"
            ls -l "$config_path"
        fi
    fi

    if ! run_with_spinner "Starting service $service_name..." systemctl start "$service_name"; then
        handle_error "ERROR" "Failed to start service $service_name."
        print_info "Please check the service logs for details: journalctl -u $service_name -n 50 --no-pager"
        if prompt_yes_no "Show last 20 lines of the service log now?" "y"; then
            journalctl -u "$service_name" -n 20 --no-pager
        fi
        # Also show status which might include more direct error info
        systemctl status "$service_name" --no-pager
        return 1
    fi

    handle_success "Service $service_name created, enabled, and appears to be starting."
    print_info "It might take a few seconds for the service to fully initialize."

    if prompt_yes_no "Check service status now to confirm it's active (running)?" "y"; then
        systemctl status "$service_name" --no-pager
    fi
    return 0
}
true # Ensure script is valid