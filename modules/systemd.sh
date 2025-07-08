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
    # If not provided, and script is run as root, use 'nobody' or a dedicated user if exists.
    # If script is not root, it will likely fail to write to /etc/systemd/system anyway.
    local effective_user="$service_user"
    local effective_group="$service_group"

    if [[ "$(id -u)" -eq 0 ]]; then # Running as root
        if [[ -z "$effective_user" ]]; then effective_user="nobody"; fi
        if [[ -z "$effective_group" ]]; then effective_group="nogroup"; fi # or 'nobody' depending on distro
        # Check if user 'nobody' exists, else use current user if not root (which it is)
        if ! id -u "$effective_user" >/dev/null 2>&1; then
            log_message "WARN" "User '$effective_user' not found, service will run as root. Consider creating a dedicated user."
            effective_user="root"
            effective_group="root"
        fi
    elif [[ -n "$effective_user" ]]; then
         log_message "WARN" "Running as non-root. Service User/Group might not be applied effectively by systemd unless root manages it."
    fi


    # Ensure the directory for service files exists
    ensure_dir "$(dirname "$service_file_path")" "755" # Systemd service dir usually root owned

    # Create the service file content
    # Added User and Group. Increased LimitNOFILE. Added some hardening.
    cat > "$service_file_path" <<EOL
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
$( [[ -n "$effective_user" ]] && echo "User=${effective_user}" )
$( [[ -n "$effective_group" ]] && echo "Group=${effective_group}" )

# Security Hardening Options (optional, but good practice)
# ProtectSystem=full
# ProtectHome=true
# PrivateTmp=true
# NoNewPrivileges=true
# ReadWritePaths=${CONFIG_DIR} ${LOG_DIR} # Paths Backhaul needs to write to, adjust as needed
# CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW # Example, adjust to minimum required

[Install]
WantedBy=multi-user.target
EOL

    if ! run_with_spinner "Reloading systemd daemon..." systemctl daemon-reload; then
        handle_error "ERROR" "Failed to reload systemd daemon. Service file might be invalid: $service_file_path"
        return 1
    fi

    log_message "INFO" "Enabling service $service_name..."
    if ! run_with_spinner "Enabling service $service_name..." systemctl enable "$service_name"; then
        handle_error "ERROR" "Failed to enable service $service_name. Check systemd logs."
        # Attempt to show specific error if possible
        journalctl -u "$service_name" -n 5 --no-pager
        return 1
    fi

    log_message "INFO" "Starting service $service_name..."
    if ! run_with_spinner "Starting service $service_name..." systemctl start "$service_name"; then
        handle_error "ERROR" "Failed to start service $service_name."
        print_info "Check configuration and logs: journalctl -u $service_name -n 50 --no-pager"
        if prompt_yes_no "Show last 20 lines of the service log now?" "y"; then
            journalctl -u "$service_name" -n 20 --no-pager
        fi
        return 1
    fi

    handle_success "Service $service_name created, enabled, and started."

    if prompt_yes_no "Check service status now?" "y"; then
        systemctl status "$service_name" --no-pager
    fi
    return 0
}
true # Ensure script is valid