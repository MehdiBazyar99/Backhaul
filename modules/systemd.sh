# systemd.sh
# Systemd service creation and management 

# --- Systemd Service Management ---
create_systemd_service() {
    local name_suffix=$1 config_path=$2
    local service_file="$SERVICE_DIR/backhaul-${name_suffix}.service"

    if ! command -v systemctl &>/dev/null; then
        print_warning "Systemd is not available on this system."
        if confirm_action "Do you want to run the tunnel in the foreground instead?" "n"; then
        fg_run="y"
    else
        fg_run="n"
    fi
        if [[ "${fg_run,,}" == "y" ]]; then
            print_info "Running: $BIN_PATH -c $config_path"
            "$BIN_PATH" -c "$config_path"
        else
            print_error "Cannot create a persistent service without systemd."
        fi
        return
    fi

    print_info "--> Creating systemd service file: $service_file"
    cat > "$service_file" <<EOL
[Unit]
Description=Backhaul Service (${name_suffix})
After=network.target

[Service]
Type=simple
ExecStart="${BIN_PATH}" -c "${config_path}"
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOL
    systemctl daemon-reload
    print_info "--> Enabling and starting service..."
    if ! systemctl enable "backhaul-${name_suffix}.service" >/dev/null 2>&1; then
        print_error "Failed to enable service. Please check systemd logs."
        return 1
    fi
    if ! systemctl start "backhaul-${name_suffix}.service"; then
        print_error "Failed to start service. Check config and logs with 'journalctl -u backhaul-${name_suffix}.service'."
        if confirm_action "Show the last 20 lines of the service log?" "y"; then
        showlog="y"
    else
        showlog="n"
    fi
        if [[ "${showlog,,}" == "y" ]]; then
            journalctl -u "backhaul-${name_suffix}.service" -n 20 --no-pager
        fi
        return 1
    fi
    print_success "Service backhaul-${name_suffix}.service created and started."

    if confirm_action "Check service status now?" "y"; then
        check_status="y"
    else
        check_status="n"
    fi
    if [[ "${check_status:-y}" == "y" ]]; then
        systemctl status "backhaul-${name_suffix}.service" --no-pager
    fi
} 