# menu.sh
# Main menu logic and script entrypoint 

# --- Installation Wizard ---
installation_wizard() {
    clear
    print_server_info_banner
    print_menu_header "EasyBackhaul Installation Wizard (v13.0-beta)" "Core by Musixal  |  Installer by @N4Xon"
    echo
    print_info "Welcome to EasyBackhaul! This wizard will help you install the Backhaul binary."
    echo
    print_info "Please choose your preferred installation method:"
    echo
    echo " 1. Automatic GitHub Download (Recommended)"
    echo "    - Downloads latest version from GitHub"
    echo "    - Includes connection testing and fallback options"
    echo
    echo " 2. Local File Installation"
    echo "    - Use a binary file you've downloaded manually"
    echo "    - Supports .tar.gz, .zip, or direct binary files"
    echo
    echo " 3. Alternative Download Source"
    echo "    - Download from your own server or alternative URL"
    echo "    - Useful when GitHub is not accessible"
    echo
    echo " 4. Network Diagnostics"
    echo "    - Test connectivity to various sources"
    echo "    - Help diagnose network issues"
    echo
    echo " 5. Skip Installation (Advanced)"
    echo "    - Continue without installing binary"
    echo "    - You can install manually later"
    echo
    print_menu_footer
    while true; do
        read -p "Please select an option [0-5, ? for help]: " install_choice
        case $install_choice in
            1)
                print_info "Starting automatic GitHub download..."
                if download_backhaul; then
                    return 0
                else
                    print_warning "⚠ Installation failed or was cancelled."
                    press_any_key
                    return 1
                fi
                ;;
            2)
                print_info "Starting local file installation..."
                local os=$(uname -s | tr '[:upper:]' '[:lower:]')
                local arch=$(uname -m)
                case $arch in
                    x86_64) arch="amd64" ;;
                    aarch64) arch="arm64" ;;
                    *) print_error "✗ Unsupported architecture: $arch"; press_any_key; return 1 ;;
                esac
                if download_from_local_file "$os" "$arch"; then
                    return 0
                else
                    print_warning "⚠ Local installation failed or was cancelled."
                    press_any_key
                    return 1
                fi
                ;;
            3)
                print_info "Starting alternative source download..."
                local os=$(uname -s | tr '[:upper:]' '[:lower:]')
                local arch=$(uname -m)
                case $arch in
                    x86_64) arch="amd64" ;;
                    aarch64) arch="arm64" ;;
                    *) print_error "✗ Unsupported architecture: $arch"; press_any_key; return 1 ;;
                esac
                if download_from_alternative_source "$os" "$arch"; then
                    return 0
                else
                    print_warning "⚠ Alternative installation failed or was cancelled."
                    press_any_key
                    return 1
                fi
                ;;
            4)
                test_network_connectivity
                installation_wizard
                return 0
                ;;
            5)
                print_warning "⚠ Skipping binary installation."
                print_info "You can install the binary manually later using option 3 in the main menu."
                print_info "Make sure to place it at: $BIN_PATH"
                press_any_key
                return 0
                ;;
            \?)
                show_installation_help
                installation_wizard
                return 0
                ;;
            0)
                print_info "Exiting EasyBackhaul installer."
                exit 0
                ;;
            *)
                print_warning "❌ Invalid option. Please enter 0-5 or ? for help."
                press_any_key
                ;;
        esac
    done
}

# Show installation-specific help
show_installation_help() {
    clear
    print_server_info_banner_minimal
    print_info "--- Installation Help ---"
    echo
    print_info "Installation Methods:"
    echo
    echo "1. Automatic GitHub Download:"
    echo "   - Best for most users with internet access"
    echo "   - Automatically tests connectivity and provides fallbacks"
    echo "   - Downloads the latest stable version"
    echo
    echo "2. Local File Installation:"
    echo "   - Use when you have the binary file locally"
    echo "   - Download from: https://github.com/Musixal/Backhaul/releases"
    echo "   - Look for: backhaul_linux_amd64.tar.gz (or arm64)"
    echo
    echo "3. Alternative Download Source:"
    echo "   - Use when GitHub is blocked or inaccessible"
    echo "   - Provide URL to your own server or mirror"
    echo "   - Must point to a .tar.gz file containing the binary"
    echo
    echo "4. Network Diagnostics:"
    echo "   - Test connectivity to various sources"
    echo "   - Help identify network issues"
    echo "   - Useful for troubleshooting"
    echo
    echo "5. Skip Installation:"
    echo "   - Continue without binary (advanced users)"
    echo "   - Install manually later if needed"
    echo
    print_info "System Requirements:"
    echo "- Linux system (x86_64 or aarch64)"
    echo "- Root/sudo access"
    echo "- Internet connection (for automatic download)"
    echo "- Basic system tools (curl, wget, tar, etc.)"
    echo
    press_any_key
}

# --- System Health & Performance Monitor ---
show_system_health_monitor() {
    clear
    print_server_info_banner_minimal
    print_info "=== System Health & Performance Monitor ==="
    echo
    
    # Initialize logging if not already done
    init_logging
    
    # Check system resources
    print_info "--- System Resources ---"
    check_system_resources
    
    # Check all tunnels health
    echo
    print_info "--- Tunnel Health Status ---"
    local tunnels
    tunnels=$(find "$CONFIG_DIR" -name "*.conf" -exec basename {} .conf \; 2>/dev/null)
    
    if [[ -n "$tunnels" ]]; then
        local healthy_count=0
        local total_count=0
        
        for tunnel in $tunnels; do
            local health_status
            health_status=$(check_tunnel_health "$tunnel")
            ((total_count++))
            
            case "$health_status" in
                "running")
                    print_success "✓ $tunnel: Running"
                    ((healthy_count++))
                    ;;
                "dead")
                    print_error "✗ $tunnel: Dead"
                    ;;
                "not_started")
                    print_warning "⚠ $tunnel: Not Started"
                    ;;
                *)
                    print_warning "? $tunnel: Unknown"
                    ;;
            esac
        done
        
        echo
        print_info "Health Summary: $healthy_count/$total_count tunnels healthy"
        
        if [[ $healthy_count -eq $total_count ]]; then
            print_success "✓ All tunnels are healthy!"
        elif [[ $healthy_count -eq 0 ]]; then
            print_error "✗ No tunnels are healthy!"
        else
            print_warning "⚠ Some tunnels need attention"
        fi
    else
        print_warning "⚠ No tunnels found"
    fi
    
    # Show performance metrics
    echo
    print_info "--- Performance Metrics ---"
    if [[ -f "$PERFORMANCE_LOG_FILE" ]]; then
        local recent_ops
        recent_ops=$(tail -n 10 "$PERFORMANCE_LOG_FILE" 2>/dev/null)
        if [[ -n "$recent_ops" ]]; then
            echo "Recent operations:"
            echo "$recent_ops" | while IFS= read -r line; do
                if [[ "$line" =~ \"operation\":\"([^\"]+)\",\"duration\":([0-9]+),\"success\":(true|false) ]]; then
                    local op="${BASH_REMATCH[1]}"
                    local duration="${BASH_REMATCH[2]}"
                    local success="${BASH_REMATCH[3]}"
                    local status_icon=$([[ "$success" == "true" ]] && echo "✓" || echo "✗")
                    echo "  $status_icon $op: ${duration}s"
                fi
            done
        else
            echo "No performance data available"
        fi
    else
        echo "No performance data available"
    fi
    
    # Show system services status
    echo
    print_info "--- System Services ---"
    local backhaul_services
    backhaul_services=$(systemctl list-unit-files --type=service 'backhaul-*.service' --no-legend | awk '{print $1}' | grep -v 'backhaul-watcher-')
    
    if [[ -n "$backhaul_services" ]]; then
        for service in $backhaul_services; do
            if systemctl is-active --quiet "$service"; then
                print_success "✓ $service: Active"
            else
                print_error "✗ $service: Inactive"
            fi
        done
    else
        print_warning "⚠ No Backhaul services found"
    fi
    
    # Show watcher status
    echo
    print_info "--- Watcher Status ---"
    local watcher_pid_files
    watcher_pid_files=$(find /tmp -name "backhaul-watcher-*.pid" 2>/dev/null)
    
    if [[ -n "$watcher_pid_files" ]]; then
        for pid_file in $watcher_pid_files; do
            local tunnel_name
            tunnel_name=$(basename "$pid_file" .pid | sed 's/backhaul-watcher-//')
            local pid
            pid=$(cat "$pid_file" 2>/dev/null)
            
            if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
                print_success "✓ Watcher for $tunnel_name: Running (PID: $pid)"
            else
                print_error "✗ Watcher for $tunnel_name: Dead"
            fi
        done
    else
        print_warning "⚠ No watchers found"
    fi
    
    # Show disk usage
    echo
    print_info "--- Disk Usage ---"
    local disk_usage
    disk_usage=$(df -h / | awk 'NR==2 {print $5}')
    local usage_percent
    usage_percent=$(echo "$disk_usage" | sed 's/%//')
    
    if [[ $usage_percent -gt 90 ]]; then
        print_error "✗ Critical disk usage: $disk_usage"
    elif [[ $usage_percent -gt 80 ]]; then
        print_warning "⚠ High disk usage: $disk_usage"
    else
        print_success "✓ Disk usage: $disk_usage"
    fi
    
    # Show log file sizes
    echo
    print_info "--- Log Files ---"
    if [[ -d "$LOG_DIR" ]]; then
        local log_files
        log_files=$(find "$LOG_DIR" -name "*.log" -type f 2>/dev/null)
        if [[ -n "$log_files" ]]; then
            for log_file in $log_files; do
                local size
                size=$(du -h "$log_file" 2>/dev/null | cut -f1)
                local filename
                filename=$(basename "$log_file")
                echo "  $filename: $size"
            done
        else
            echo "No log files found"
        fi
    else
        echo "Log directory not found"
    fi
    
    # Action menu
    echo
    print_info "--- Actions ---"
    echo " 1. Refresh health status"
    echo " 2. Clean up zombie processes"
    echo " 3. View detailed logs"
    echo " 4. Optimize all tunnel processes"
    echo " 0. Back to main menu"
    echo
    print_info "----------------------------------------------------------------"
    while true; do
        read -p "Select action [0-4]: " action_choice
        case $action_choice in
            1)
                show_system_health_monitor
                ;;
            2)
                cleanup_zombie_processes
                print_success "✓ Zombie processes cleaned up"
                press_any_key
                show_system_health_monitor
                ;;
            3)
                if [[ -d "$LOG_DIR" ]]; then
                    clear
                    print_info "=== Log Files ==="
                    echo
                    local log_files
                    log_files=$(find "$LOG_DIR" -name "*.log" -type f 2>/dev/null)
                    if [[ -n "$log_files" ]]; then
                        local i=1
                        for log_file in $log_files; do
                            echo " $i. $(basename "$log_file")"
                            ((i++))
                        done
                        echo " 0. Back"
                        echo
                        while true; do
                            read -p "Select log file to view [0-$((i-1))]: " log_choice
                            if [[ "$log_choice" == "0" ]]; then
                                break
                            elif [[ "$log_choice" =~ ^[1-9][0-9]*$ ]] && [[ $log_choice -lt $i ]]; then
                                local selected_log
                                selected_log=$(echo "$log_files" | sed -n "${log_choice}p")
                                if [[ -f "$selected_log" ]]; then
                                    clear
                                    print_info "=== $(basename "$selected_log") ==="
                                    echo
                                    if command -v less >/dev/null 2>&1; then
                                        less "$selected_log"
                                    else
                                        cat "$selected_log"
                                    fi
                                fi
                                break
                            else
                                print_warning "❌ Invalid option. Please enter 0-$((i-1))."
                                press_any_key
                            fi
                        done
                    else
                        print_warning "⚠ No log files found"
                        press_any_key
                    fi
                else
                    print_warning "⚠ Log directory not found"
                    press_any_key
                fi
                show_system_health_monitor
                ;;
            4)
                print_info "Optimizing all tunnel processes..."
                optimize_all_tunnel_processes
                print_success "✓ All tunnel processes optimized"
                press_any_key
                show_system_health_monitor
                ;;
            0)
                return
                ;;

            *)
                print_warning "❌ Invalid option. Please enter 0-4."
                press_any_key
                ;;
        esac
    done
}

# --- Main Menu Logic & Entrypoint ---
main_menu() {
    clear
    print_server_info_banner
    print_info "      EasyBackhaul Installer & Management Menu (v13.0-beta)"
    print_info "================================================================"
    print_info "  Core by Musixal  |  Installer by @N4Xon"
    print_info "----------------------------------------------------------------"
    
    # Show binary status
    if [[ -f "$BIN_PATH" ]]; then
        # Check if binary is executable
        if [[ ! -x "$BIN_PATH" ]]; then
            print_warning "⚠ Binary Status: Found but not executable"
        else
            # Try to get version, but don't fail if it doesn't work
            local version_output=""
            if "$BIN_PATH" -v >/dev/null 2>&1; then
                version_output=$("$BIN_PATH" -v 2>/dev/null | head -n1)
            elif "$BIN_PATH" --version >/dev/null 2>&1; then
                version_output=$("$BIN_PATH" --version 2>/dev/null | head -n1)
            fi
            
            # Check if any backhaul services are running
            local running_services
            running_services=$(systemctl list-units --type=service --state=running | grep -c "backhaul-" 2>/dev/null || echo "0")
            
            if [[ "$running_services" -gt 0 ]]; then
                if [[ -n "$version_output" ]]; then
                    print_success "✓ Binary Status: $version_output (Services: $running_services running)"
                else
                    print_success "✓ Binary Status: Found and working (Services: $running_services running)"
                fi
            else
                if [[ -n "$version_output" ]]; then
                    print_success "✓ Binary Status: $version_output (No services running)"
                else
                    print_success "✓ Binary Status: Found and executable (No services running)"
                fi
            fi
        fi
    else
        print_error "✗ Binary Status: Not installed"
    fi
    echo
    
    while true; do
        echo
        echo " 1. Configure a New Tunnel"
        echo " 2. Manage Existing Tunnels"
        echo " 3. Update/Re-install Backhaul Binary"
        echo " 4. Generate Self-Signed TLS Certificate"
        echo " 5. Select Backhaul Binary Directory (current: $BIN_PATH)"
        echo " 6. System Health & Performance Monitor"
        echo " 7. Clean Up Zombie/Orphaned Processes"
        echo " 8. Uninstall EasyBackhaul (Removes binary and ALL configs)"
        echo
        print_info "----------------------------------------------------------------"
        echo " ?. Help"
        echo " 0. Exit"
        echo
        read -p "Please select an option [0-8, ? for help]: " choice
        case $choice in
            1) configure_new_tunnel; press_any_key ;;
            2) manage_tunnels ;;
            3) download_backhaul; press_any_key ;;
            4) generate_self_signed_cert; press_any_key ;;
            5)
               read -e -p "Enter the full path for the Backhaul binary (e.g., /usr/local/bin/backhaul): " new_bin_path
               if [[ -n "$new_bin_path" ]]; then
                   BIN_PATH="$new_bin_path"
                   print_success "✓ Backhaul binary path set to: $BIN_PATH (for this session)"
               else
                   print_warning "⚠ No path entered. Keeping current: $BIN_PATH"
               fi
               press_any_key
               ;;
            6)
               show_system_health_monitor
               press_any_key
               ;;
            7)
               clear
               print_server_info_banner_minimal
               print_info "--- Clean Up Zombie/Orphaned Processes ---"
               echo
               print_info "This will clean up any zombie processes and orphaned watcher processes."
               echo
               cleanup_zombie_processes
               press_any_key
               ;;
            8)
               read -p "This will REMOVE the binary and ALL configs/services. This is irreversible. Are you sure? [y/N]: " confirm
               if [[ "${confirm,,}" == "y" ]]; then
                    echo
                    print_warning "Summary of what will be deleted:"
                    echo "  - Backhaul binary: $BIN_PATH"
                    echo "  - All configs: $CONFIG_DIR"
                    echo "  - All backups: $BACKUP_DIR"
                    echo "  - All systemd services: $SERVICE_DIR/backhaul-*.service"
                    echo "  - All watcher scripts, logs, and PID files in /tmp/"
                    echo "  - All UFW rules and metadata: $UFW_METADATA_FILE"
                    echo "  - All cron jobs managed by EasyBackhaul"
                    echo
                    read -p "Type DELETE to confirm: " really_delete
                    if [[ "$really_delete" != "DELETE" ]]; then
                        print_warning "❌ Uninstall cancelled. Nothing was deleted."
                        press_any_key
                        return
                    fi
                    
                    print_warning "Stopping and disabling all backhaul services..."
                    systemctl stop backhaul-*.service &>/dev/null
                    systemctl disable backhaul-*.service &>/dev/null
                    
                    # Clean up all watcher processes and files with robust termination
                    print_warning "Cleaning up all watcher processes and files..."
                    for pid_file in /tmp/backhaul-watcher-*.pid; do
                        if [[ -f "$pid_file" ]]; then
                            local watcher_pid=$(cat "$pid_file")
                            if [[ -n "$watcher_pid" ]]; then
                                print_info "Stopping watcher process (PID: $watcher_pid)..."
                                
                                # Try graceful termination first
                                kill "$watcher_pid" 2>/dev/null
                                
                                # Wait up to 5 seconds for graceful shutdown
                                local count=0
                                while kill -0 "$watcher_pid" 2>/dev/null && [[ $count -lt 5 ]]; do
                                    sleep 1
                                    ((count++))
                                done
                                
                                # If still running, force kill
                                if kill -0 "$watcher_pid" 2>/dev/null; then
                                    print_warning "Process not responding to SIGTERM, forcing termination..."
                                    kill -9 "$watcher_pid" 2>/dev/null
                                    sleep 1
                                fi
                                
                                # Verify process is dead
                                if kill -0 "$watcher_pid" 2>/dev/null; then
                                    print_error "Failed to terminate watcher process (PID: $watcher_pid)"
                                else
                                    print_success "Watcher process terminated successfully"
                                fi
                            fi
                            rm -f "$pid_file"
                        fi
                    done
                    
                    # Kill any remaining watcher processes by pattern
                    pkill -f "backhaul-watcher" 2>/dev/null
                    
                    # Remove all watcher scripts and logs
                    rm -f /tmp/backhaul-watcher-*.sh
                    rm -f /tmp/backhaul-watcher-*.log
                    rm -f /tmp/restart_ack_*
                    print_info "Removed all watcher scripts, logs, and temporary files"
                    
                    print_warning "Removing all related files..."
                    rm -f "$BIN_PATH"
                    rm -rf "$CONFIG_DIR"
                    rm -rf "$BACKUP_DIR"
                    rm -f "$SERVICE_DIR"/backhaul-*.service
                    rm -f "$UFW_METADATA_FILE"
                    (crontab -l 2>/dev/null | grep -v "$CRON_COMMENT_TAG") | crontab -
                    systemctl daemon-reload
                    
                    # Clean up UFW rules
                    if command -v ufw >/dev/null 2>&1; then
                        print_info "Cleaning up UFW rules..."
                        # Remove all backhaul-related UFW rules
                        ufw status numbered | grep -E "(backhaul|45680|45690)" | awk '{print $1}' | tac | while read -r rule_num; do
                            if [[ -n "$rule_num" ]]; then
                                echo "y" | ufw delete "$rule_num" >/dev/null 2>&1
                            fi
                        done
                    fi
                    
                    # Cert removal prompt
                    local CERT_DIR="/etc/backhaul/certs"
                    if [ -d "$CERT_DIR" ] && compgen -G "$CERT_DIR/*.crt" > /dev/null; then
                        read -p "Do you also want to delete all TLS certificates in $CERT_DIR? (y/n): " delcerts
                        if [[ "${delcerts,,}" == "y" ]]; then
                            rm -rf "$CERT_DIR"
                            print_success "All certificates in $CERT_DIR have been deleted."
                        else
                            print_info "Certificates in $CERT_DIR have been preserved."
                        fi
                    fi
                    
                    # Run zombie cleanup
                    cleanup_zombie_processes
                    
                    print_success "✓ EasyBackhaul has been completely uninstalled (including all watchers and related files)."
                    exit 0
               fi
               press_any_key
               ;;
            \?) show_help; press_any_key ;;
            0) exit 0 ;;
            *) print_warning "❌ Invalid option. Please enter 0-8 or ? for help."; press_any_key ;;
        esac
    done
}

# --- Script Entrypoint ---
get_server_info
check_root
check_dependencies
mkdir -p "$CONFIG_DIR" "$BACKUP_DIR"

# Initialize enhanced logging system
init_logging

# Check if binary exists, if not run installation wizard
if [ ! -f "$BIN_PATH" ]; then
    echo
    print_warning "⚠ Backhaul binary not found at: $BIN_PATH"
    echo
    print_info "The Backhaul binary is required to create and manage tunnels."
    print_info "Please complete the installation to continue."
    echo
    print_info "Press any key to start the installation wizard..."
    press_any_key
    
    # Run installation wizard
    installation_wizard
    
    # Check if installation was successful
    if [ ! -f "$BIN_PATH" ]; then
        echo
        print_warning "⚠ Binary installation was not completed."
        print_info "You can still use the script to manage existing tunnels or install later."
        echo
        print_info "To install the binary later, use option 3 in the main menu."
        print_info "Press any key to continue to the main menu..."
        press_any_key
    fi
fi

while true; do
    main_menu
done 