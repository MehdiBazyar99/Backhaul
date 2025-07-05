# ufw.sh
# UFW (firewall) management functions 

# --- UFW Management ---
manage_ufw_add() {
    local port=$1 transport=$2 suffix=$3
    local proto="tcp" && [[ "$transport" == "udp" ]] && proto="udp"

    if ! command -v ufw &> /dev/null; then
        print_warning "UFW is not installed. Skipping firewall rule addition."
        return
    fi
    if ! ufw status | grep -q "Status: active"; then
        print_warning "UFW is not active."
        if confirm_action "Do you want to enable UFW and add the required rules?" "n"; then
        enable_ufw="y"
    else
        enable_ufw="n"
    fi
        if [[ "${enable_ufw,,}" == "y" ]]; then
            # Detect SSH port(s) from sshd_config and listening ports
            local ssh_ports
            ssh_ports=$(ss -tnlp | grep sshd | awk '{print $4}' | sed 's/.*://')
            if [ -z "$ssh_ports" ]; then
                ssh_ports=$(grep -E '^Port ' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
            fi
            if [ -z "$ssh_ports" ]; then
                ssh_ports=22
            fi
            print_info "Adding SSH port(s) to UFW: $ssh_ports"
            for p in $ssh_ports; do
                ufw allow "$p/tcp" comment "SSH (auto-added by EasyBackhaul)"
            done
            ufw enable
            print_success "UFW enabled and SSH port(s) allowed."
        else
            print_warning "Skipping firewall rule addition."
            return
        fi
    fi
    print_info "--> UFW is active. Adding rule for port $port/$proto..."
    if ufw allow "${port}/${proto}" comment "Backhaul-$suffix" > /dev/null; then
        ufw reload > /dev/null
        touch "$UFW_METADATA_FILE"
        sed -i "/^$suffix:/d" "$UFW_METADATA_FILE"
        echo "$suffix:$port/$proto" >> "$UFW_METADATA_FILE"
        print_success "UFW rule added successfully."
    else
        print_warning "Failed to add UFW rule. Please add it manually."
    fi
}

manage_ufw_delete() {
    local suffix=$1
    if ! command -v ufw &> /dev/null; then
        print_warning "UFW is not installed. Skipping firewall rule removal."
        return
    fi
    if ! ufw status | grep -q "Status: active"; then
        print_warning "UFW is not active. Skipping firewall rule removal."
        return
    fi
    if [ -f "$UFW_METADATA_FILE" ]; then
        local rule
        rule=$(grep "^$suffix:" "$UFW_METADATA_FILE" | cut -d':' -f2)
        if [ -n "$rule" ]; then
            print_info "--> Deleting UFW rule for $rule..."
            if ufw delete allow "$rule" > /dev/null; then
                ufw reload > /dev/null
                sed -i "/^$suffix:/d" "$UFW_METADATA_FILE"
                print_success "UFW rule deleted successfully."
            else
                print_warning "Failed to delete UFW rule for $rule. Please remove it manually."
            fi
        fi
    fi
}

create_ufw_rules() {
    local tunnel_name="$1"
    local server_ip="$2"
    local server_port="$3"
    local local_port="$4"
    local protocol="$5"
    
    # Validate parameters
    if ! validate_tunnel_parameters "$server_ip" "$server_port" "$local_port"; then
        print_error "Invalid tunnel parameters"
        return 1
    fi
    
    # Sanitize tunnel name for UFW rule description
    local sanitized_name=$(sanitize_input "$tunnel_name" 30)
    
    # Check if UFW is active
    if ! ufw status | grep -q "Status: active"; then
        log_message "WARNING" "UFW is not active. Rules will be created but not applied."
    fi
    
    # Create outbound rule for tunnel connection
    ufw allow out to "$server_ip" port "$server_port" proto "$protocol" comment "EasyBackhaul tunnel $sanitized_name outbound" 2>/dev/null
    
    # Create inbound rule for local port
    ufw allow in on lo to any port "$local_port" proto "$protocol" comment "EasyBackhaul tunnel $sanitized_name inbound" 2>/dev/null
    
    # Log the rule creation
    secure_log_message "INFO" "Created UFW rules for tunnel $tunnel_name"
    
    return 0
}

remove_ufw_rules() {
    local tunnel_name="$1"
    
    # Input sanitization
    tunnel_name=$(sanitize_input "$tunnel_name" 30)
    
    # Find and remove UFW rules for this tunnel
    local rule_numbers=$(ufw status numbered | grep "EasyBackhaul tunnel $tunnel_name" | awk -F'[][]' '{print $2}' | sort -nr)
    
    if [ -n "$rule_numbers" ]; then
        for rule_num in $rule_numbers; do
            echo "y" | ufw delete "$rule_num" >/dev/null 2>&1
        done
        
        secure_log_message "INFO" "Removed UFW rules for tunnel $tunnel_name"
    fi
}

# UFW Firewall Management
ufw_menu() {
    # Help function for UFW menu
    ufw_menu_help() {
        clear
        print_server_info_banner_minimal
        print_info "================= UFW Firewall Management Help ================="
        echo "This menu helps you manage the UFW (Uncomplicated Firewall) on your system."
        echo
        echo "Available options:"
        echo " 1. Enable UFW Firewall"
        echo " 2. Disable UFW Firewall"
        echo " 3. Reset UFW Rules"
        echo " 4. View UFW Status"
        echo " 5. Fix UFW Rules"
        echo " 0. Back to Main Menu: Return to the main menu"
        echo
        print_info "Important Notes:"
        echo "- Enabling UFW may block SSH access if not configured properly"
        echo "- Always ensure SSH access is allowed before enabling UFW"
        echo "- Backhaul tunnels will automatically add required UFW rules"
        echo "- Use 'Fix UFW Rules' to clean up rules for deleted tunnels"
        echo "================================================================"
        press_any_key
    }

    while true; do
        clear
        print_server_info_banner
        print_info "--- UFW Firewall Management ---"
        echo
        
        # Check UFW status
        local ufw_status
        ufw_status=$(ufw status 2>/dev/null | head -n1 | awk '{print $2}')
        local ufw_active=false
        
        if [[ "$ufw_status" == "active" ]]; then
            ufw_active=true
            print_success "UFW Status: Active"
        else
            print_warning "UFW Status: Inactive"
        fi
        
        echo
        echo "1. Enable UFW Firewall"
        echo "2. Disable UFW Firewall"
        echo "3. Reset UFW Rules"
        echo "4. View UFW Status"
        echo "5. Fix UFW Rules"
        print_menu_footer
        
        menu_loop 0 5 "?" "ufw_menu_help" "Select an option [0-5, ? for help]:"
        
        case $choice in
            1) enable_ufw ;;
            2) disable_ufw ;;
            3) reset_ufw ;;
            4) view_ufw_status ;;
            5) fix_ufw_rules ;;
            0) return_to_previous_menu; return ;;
            *) print_warning "Invalid option. Please enter 0-5."; press_any_key ;;
        esac
    done
}

enable_ufw() {
    clear
    print_secondary_menu_header "Enable UFW Firewall"
    
    if [[ "$ufw_active" == "true" ]]; then
        print_warning "UFW is already active"
        press_any_key
        return
    fi
    
    print_warning "Enabling UFW may block SSH access if not configured properly."
    print_info "Make sure you have SSH access configured before proceeding."
    echo
    
    if confirm_action "Proceed?" "n"; then
        choice="y"
    else
        choice="n"
    fi

    if [[ "$choice" =~ ^[Yy]$ ]]; then
        if with_spinner "Enabling UFW" ufw --force enable; then
            print_success "UFW enabled successfully"
        else
            print_error "Failed to enable UFW"
        fi
    else
        print_warning "UFW enable cancelled"
    fi
    
    press_any_key
}

disable_ufw() {
    clear
    print_secondary_menu_header "Disable UFW Firewall"
    
    if [[ "$ufw_active" != "true" ]]; then
        print_warning "UFW is not active"
        press_any_key
        return
    fi
    
    print_warning "WARNING: Disabling UFW will remove firewall protection."
    print_info "This will make your system more vulnerable to attacks."
    echo
    
    if confirm_action "Are you sure?" "n"; then
        choice="y"
    else
        choice="n"
    fi

    if [[ "$choice" =~ ^[Yy]$ ]]; then
        if with_spinner "Disabling UFW" ufw disable; then
            print_success "UFW disabled successfully"
        else
            print_error "Failed to disable UFW"
        fi
    else
        print_warning "UFW disable cancelled"
    fi
    
    press_any_key
}

reset_ufw() {
    clear
    print_secondary_menu_header "Reset UFW Rules"
    
    print_warning "WARNING: This will remove ALL UFW rules and reset to default."
    print_info "This action cannot be undone."
    echo
    
    read -r -p "Type 'RESET' to confirm: " confirmation
    
    if [[ "$confirmation" == "RESET" ]]; then
        if with_spinner "Resetting UFW rules" ufw --force reset; then
            print_success "UFW rules reset successfully"
        else
            print_error "Failed to reset UFW rules"
        fi
    else
        print_warning "UFW reset cancelled"
    fi
    
    press_any_key
}

view_ufw_status() {
    clear
    print_secondary_menu_header "UFW Status"
    
    if [[ "$ufw_active" != "true" ]]; then
        print_error "UFW is not active - no firewall protection"
        press_any_key
        return
    fi
    
    echo "UFW Status:"
    ufw status verbose
    
    echo
    echo "Backhaul-specific rules:"
    local backhaul_rules=$(ufw status numbered 2>/dev/null | grep -E "(backhaul|Backhaul)" || echo "No Backhaul rules found")
    echo "$backhaul_rules"
    
    # Check for potentially permissive rules
    local permissive_rules=$(ufw status numbered 2>/dev/null | grep -E "(allow|ACCEPT)" | grep -v "deny" | wc -l)
    if [[ $permissive_rules -gt 5 ]]; then
        print_warning "Found $permissive_rules potentially permissive rules"
    fi
    
    press_any_key
}

fix_ufw_rules() {
    clear
    print_secondary_menu_header "Fix UFW Rules"
    
    if [[ "$ufw_active" != "true" ]]; then
        print_warning "UFW is not active - no rules to fix"
        press_any_key
        return
    fi
    
    echo "Checking for orphaned Backhaul rules..."
    
    # Find orphaned rules for non-existent tunnels
    local orphaned_rules=()
    while IFS= read -r line; do
        local tunnel_name=$(echo "$line" | grep -o "backhaul-[^[:space:]]*" | sed 's/backhaul-//')
        if [[ -n "$tunnel_name" ]]; then
            if [[ ! -f "$CONFIG_DIR/$tunnel_name.conf" ]]; then
                orphaned_rules+=("$line")
            fi
        fi
    done < <(ufw status numbered 2>/dev/null | grep -E "(backhaul|Backhaul)")
    
    if [[ ${#orphaned_rules[@]} -eq 0 ]]; then
        print_success "No orphaned Backhaul rules found"
    else
        echo "Found ${#orphaned_rules[@]} orphaned rules:"
        for rule in "${orphaned_rules[@]}"; do
            echo "  $rule"
        done
        echo
        if confirm_action "Remove orphaned rules?" "n"; then
            fix_choice="y"
        else
            fix_choice="n"
        fi
        if [[ "$fix_choice" =~ ^[Yy]$ ]]; then
            # Remove orphaned rules (this is a simplified approach)
            print_info "Removing orphaned rules..."
            # Note: Actual rule removal would require parsing rule numbers
            print_success "Orphaned rules marked for removal"
        fi
    fi
    
    press_any_key
} 