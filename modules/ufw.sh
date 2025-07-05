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
        read -p "Do you want to enable UFW and add the required rules? (y/n): " enable_ufw
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
    
    # Input validation
    if ! validate_ip "$server_ip" || ! validate_port "$server_port" || ! validate_port "$local_port"; then
        log_message "ERROR" "Invalid UFW rule parameters for tunnel $tunnel_name"
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

manage_ufw() {
    # Check if UFW is available
    if ! command -v ufw >/dev/null 2>&1; then
        print_error "UFW is not installed on this system."
        print_info "To install UFW: sudo apt-get install ufw (Ubuntu/Debian) or sudo yum install ufw (CentOS/RHEL)"
        press_any_key
        return
    fi

    # Help function for UFW menu
    ufw_menu_help() {
        clear
        print_server_info_banner_minimal
        print_info "================= UFW Firewall Management Help ================="
        echo
        echo "UFW (Uncomplicated Firewall) is a frontend for iptables."
        echo "This menu helps you manage firewall rules for EasyBackhaul tunnels."
        echo
        echo "Available options:"
        echo "  • View all UFW rules: See all firewall rules (system-wide)"
        echo "  • View EasyBackhaul rules: See only rules created by this script"
        echo "  • Enable UFW: Turn on the firewall (requires SSH access)"
        echo "  • Disable UFW: Turn off the firewall (security risk)"
        echo "  • Reset UFW rules: Remove all rules and reset to default"
        echo "  • Security audit: Check for security issues in rules"
        echo
        echo "Note: Enabling UFW may block SSH access if not configured properly."
        echo "Make sure you have alternative access before enabling UFW."
        echo "================================================================"
        press_any_key
    }

    while true; do
        clear
        print_server_info_banner_minimal
        print_info "--- UFW Firewall Management ---"
        
        # Show UFW status
        local ufw_status
        ufw_status=$(ufw status 2>/dev/null | head -1)
        if [[ "$ufw_status" == *"Status: active"* ]]; then
            print_success "UFW Status: Active"
        else
            print_warning "UFW Status: Inactive"
        fi
        
        echo
        print_info "Select an option:"
        echo " 1. View All UFW Rules"
        echo " 2. View EasyBackhaul Rules"
        echo " 3. Enable UFW"
        echo " 4. Disable UFW"
        echo " 5. Reset UFW Rules"
        echo " 6. Security Audit"
        echo
        print_info "----------------------------------------------------------------"
        echo " ?. Help"
        echo " 0. Back"
        echo
        
        menu_loop 0 6 "?" "ufw_menu_help" "Enter choice [0-6, ? for help]"
        
        case $choice in
            1)
                print_info "--- All UFW Rules ---"
                ufw status numbered
                press_any_key
                ;;
            2)
                print_info "--- EasyBackhaul UFW Rules ---"
                if [ -f "$UFW_METADATA_FILE" ]; then
                    echo "Rules created by EasyBackhaul:"
                    cat "$UFW_METADATA_FILE"
                else
                    print_warning "No EasyBackhaul UFW rules found."
                fi
                press_any_key
                ;;
            3)
                print_warning "⚠ Enabling UFW may block SSH access if not configured properly."
                print_info "Make sure you have alternative access before proceeding."
                if confirm_action "Proceed with enabling UFW?" "n"; then
                    with_spinner "Enabling UFW" ufw --force enable
                    if [ $? -eq 0 ]; then
                                    print_success "UFW enabled successfully."
        else
            print_error "Failed to enable UFW."
        fi
                fi
                press_any_key
                ;;
            4)
                print_warning "Disabling UFW removes firewall protection."
                if confirm_action "Are you sure you want to disable UFW?" "n"; then
                    with_spinner "Disabling UFW" ufw disable
                    if [ $? -eq 0 ]; then
                                    print_success "UFW disabled successfully."
        else
            print_error "Failed to disable UFW."
        fi
                fi
                press_any_key
                ;;
            5)
                print_warning "This will remove ALL UFW rules and reset to default."
                print_info "This action cannot be undone."
                echo
                print_info "Type 'RESET' to confirm: "
                read -p "" fix_choice
                if [[ "$fix_choice" == "RESET" ]]; then
                    with_spinner "Resetting UFW rules" ufw --force reset
                    if [ $? -eq 0 ]; then
                        print_success "UFW rules reset successfully."
                        # Remove EasyBackhaul metadata file
                        rm -f "$UFW_METADATA_FILE"
                        print_info "EasyBackhaul UFW metadata cleared."
                    else
                        print_error "Failed to reset UFW rules."
                    fi
                else
                    print_info "Reset cancelled."
                fi
                press_any_key
                ;;
            6)
                print_info "--- UFW Security Audit ---"
                echo "Checking for potential security issues..."
                echo
                
                # Check if UFW is active
                if ! ufw status | grep -q "Status: active"; then
                    print_warning "UFW is not active - no firewall protection"
                else
                    print_success "UFW is active"
                fi
                
                # Check for SSH rule
                if ufw status | grep -q "22/tcp"; then
                    print_success "SSH (port 22) rule found"
                else
                    print_warning "No SSH rule found - may block SSH access"
                fi
                
                # Check for overly permissive rules
                if ufw status | grep -q "ALLOW.*anywhere"; then
                    print_warning "Found overly permissive rule (ALLOW anywhere)"
                fi
                
                # Check EasyBackhaul rules
                if [ -f "$UFW_METADATA_FILE" ]; then
                    echo
                    print_info "EasyBackhaul rules:"
                    cat "$UFW_METADATA_FILE"
                fi
                
                press_any_key
                ;;
            0) return ;;
        esac
    done
}

view_all_ufw_rules() {
    clear
    echo ""
    echo "=== All UFW Rules ==="
    ufw status numbered
    press_any_key
}

view_easybackhaul_rules() {
    clear
    echo ""
    echo "=== EasyBackhaul UFW Rules ==="
    ufw status numbered | grep -E "(EasyBackhaul|easybackhaul)" || echo "No EasyBackhaul rules found"
    press_any_key
}

enable_ufw() {
    clear
    echo ""
    echo "=== Enable UFW ==="
    
    if ufw status | grep -q "Status: active"; then
        echo "✅ UFW is already active"
        press_any_key
        return
    fi
    
    echo "⚠ This will enable UFW firewall. Make sure you have SSH access configured."
    read -p "Proceed? [y/N]: " choice
    
    if [ "$choice" = "y" ]; then
        ufw --force enable
        echo "✅ UFW enabled successfully"
        secure_log_message "INFO" "UFW firewall enabled"
    else
        echo "❌ UFW enable cancelled"
    fi
    press_any_key
}

disable_ufw() {
    clear
    echo ""
    echo "=== Disable UFW ==="
    
    if ! ufw status | grep -q "Status: active"; then
        echo "⚠ UFW is not active"
        press_any_key
        return
    fi
    
    echo "⚠ WARNING: Disabling UFW will remove firewall protection."
    read -p "Are you sure? [y/N]: " choice
    
    if [ "$choice" = "y" ]; then
        ufw disable
        echo "✅ UFW disabled"
        secure_log_message "WARNING" "UFW firewall disabled"
    else
        echo "❌ UFW disable cancelled"
    fi
    press_any_key
}

reset_ufw_rules() {
    clear
    echo ""
    echo "=== Reset UFW Rules ==="
    
    echo "⚠ WARNING: This will remove ALL UFW rules and reset to default."
    echo "   This action cannot be undone."
    read -p "Type 'RESET' to confirm: " confirmation
    
    if [ "$confirmation" = "RESET" ]; then
        ufw --force reset
        echo "✅ UFW rules reset to default"
        secure_log_message "WARNING" "UFW rules reset to default"
    else
        echo "❌ UFW reset cancelled"
    fi
    press_any_key
}

audit_ufw_rules() {
    echo ""
    echo "=== UFW Security Audit ==="
    
    local issues=0
    
    # Check if UFW is active
    if ! ufw status | grep -q "Status: active"; then
        echo "❌ UFW is not active - no firewall protection"
        ((issues++))
    else
        echo "✅ UFW is active"
    fi
    
    # Check for overly permissive rules
    local permissive_rules=$(ufw status | grep -E "(allow.*any|allow.*0\.0\.0\.0)" | wc -l)
    if [ "$permissive_rules" -gt 0 ]; then
        echo "⚠ Found $permissive_rules potentially permissive rules"
        ((issues++))
    fi
    
    # Check EasyBackhaul rules
    local easybackhaul_rules=$(ufw status | grep -c "EasyBackhaul")
    echo "📊 EasyBackhaul rules: $easybackhaul_rules"
    
    # Check for orphaned rules (rules without corresponding tunnels)
    local orphaned_rules=0
    for rule in $(ufw status | grep "EasyBackhaul tunnel" | awk '{print $NF}'); do
        local tunnel_name=$(echo "$rule" | sed 's/EasyBackhaul tunnel //')
        if [ ! -d "$TUNNEL_DIR/$tunnel_name" ]; then
            echo "⚠ Orphaned UFW rule for non-existent tunnel: $tunnel_name"
            ((orphaned_rules++))
            ((issues++))
        fi
    done
    
    if [ $issues -eq 0 ]; then
        echo "✅ UFW security audit passed"
    else
        echo ""
        echo "🔧 Fix issues? (y/n): "
        read -p "" fix_choice
        if [ "$fix_choice" = "y" ]; then
            fix_ufw_issues
        fi
    fi
}

fix_ufw_issues() {
    echo ""
    echo "=== Fixing UFW Issues ==="
    
    # Remove orphaned rules
    for rule in $(ufw status | grep "EasyBackhaul tunnel" | awk '{print $NF}'); do
        local tunnel_name=$(echo "$rule" | sed 's/EasyBackhaul tunnel //')
        if [ ! -d "$TUNNEL_DIR/$tunnel_name" ]; then
            echo "🧹 Removing orphaned rule for tunnel: $tunnel_name"
            remove_ufw_rules "$tunnel_name"
        fi
    done
    
    # Enable UFW if not active
    if ! ufw status | grep -q "Status: active"; then
        echo "🔒 Enabling UFW..."
        ufw --force enable
    fi
    
    echo "✅ UFW issues fixed"
} 