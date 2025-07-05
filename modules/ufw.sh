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

ufw_menu() {
    clear
    echo "=== UFW Firewall Rules Management ==="
    echo ""
    
    # Check UFW status
    local ufw_status=$(ufw status | grep "Status:" | awk '{print $2}')
    echo "🔒 UFW Status: $ufw_status"
    echo ""
    
    echo "UFW Options:"
    echo "1) View all UFW rules"
    echo "2) View EasyBackhaul rules only"
    echo "3) Enable UFW"
    echo "4) Disable UFW"
    echo "5) Reset UFW rules"
    echo "6) Security audit UFW rules"
    echo "0) Back to main menu"
    
    read -p "Enter choice (0-6): " choice
    
    case $choice in
        0) return ;;
        1) view_all_ufw_rules ;;
        2) view_easybackhaul_rules ;;
        3) enable_ufw ;;
        4) disable_ufw ;;
        5) reset_ufw_rules ;;
        6) audit_ufw_rules ;;
        *) echo "❌ Invalid choice" ;;
    esac
}

view_all_ufw_rules() {
    echo ""
    echo "=== All UFW Rules ==="
    ufw status numbered
}

view_easybackhaul_rules() {
    echo ""
    echo "=== EasyBackhaul UFW Rules ==="
    ufw status numbered | grep -E "(EasyBackhaul|easybackhaul)" || echo "No EasyBackhaul rules found"
}

enable_ufw() {
    echo ""
    echo "=== Enable UFW ==="
    
    if ufw status | grep -q "Status: active"; then
        echo "✅ UFW is already active"
        return
    fi
    
    echo "⚠ This will enable UFW firewall. Make sure you have SSH access configured."
    read -p "Proceed? (y/n): " choice
    
    if [ "$choice" = "y" ]; then
        ufw --force enable
        echo "✅ UFW enabled successfully"
        secure_log_message "INFO" "UFW firewall enabled"
    else
        echo "❌ UFW enable cancelled"
    fi
}

disable_ufw() {
    echo ""
    echo "=== Disable UFW ==="
    
    if ! ufw status | grep -q "Status: active"; then
        echo "⚠ UFW is not active"
        return
    fi
    
    echo "⚠ WARNING: Disabling UFW will remove firewall protection."
    read -p "Are you sure? (y/n): " choice
    
    if [ "$choice" = "y" ]; then
        ufw --force disable
        echo "✅ UFW disabled"
        secure_log_message "WARNING" "UFW firewall disabled"
    else
        echo "❌ UFW disable cancelled"
    fi
}

reset_ufw_rules() {
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