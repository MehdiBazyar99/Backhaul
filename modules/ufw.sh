# modules/ufw.sh
# UFW (Uncomplicated Firewall) management functions.

# --- UFW Rule Management for Tunnels ---

# Adds a UFW rule for a specific tunnel port.
# Parameters:
#   $1: port - The port number.
#   $2: transport - "tcp" or "udp".
#   $3: tunnel_suffix - Unique identifier for the tunnel (e.g., server-tcp-timestamp).
#                       Used in the UFW rule comment for identification.
# This function is typically called when a new tunnel is configured.
add_ufw_rule_for_tunnel() {
    local port="$1"
    local transport_protocol="$2" # Should be "tcp" or "udp"
    local tunnel_suffix="$3"

    if ! command -v ufw &>/dev/null; then
        log_message "WARN" "UFW is not installed. Skipping firewall rule addition for port $port/$transport_protocol."
        return 1
    fi

    local ufw_status_output
    ufw_status_output=$(ufw status)
    if ! echo "$ufw_status_output" | grep -q "Status: active"; then
        log_message "WARN" "UFW is not active."
        if prompt_yes_no "UFW is inactive. Enable UFW and add required SSH/tunnel rules?" "n"; then
            _enable_ufw_with_ssh_allow # Call helper to enable UFW and allow SSH
        else
            log_message "WARN" "User chose not to enable UFW. Skipping firewall rule addition for port $port/$transport_protocol."
            return 1
        fi
    fi

    local ufw_comment="EasyBackhaul: tunnel-${tunnel_suffix}"
    log_message "INFO" "Adding UFW rule: allow $port/$transport_protocol (Comment: $ufw_comment)"

    if run_with_spinner "Adding UFW rule for port $port/$transport_protocol..." \
        ufw allow "$port/$transport_protocol" comment "$ufw_comment"; then
        if run_with_spinner "Reloading UFW..." ufw reload; then
            handle_success "UFW rule for port $port/$transport_protocol added and UFW reloaded."
            return 0
        else
            handle_error "ERROR" "Failed to reload UFW after adding rule for port $port/$transport_protocol."
            return 1
        fi
    else
        handle_error "ERROR" "Failed to add UFW rule for port $port/$transport_protocol. Please add it manually."
        return 1
    fi
}

# Deletes UFW rules associated with a specific tunnel suffix.
# Parameters:
#   $1: tunnel_suffix - Unique identifier for the tunnel.
# This function is typically called when a tunnel is deleted.
delete_ufw_rules_for_tunnel() {
    local tunnel_suffix="$1"

    if ! command -v ufw &>/dev/null; then
        log_message "WARN" "UFW is not installed. Skipping firewall rule removal for tunnel $tunnel_suffix."
        return 1
    fi
    
    local ufw_status_output
    ufw_status_output=$(ufw status)
    if ! echo "$ufw_status_output" | grep -q "Status: active"; then
        log_message "INFO" "UFW is not active. No rules to remove for tunnel $tunnel_suffix."
        return 0
    fi

    local ufw_comment_pattern="EasyBackhaul: tunnel-${tunnel_suffix}"
    log_message "INFO" "Searching for UFW rules to delete with comment pattern: '$ufw_comment_pattern'"

    local rules_deleted_count=0
    # Loop to delete rules by number, as rule numbers change after each deletion.
    # We get all matching rules, sort them in reverse order, and delete.
    while true; do
        local rule_to_delete_num
        # Get the highest rule number that matches the comment
        rule_to_delete_num=$(ufw status numbered | grep -F "$ufw_comment_pattern" | head -n 1 | awk -F'[][]' '{print $2}')
        
        if [[ -z "$rule_to_delete_num" ]]; then
            break # No more rules found with this comment
        fi

        log_message "INFO" "Deleting UFW rule #$rule_to_delete_num (comment: $ufw_comment_pattern)"
        if echo "y" | ufw delete "$rule_to_delete_num"; then # Auto-confirm deletion
            log_message "DEBUG" "Successfully deleted UFW rule #$rule_to_delete_num."
            ((rules_deleted_count++))
        else
            handle_error "ERROR" "Failed to delete UFW rule #$rule_to_delete_num. You may need to remove it manually."
            # Potentially break here or try to continue, depending on desired robustness
        fi
    done

    if (( rules_deleted_count > 0 )); then
        if run_with_spinner "Reloading UFW..." ufw reload; then
            handle_success "Deleted $rules_deleted_count UFW rule(s) for tunnel $tunnel_suffix and reloaded UFW."
        else
            handle_error "ERROR" "Failed to reload UFW after deleting rules for tunnel $tunnel_suffix."
        fi
    elif [[ -z "$rule_to_delete_num" ]]; then # Check if any rule was found initially
        log_message "INFO" "No UFW rules found with comment pattern '$ufw_comment_pattern' for tunnel $tunnel_suffix."
    fi
    return 0
}


# --- UFW General Management Menu & Functions ---

_ufw_menu_help() {
    print_menu_header "secondary" "UFW Firewall Management Help"
    echo "This menu allows you to manage the UFW (Uncomplicated Firewall) on your system."
    echo
    print_info "Options:"
    echo "  1. Enable UFW: Activates the firewall. Ensures SSH is allowed."
    echo "  2. Disable UFW: Deactivates the firewall (not recommended)."
    echo "  3. View Status: Shows current UFW status and rules."
    echo "  4. Reset UFW: Disables UFW and deletes ALL rules (use with caution)."
    echo "  5. Clean Orphaned Rules: Removes EasyBackhaul rules for non-existent tunnels."
    echo
    print_info "Important Notes:"
    echo " - Enabling UFW without allowing SSH can lock you out of your server."
    echo " - This script attempts to allow common SSH ports when enabling UFW."
    echo " - Tunnel configurations automatically add/remove their specific UFW rules if UFW is active."
    press_any_key
}

# Main menu for UFW management
manage_ufw_main_menu() {
    local ufw_menu_options=(
        "1. Enable UFW Firewall"
        "2. Disable UFW Firewall"
        "3. View UFW Status & Rules"
        "4. Reset UFW (Deletes ALL rules)"
        "5. Clean Orphaned EasyBackhaul Rules"
    )
    local ufw_exit_details=("0" "Back to Main Menu") # Array: [key, text]
    local user_choice menu_rc

    while true; do
        local ufw_current_status="Inactive"
        if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then # Added 2>/dev/null for ufw status
            ufw_current_status="Active"
        elif ! command -v ufw &>/dev/null; then
            ufw_current_status="Not Installed"
        fi
        print_menu_header "primary" "UFW Firewall Management" "Status: $ufw_current_status"
        
        menu_loop "Select UFW option" ufw_menu_options ufw_exit_details "_ufw_menu_help"
        user_choice="$MENU_CHOICE" # menu_loop sets MENU_CHOICE
        menu_rc=$?                # menu_loop returns status code
        
        # Handle universal navigation keys based on menu_rc
        case "$menu_rc" in
            3) go_to_main_menu; return 0 ;; # m -> main menu
            4) request_script_exit; return 0 ;; # e -> exit script
            5) return_from_menu; return 0 ;; # r -> return/back (to previous menu)
            2) continue ;; # ? -> help was shown, re-loop current menu
            0) # Numeric choice or default exit "0"
               # Proceed to specific choice handling below
               ;;
            *) handle_error "ERROR" "Unhandled menu_loop code $menu_rc in manage_ufw_main_menu"; press_any_key; continue ;;
        esac

        # Handle numeric choices and the specific default exit ("0")
        case "$user_choice" in
            "1") _enable_ufw_with_ssh_allow ;;
            "2") _disable_ufw ;;
            "3") _view_ufw_status ;;
            "4") _reset_ufw ;;
            "5") _clean_orphaned_ufw_rules ;;
            "0") return_from_menu; return 0 ;; # Default exit for this menu
            *) print_warning "Invalid option. Please try again."; press_any_key ;;
        esac
    done
}

_enable_ufw_with_ssh_allow() {
    print_menu_header "secondary" "Enable UFW Firewall"
    if ! command -v ufw &>/dev/null; then
        handle_error "ERROR" "UFW command not found. Please install UFW first."
        press_any_key
        return 1
    fi

    if ufw status | grep -q "Status: active"; then
        handle_success "UFW is already active."
        press_any_key
        return 0
    fi

    print_warning "Enabling UFW may block SSH access if not configured properly."
    print_info "This script will attempt to allow common SSH ports (22 and any custom SSH port found)."
    if ! prompt_yes_no "Proceed with enabling UFW?" "y"; then
        print_info "UFW enable cancelled."
        press_any_key
        return 1
    fi

    # Allow SSH - find common and configured SSH ports
    local ssh_ports_to_allow=("22") # Default SSH port
    if [[ -f /etc/ssh/sshd_config ]]; then
        local custom_ssh_port
        custom_ssh_port=$(grep -E "^Port\s+[0-9]+" /etc/ssh/sshd_config | awk '{print $2}' | head -n1)
        if [[ -n "$custom_ssh_port" && "$custom_ssh_port" != "22" ]]; then
            ssh_ports_to_allow+=("$custom_ssh_port")
        fi
    fi
    # Also check currently listening SSHD ports
    if command -v ss &>/dev/null; then
         local listening_ssh_ports
         listening_ssh_ports=$(ss -tlpn | grep sshd | awk '{print $4}' | sed 's/.*://' | sort -u)
         for port in $listening_ssh_ports; do
             if [[ ! " ${ssh_ports_to_allow[*]} " =~ " ${port} " ]]; then # Check if port already in array
                 ssh_ports_to_allow+=("$port")
             fi
         done
    fi
    
    for port in "${ssh_ports_to_allow[@]}"; do
        if validate_port "$port"; then # from helpers.sh
            log_message "INFO" "Allowing SSH on port $port/tcp in UFW..."
            if ! run_with_spinner "Allowing port $port/tcp (SSH)..." ufw allow "$port/tcp" comment "SSH access (EasyBackhaul)"; then
                handle_error "WARNING" "Failed to add UFW rule for SSH on port $port/tcp."
            fi
        fi
    done

    if run_with_spinner "Enabling UFW..." ufw --force enable; then # --force to enable without prompt
        handle_success "UFW enabled successfully."
    else
        handle_error "ERROR" "Failed to enable UFW. Check UFW logs or status."
    fi
    press_any_key
}

_disable_ufw() {
    print_menu_header "secondary" "Disable UFW Firewall"
    if ! command -v ufw &>/dev/null; then
        handle_error "ERROR" "UFW command not found."
        press_any_key
        return 1
    fi

    if ! ufw status | grep -q "Status: active"; then
        handle_warning "UFW is already inactive."
        press_any_key
        return 0
    fi
    
    print_warning "Disabling UFW will remove firewall protection from this server."
    if ! prompt_yes_no "Are you sure you want to disable UFW?" "n"; then
        print_info "UFW disable cancelled."
        press_any_key
        return 1
    fi

    if run_with_spinner "Disabling UFW..." ufw disable; then
        handle_success "UFW disabled successfully."
    else
        handle_error "ERROR" "Failed to disable UFW."
    fi
    press_any_key
}

_view_ufw_status() {
    print_menu_header "secondary" "UFW Status & Rules"
    if ! command -v ufw &>/dev/null; then
        handle_error "ERROR" "UFW command not found."
        press_any_key
        return 1
    fi

    if ! ufw status | grep -q "Status: active"; then
        handle_warning "UFW is not active."
    else
        print_success "UFW is active."
    fi
    echo
    print_info "Current UFW Rules (numbered):"
    ufw status numbered
    echo
    print_info "EasyBackhaul specific rules are typically commented with 'EasyBackhaul: tunnel-<name>'."
    press_any_key
}

_reset_ufw() {
    print_menu_header "secondary" "Reset UFW Firewall"
     if ! command -v ufw &>/dev/null; then
        handle_error "ERROR" "UFW command not found."
        press_any_key
        return 1
    fi

    print_warning "WARNING: This will disable UFW and delete ALL existing rules."
    print_warning "This action is irreversible and will remove all firewall protection."
    if ! prompt_yes_no "ARE YOU ABSOLUTELY SURE you want to reset UFW?" "n"; then
        print_info "UFW reset cancelled."
        press_any_key
        return 1
    fi
    
    # Second confirmation for such a destructive action
    read -r -p "Type 'CONFIRM RESET UFW' to proceed: " confirmation_text
    if [[ "$confirmation_text" != "CONFIRM RESET UFW" ]]; then
        print_info "Confirmation failed. UFW reset cancelled."
        press_any_key
        return 1
    fi

    if run_with_spinner "Resetting UFW (disabling and deleting all rules)..." ufw --force reset; then
        handle_success "UFW has been reset to its default (inactive) state. All rules deleted."
    else
        handle_error "ERROR" "Failed to reset UFW."
    fi
    press_any_key
}

_clean_orphaned_ufw_rules() {
    print_menu_header "secondary" "Clean Orphaned EasyBackhaul UFW Rules"
    if ! command -v ufw &>/dev/null; then
        handle_error "ERROR" "UFW command not found."
        press_any_key
        return 1
    fi
    if ! ufw status | grep -q "Status: active"; then
        handle_warning "UFW is not active. No rules to clean."
        press_any_key
        return 0
    fi

    log_message "INFO" "Scanning for orphaned EasyBackhaul UFW rules..."
    local ufw_comment_base="EasyBackhaul: tunnel-"
    
    local orphaned_rule_numbers=()
    # Get all rules with EasyBackhaul comments
    # Use process substitution and a while read loop for safer parsing
    while IFS= read -r line; do
        # Extract rule number and comment
        local rule_num comment
        rule_num=$(echo "$line" | awk -F'[][]' '{print $2}')
        comment=$(echo "$line" | sed -n 's/.*comment '"'"'\([^'"'"']*\)'"'"'.*/\1/p')

        if [[ -n "$rule_num" && "$comment" == ${ufw_comment_base}* ]]; then
            local tunnel_suffix
            tunnel_suffix=${comment#${ufw_comment_base}} # Extract suffix from comment
            local tunnel_config_file="$CONFIG_DIR/config-${tunnel_suffix}.toml" # Adjusted to new name format

            if [[ -n "$tunnel_suffix" && ! -f "$tunnel_config_file" ]]; then
                log_message "WARN" "Found orphaned UFW rule #$rule_num for non-existent tunnel '$tunnel_suffix' (Comment: '$comment')."
                orphaned_rule_numbers+=("$rule_num")
            fi
        fi
    done < <(ufw status numbered)

    if [[ ${#orphaned_rule_numbers[@]} -eq 0 ]]; then
        handle_success "No orphaned EasyBackhaul UFW rules found."
        press_any_key
        return 0
    fi

    print_warning "Found ${#orphaned_rule_numbers[@]} orphaned UFW rule(s) linked to deleted tunnels:"
    # Displaying rules again for confirmation can be tricky as numbers might shift if user manually deletes.
    # Best to show the numbers found now.
    for num in "${orphaned_rule_numbers[@]}"; do
        echo "  - Rule #$num"
    done
    echo
    if ! prompt_yes_no "Delete these ${#orphaned_rule_numbers[@]} orphaned rule(s)?" "n"; then
        print_info "Orphaned rule cleanup cancelled."
        press_any_key
        return 1
    fi

    local deleted_count=0
    # Sort numbers in reverse order for deletion to avoid shifting rule numbers
    local sorted_orphans
    IFS=$'\n' sorted_orphans=($(sort -nr <<<"${orphaned_rule_numbers[*]}"))
    unset IFS

    for rule_num_to_delete in "${sorted_orphans[@]}"; do
        log_message "INFO" "Deleting orphaned UFW rule #$rule_num_to_delete."
        if echo "y" | ufw delete "$rule_num_to_delete"; then
            ((deleted_count++))
        else
            handle_error "ERROR" "Failed to delete orphaned UFW rule #$rule_num_to_delete."
        fi
    done

    if (( deleted_count > 0 )); then
        if run_with_spinner "Reloading UFW..." ufw reload; then
            handle_success "Successfully deleted $deleted_count orphaned UFW rule(s) and reloaded UFW."
        else
            handle_error "ERROR" "Failed to reload UFW after deleting orphaned rules."
        fi
    else
        print_info "No orphaned rules were deleted."
    fi
    press_any_key
}

true # Ensure script is valid