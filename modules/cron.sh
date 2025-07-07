# modules/cron.sh
# Cron job management for auto-restart of services.

# --- Cron Management ---

# Local helper for cron menu help text
_manage_cron_menu_help() {
    print_menu_header "secondary" "Cron Auto-Restart Help" "Service: $1" # Pass service name for context
    echo "Cron jobs can automatically restart your tunnel service at regular intervals."
    echo "This helps ensure the tunnel remains operational even if it encounters an issue."
    echo
    print_info "Available Intervals:"
    echo "  - Every 15 Minutes: Frequent restarts, useful for potentially unstable connections."
    echo "  - Every Hour: A balanced approach."
    echo "  - Every 6 Hours: Less frequent, suitable for generally stable connections."
    echo "  - Every 24 Hours: Daily restart, minimal operational overhead."
    echo "  - Custom: Define your own restart interval in minutes."
    echo
    print_info "Important Notes:"
    echo "  - Only one auto-restart cron job can be active per service at a time."
    echo "  - Setting a new job will replace any existing EasyBackhaul-managed cron job for this service."
    echo "  - Cron jobs are identified by the comment tag: '$CRON_COMMENT_TAG'"
    press_any_key
}

# Main menu for managing cron jobs for a specific service
manage_cron_job_for_service() {
    local service_name="$1" # e.g., backhaul-server-tcp-xxxx

    if [[ -z "$service_name" ]]; then
        handle_error "ERROR" "Service name not provided to manage_cron_job_for_service."
        return 1
    fi
    # Ensure CRON_COMMENT_TAG is available (from globals.sh)
    if [[ -z "$CRON_COMMENT_TAG" ]]; then
        handle_error "CRITICAL" "CRON_COMMENT_TAG is not defined. Cannot manage cron jobs."
        return 1
    fi

    local current_cron_job
    local cron_menu_options=(
        "1. Set/Update: Every 15 Minutes"
        "2. Set/Update: Every Hour"
        "3. Set/Update: Every 6 Hours"
        "4. Set/Update: Every 24 Hours"
        "5. Set/Update: Custom Interval (minutes)"
        "6. Remove Auto-Restart Cron Job"
    )
    local cron_exit_details=("0" "Back to Tunnel Management") # Array: [key, text]
    local user_choice menu_rc

    while true; do
        print_menu_header "secondary" "Cron Auto-Restart Management" "Service: $service_name"
        
        current_cron_job=$(crontab -l 2>/dev/null | grep -F "$service_name" | grep -F "# $CRON_COMMENT_TAG")
        if [[ -n "$current_cron_job" ]]; then
            print_success "Current Cron Job: $current_cron_job"
        else
            print_warning "No EasyBackhaul-managed cron job found for this service."
        fi
        echo

        # Pass service_name to the help function for context
        menu_loop "Select option" cron_menu_options cron_exit_details "_manage_cron_menu_help \"$service_name\""
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
            *) handle_error "ERROR" "Unhandled menu_loop code $menu_rc in manage_cron_job_for_service"; press_any_key; continue;;
        esac

        # Handle numeric choices and the specific default exit ("0")
        case "$user_choice" in
            "1") _set_service_cron_job "*/15 * * * *" "$service_name"; break ;;
            "2") _set_service_cron_job "0 * * * *" "$service_name"; break ;;
            "3") _set_service_cron_job "0 */6 * * *" "$service_name"; break ;;
            "4") _set_service_cron_job "0 0 * * *" "$service_name"; break ;;
            "5")
                local custom_interval
                print_info "Enter custom interval in minutes (1-1440, or 0 to cancel)."
                while true; do
                    read -r -p "Interval (minutes): " custom_interval
                    if [[ "$custom_interval" == "0" ]]; then
                        print_info "Custom interval setup cancelled."
                        break # Breaks inner loop, will re-show cron menu
                    elif [[ "$custom_interval" =~ ^[0-9]+$ ]] && (( custom_interval >= 1 && custom_interval <= 1440 )); then
                        _set_service_cron_job "*/${custom_interval} * * * *" "$service_name"
                        break 2 # Breaks both loops, exiting manage_cron_job_for_service after success
                    else
                        print_warning "Invalid interval. Please enter a number between 1 and 1440, or 0 to cancel."
                    fi
                done
                # If inner loop broken by '0', outer loop continues. If broken by valid custom interval, outer loop also breaks.
                if [[ "$custom_interval" != "0" ]]; then break; fi
                ;;
            "6") _remove_service_cron_job "$service_name"; break ;;
            "0") return_from_menu; return 0 ;;
            *) print_warning "Invalid option. Please try again."; press_any_key ;;
        esac
    done
    press_any_key # After a cron job action
    return_from_menu # Return to the calling menu (likely tunnel management)
}

# Internal function to set a cron job for a specific service
_set_service_cron_job() {
    local schedule_expression="$1"
    local service_to_manage="$2"

    # Remove any existing cron job for this service managed by this script
    _remove_service_cron_job "$service_to_manage" "quiet" # quiet mode for removal

    local new_cron_job_line="${schedule_expression} systemctl restart ${service_to_manage} # ${CRON_COMMENT_TAG}"

    # Add the new job
    # Fetch current crontab, append new job, then load it. Handle empty crontab.
    local current_crontab
    current_crontab=$(crontab -l 2>/dev/null)

    if [[ -z "$current_crontab" ]]; then
        echo "$new_cron_job_line" | crontab -
    else
        (echo "$current_crontab"; echo "$new_cron_job_line") | crontab -
    fi

    if crontab -l 2>/dev/null | grep -Fq "$new_cron_job_line"; then
        handle_success "Cron job set successfully for $service_to_manage."
        log_message "INFO" "Cron job set for $service_to_manage: $new_cron_job_line"
    else
        handle_error "ERROR" "Failed to set cron job for $service_to_manage. Check crontab permissions or syntax."
    fi
}

# Internal function to remove a cron job for a specific service
# Param $2: "quiet" to suppress "no job found" message.
_remove_service_cron_job() {
    local service_to_manage="$1"
    local mode="${2:-verbose}" # Default to verbose
    local job_found=false

    # Check if crontab command exists
    if ! command -v crontab &> /dev/null; then
        handle_error "WARNING" "crontab command not found. Cannot manage cron jobs."
        return 1
    fi

    local current_crontab
    current_crontab=$(crontab -l 2>/dev/null)

    if echo "$current_crontab" | grep -Fq "$service_to_manage" && \
       echo "$current_crontab" | grep -Fq "# $CRON_COMMENT_TAG"; then
        job_found=true
        # Filter out the job for the specific service and comment tag
        echo "$current_crontab" | grep -vF "$service_to_manage" | grep -vF "# $CRON_COMMENT_TAG" | crontab -
        # This grep logic is a bit broad, ideally it should remove the specific line.
        # A more precise way:
        # echo "$current_crontab" | grep -vE "systemctl restart ${service_to_manage} # ${CRON_COMMENT_TAG}$" | crontab -
        # For simplicity, the above is okay if we assume one job per service.
        # Let's refine it:
        echo "$current_crontab" | grep -v "systemctl restart ${service_to_manage} # ${CRON_COMMENT_TAG}" | crontab -


        # Verify removal
        if ! crontab -l 2>/dev/null | grep -Fq "$service_to_manage" | grep -Fq "# $CRON_COMMENT_TAG"; then
             if [[ "$mode" != "quiet" ]]; then
                handle_success "Cron job for $service_to_manage removed."
            fi
            log_message "INFO" "Cron job removed for $service_to_manage."
        else
            if [[ "$mode" != "quiet" ]]; then
                handle_error "ERROR" "Failed to remove cron job for $service_to_manage."
            fi
        fi
    elif [[ "$mode" != "quiet" ]]; then
        print_warning "No EasyBackhaul-managed cron job found for $service_to_manage."
    fi
    return 0
}
true # Ensure script is valid