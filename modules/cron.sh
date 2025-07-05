# cron.sh
# Cron job management for auto-restart 

# --- Cron Management ---
manage_cron_menu() {
    local service=$1
    
    # Help function for cron menu
    cron_menu_help() {
        clear
        print_server_info_banner_minimal
        print_info "================= Cron Auto-Restart Help ================="
        echo
        echo "Cron jobs automatically restart your tunnel service at regular intervals."
        echo "This is useful for ensuring your tunnel stays running even if it crashes."
        echo
        echo "Available intervals:"
        echo "  • Every 15 minutes: Frequent restarts, good for unstable connections"
        echo "  • Every hour: Balanced approach, restarts once per hour"
        echo "  • Every 6 hours: Less frequent, good for stable connections"
        echo "  • Every 24 hours: Daily restart, minimal overhead"
        echo "  • Custom: Set your own interval in minutes"
        echo
        echo "Note: Only one cron job can be active per service at a time."
        echo "Setting a new job will replace any existing job."
        echo "================================================================"
        press_any_key
    }
    
    while true; do
        clear
        print_server_info_banner_minimal
        print_info "--- Cron Auto-Restart Management ---"
        print_info "Service: $service"
        
        local current_job
        current_job=$(crontab -l 2>/dev/null | grep "$service" | grep "$CRON_COMMENT_TAG")
        if [ -n "$current_job" ]; then
            print_success "Current Cron Job: $current_job"
        else
            print_warning "No cron job is currently set for this service."
        fi
        
        echo
        print_info "Select an option:"
        echo " 1. Set/Update Job: Every 15 Minutes"
        echo " 2. Set/Update Job: Every Hour"
        echo " 3. Set/Update Job: Every 6 Hours"
        echo " 4. Set/Update Job: Every 24 Hours"
        echo " 5. Set/Update Job: Custom Interval (minutes)"
        echo " 6. Remove Existing Cron Job"
        print_menu_footer
        
        menu_loop 0 6 "?" "cron_menu_help" "Enter choice [0-6, ? for help]"
        
        case $choice in
            1) set_cron_job "*/15 * * * *" "$service"; break;;
            2) set_cron_job "0 * * * *" "$service"; break;;
            3) set_cron_job "0 */6 * * *" "$service"; break;;
            4) set_cron_job "0 0 * * *" "$service"; break;;
            5) 
                while true; do
                    read -p "Enter interval in minutes (1-1440): " interval
                    if [[ "$interval" == "?" ]]; then
                        print_info "--- Custom Interval Help ---"
                        echo "Enter the number of minutes between restarts."
                        echo "Minimum: 1 minute"
                        echo "Maximum: 1440 minutes (24 hours)"
                        echo "Examples: 30 (every 30 minutes), 120 (every 2 hours)"
                        press_any_key
                        continue
                    elif [[ "$interval" == "0" ]]; then
                        print_info "Operation cancelled."
                        break
                    elif [[ -n "$interval" ]] && [[ "$interval" =~ ^[0-9]+$ ]] && [[ $interval -ge 1 ]] && [[ $interval -le 1440 ]]; then
                        set_cron_job "*/$interval * * * *" "$service"
                        break
                    else
                        print_warning "❌ Invalid interval. Please enter a number between 1 and 1440."
                        press_any_key
                    fi
                done
                break;;
            6) remove_cron_job "$service"; break;;
            0) return;;
        esac
    done
    press_any_key
}

set_cron_job() {
    local schedule=$1 service=$2
    remove_cron_job "$service"
    local cron_job="$schedule systemctl restart $service # $CRON_COMMENT_TAG"
    (crontab -l 2>/dev/null; echo "$cron_job") | crontab -
    print_success "✅ Cron job set successfully for $service."
}

remove_cron_job() {
    local service=$1
    if crontab -l 2>/dev/null | grep -q "$service"; then
       (crontab -l 2>/dev/null | grep -v "$service") | crontab -
       print_success "✅ Cron job for $service removed."
    else
       print_warning "⚠ No cron job found for $service."
    fi
} 