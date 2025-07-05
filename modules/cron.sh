# cron.sh
# Cron job management for auto-restart 

# --- Cron Management ---
manage_cron_menu() {
    local service=$1
    while true; do
        clear
        print_server_info_banner
        print_info "--- Cron Auto-Restart for $service ---"
        
        local current_job
        current_job=$(crontab -l 2>/dev/null | grep "$service" | grep "$CRON_COMMENT_TAG")
        if [ -n "$current_job" ]; then
            print_success "Current Cron Job: $current_job"
        else
            print_warning "No cron job is currently set for this service."
        fi
        
        print_info "\nSelect an option:"
        echo " 1. Set/Update Job: Every 15 Minutes"
        echo " 2. Set/Update Job: Every Hour"
        echo " 3. Set/Update Job: Every 6 Hours"
        echo " 4. Set/Update Job: Every 24 Hours"
        echo " 5. Set/Update Job: Custom Interval (minutes)"
        echo " 6. Remove Existing Cron Job"
        echo " 0. Back to Tunnel Menu"
        read -p "Enter choice [1-6, 0]: " choice

        case $choice in
            1) set_cron_job "*/15 * * * *" "$service"; break;;
            2) set_cron_job "0 * * * *" "$service"; break;;
            3) set_cron_job "0 */6 * * *" "$service"; break;;
            4) set_cron_job "0 0 * * *" "$service"; break;;
            5) 
                read -p "Enter interval in minutes: " interval
                if validate_number "$interval"; then
                    set_cron_job "*/$interval * * * *" "$service"
                else
                    print_error "Invalid interval. Must be a number."; sleep 2
                fi
                break;;
            6) remove_cron_job "$service"; break;;
            0) return;;
            *) print_warning "Invalid choice.";;
        esac
    done
    press_any_key
}

set_cron_job() {
    local schedule=$1 service=$2
    remove_cron_job "$service"
    local cron_job="$schedule systemctl restart $service # $CRON_COMMENT_TAG"
    (crontab -l 2>/dev/null; echo "$cron_job") | crontab -
    print_success "Cron job set successfully for $service."
}

remove_cron_job() {
    local service=$1
    if crontab -l 2>/dev/null | grep -q "$service"; then
       (crontab -l 2>/dev/null | grep -v "$service") | crontab -
       print_success "Cron job for $service removed."
    fi
} 