# modules/backhaul_core.sh
# Download, install, and update Backhaul binary; get server info 

# Global variables for server info - to be populated by get_server_info
SERVER_IP="N/A"
SERVER_COUNTRY="N/A"
SERVER_ISP="N/A"

# Fetches server's public IP and geo-information.
# Populates SERVER_IP, SERVER_COUNTRY, SERVER_ISP global variables.
get_server_info() {
    log_message "INFO" "Attempting to fetch server IP and geo-information..."
    SERVER_IP="N/A"
    SERVER_COUNTRY="N/A"
    SERVER_ISP="N/A"

    local services_to_try=(
        "http://ip-api.com/json/?fields=query,country,isp"
        "https://ipapi.co/json/"
        "https://ipinfo.io/json"
    )
    local response_json

    for service_url in "${services_to_try[@]}"; do
        log_message "DEBUG" "Trying IP service: $service_url"
        
        # Use run_with_spinner for curl command with timeout
        # Create a temporary file to capture curl output
        local temp_output_file
        temp_output_file=$(mktemp)

        # Using a subshell to capture output for response_json
        if response_json=$(timeout 10s curl -s --connect-timeout 3 --max-time 8 "$service_url" 2>"$temp_output_file"); then
            if [[ -n "$response_json" ]] && echo "$response_json" | jq -e . >/dev/null 2>&1; then
                # Attempt to parse common fields
                local ip country isp
                ip=$(echo "$response_json" | jq -r '.ip // .query // "N/A"')
                country=$(echo "$response_json" | jq -r '.country // .country_name // "N/A"')
                isp=$(echo "$response_json" | jq -r '.isp // .org // "N/A"')

                if [[ "$ip" != "N/A" && "$ip" != "null" ]]; then
                    SERVER_IP="$ip"
                    SERVER_COUNTRY="$country"
                    SERVER_ISP="$isp"
                    log_message "INFO" "Server info fetched from $service_url: IP=$SERVER_IP, Country=$SERVER_COUNTRY, ISP=$SERVER_ISP"
                    rm -f "$temp_output_file"
                    return 0
                else
                    log_message "WARN" "Successfully fetched from $service_url, but IP address was null or N/A."
                fi
            else
                log_message "WARN" "Invalid or empty JSON response from $service_url. Error: $(cat "$temp_output_file")"
            fi
        else
            log_message "WARN" "Failed to fetch from $service_url. Error: $(cat "$temp_output_file")"
        fi
        rm -f "$temp_output_file"
    done

    log_message "WARN" "All external IP services failed. Attempting fallback using icanhazip.com..."
    local fallback_ip
    if fallback_ip=$(curl -s --connect-timeout 3 --max-time 5 https://icanhazip.com 2>/dev/null | tr -d '\n\r'); then
         if [[ -n "$fallback_ip" ]] && validate_ip "$fallback_ip"; then # Use helper
            SERVER_IP="$fallback_ip"
            # SERVER_COUNTRY and SERVER_ISP will remain N/A
            log_message "INFO" "Fallback successful. Server IP detected as: $SERVER_IP (Country/ISP unknown)."
            return 0
        else
            log_message "WARN" "Fallback icanhazip.com returned invalid IP: $fallback_ip"
        fi
    else
        log_message "ERROR" "Could not fetch server IP from any source."
    fi
    
    # If still N/A, log it.
    if [[ "$SERVER_IP" == "N/A" ]]; then
        log_message "ERROR" "Unable to determine server IP address."
    fi
    return 1
}

# Verifies the Backhaul binary installation and version.
# Uses global BIN_PATH.
verify_binary_installation() {
    log_message "INFO" "Verifying Backhaul binary at: $BIN_PATH"
    if [[ ! -f "$BIN_PATH" ]]; then
        handle_error "ERROR" "Binary not found at expected location: $BIN_PATH"
        return 1
    fi
    
    if [[ ! -x "$BIN_PATH" ]]; then
        handle_error "WARNING" "Binary at $BIN_PATH is not executable. Attempting to fix..."
        chmod +x "$BIN_PATH"
        if [[ ! -x "$BIN_PATH" ]]; then
            handle_error "ERROR" "Failed to make binary $BIN_PATH executable."
            return 1
        fi
        log_message "INFO" "Binary permissions fixed for $BIN_PATH."
    fi
    
    local version_output=""
    # Try -v first, then --version
    if version_output=$("$BIN_PATH" -v 2>&1 | head -n1); then
        : # Command succeeded, version_output captured
    elif version_output=$("$BIN_PATH" --version 2>&1 | head -n1); then
        : # Command succeeded, version_output captured
    else
        handle_error "WARNING" "Binary exists at $BIN_PATH but version check command failed. It might be incompatible or corrupted."
        return 1
    fi

    if [[ -z "$version_output" ]] || echo "$version_output" | grep -qiE "command not found|no such file|error"; then
        handle_error "WARNING" "Binary at $BIN_PATH version output seems invalid: $version_output"
        return 1
    fi

    handle_success "Backhaul binary verification successful. Version: $version_output"
    return 0
}

# Installs the downloaded Backhaul binary.
# Assumes binary is at /tmp/backhaul.tar.gz
# Uses global BIN_PATH.
install_downloaded_binary() {
    local archive_path="/tmp/backhaul.tar.gz"
    local target_bin_dir
    target_bin_dir=$(dirname "$BIN_PATH")
    local target_bin_name
    target_bin_name=$(basename "$BIN_PATH")

    log_message "INFO" "Starting installation of Backhaul binary from $archive_path to $BIN_PATH"

    if [[ ! -f "$archive_path" ]]; then
        handle_error "ERROR" "Downloaded archive $archive_path not found."
        return 1
    fi

    if ! tar -tzf "$archive_path" >/dev/null 2>&1; then
        handle_error "ERROR" "File $archive_path is not a valid tar.gz archive."
        secure_delete "$archive_path"
        return 1
    fi

    local temp_extract_dir
    temp_extract_dir=$(mktemp -d /tmp/backhaul_extract_XXXXXX)

    log_message "INFO" "Extracting $archive_path to $temp_extract_dir..."
    if ! tar -xzf "$archive_path" -C "$temp_extract_dir"; then
        handle_error "ERROR" "Extraction of $archive_path failed."
        rm -rf "$temp_extract_dir"
        secure_delete "$archive_path"
        return 1
    fi

    # Find the binary - could be 'backhaul' or 'backhaul_os_arch/backhaul' etc.
    local found_binary_path
    found_binary_path=$(find "$temp_extract_dir" -type f \( -name "backhaul" -o -name "$target_bin_name" \) -executable 2>/dev/null | head -n1)

    if [[ -z "$found_binary_path" ]]; then
        # If not executable, try finding by name only
        found_binary_path=$(find "$temp_extract_dir" -type f \( -name "backhaul" -o -name "$target_bin_name" \) 2>/dev/null | head -n1)
        if [[ -z "$found_binary_path" ]]; then
            handle_error "ERROR" "Could not find 'backhaul' binary within the extracted archive."
            rm -rf "$temp_extract_dir"
            secure_delete "$archive_path"
            return 1
        fi
        log_message "WARN" "Found binary '$found_binary_path' but it was not marked executable initially."
    fi

    log_message "INFO" "Found binary at '$found_binary_path'. Moving to $BIN_PATH."
    
    ensure_dir "$target_bin_dir" "755" # Ensure target directory exists
    
    if ! mv "$found_binary_path" "$BIN_PATH"; then
        handle_error "ERROR" "Failed to move binary from $found_binary_path to $BIN_PATH."
        rm -rf "$temp_extract_dir"
        secure_delete "$archive_path"
        return 1
    fi

    chmod +x "$BIN_PATH"
    set_secure_file_permissions "$BIN_PATH" "755" # Executable for owner, readable for others

    rm -rf "$temp_extract_dir"
    secure_delete "$archive_path"
    
    log_message "INFO" "Backhaul binary extracted and placed at $BIN_PATH."

    if verify_binary_installation; then
        handle_success "Backhaul binary installation completed and verified!"
        print_info "Summary: 📁 $BIN_PATH | 🔒 $(stat -c %a "$BIN_PATH") | 📊 $(du -h "$BIN_PATH" | cut -f1)"
    else
        handle_error "WARNING" "Binary installed to $BIN_PATH, but verification failed. It may be incompatible."
    fi
    return 0
}


# --- Download Backhaul Binary Workflow ---
_download_menu_help() {
    print_info "Backhaul Installation Help:"
    echo " - GitHub Download: Attempts to fetch the latest release directly."
    echo " - Local File: Install from a .tar.gz you've already downloaded."
    echo " - Alt. Source: Provide a custom URL for the .tar.gz binary archive."
    echo " - Network Diagnostics: Test connectivity if downloads fail."
    echo " - Skip: Continue without installing (you can install later)."
    press_any_key
}

download_backhaul_binary_workflow() {
    print_menu_header "primary" "Backhaul Binary Installation"
    
    log_message "INFO" "Identifying system architecture..."
    local system_os system_arch detected_arch_suffix
    system_os=$(uname -s | tr '[:upper:]' '[:lower:]')
    system_arch=$(uname -m)

    case "$system_arch" in
        x86_64) detected_arch_suffix="amd64" ;;
        aarch64) detected_arch_suffix="arm64" ;;
        armv7l) detected_arch_suffix="armv7" ;; # Common for RPi
        *) 
            handle_error "CRITICAL" "Unsupported architecture: $system_arch. Cannot automatically download."
            press_any_key
            return 1
            ;;
    esac
    print_success "Detected System: $system_os / $detected_arch_suffix (raw: $system_arch)"
    echo

    local menu_options=(
        "1. Automatic GitHub Download (Recommended)"
        "2. Install from Local File"
        "3. Install from Alternative URL"
        "4. Run Network Diagnostics"
        "5. Skip Installation (Advanced)"
    )
    local current_exit_details=("0" "Cancel Installation") # Array: [key, text]
    local user_choice menu_rc

    while true; do
        print_menu_header "primary" "Backhaul Binary Installation" "Choose Installation Method"
        # Pass arrays by name
        menu_loop "Select option" menu_options current_exit_details "_download_menu_help"
        user_choice="$MENU_CHOICE" # menu_loop sets MENU_CHOICE
        menu_rc=$?                # menu_loop returns status code
        
        # Handle universal navigation keys based on menu_rc
        case "$menu_rc" in
            3) go_to_main_menu; return 0 ;; # m -> main menu
            4) request_script_exit; return 0 ;; # e -> exit script
            5) # r -> return/back (for this top-level workflow, it's like cancelling)
               print_info "Installation cancelled via 'r' key."
               return 1 ;;
            2) continue ;; # ? -> help was shown, re-loop current menu
        esac

        # Handle numeric choices and the specific default exit ("0")
        case "$user_choice" in
            "1") # GitHub Download
                _download_from_github "$system_os" "$detected_arch_suffix" # This function will return 0 on success, 1 on failure
                # If successful, download_backhaul_binary_workflow should also return 0
                # If _download_from_github was successful (which means install_downloaded_binary was successful),
                # we can assume the workflow is complete.
                if [[ $? -eq 0 ]]; then return 0; fi
                # If it failed, the error message is handled in _download_from_github or install_downloaded_binary
                # Loop will continue to re-prompt installation method.
                ;;
            "2") # Local File
                _download_from_local_file "$system_os" "$detected_arch_suffix"
                if [[ $? -eq 0 ]]; then return 0; fi
                ;;
            "3") # Alternative URL
                _download_from_alternative_source "$system_os" "$detected_arch_suffix"
                if [[ $? -eq 0 ]]; then return 0; fi
                ;;
            "4") # Network Diagnostics
                # run_network_diagnostics_menu is a self-contained menu loop.
                # It will handle its own navigation and return when the user exits it.
                # We need to ensure it's called correctly.
                # If run_network_diagnostics_menu itself needs to trigger main menu or exit script, it should use the nav helpers.
                # For now, assume it returns to this loop.
                if type run_network_diagnostics_menu &>/dev/null; then
                    navigate_to_menu "run_network_diagnostics_menu"
                    return 0 # Let main loop call it
                else
                    handle_error "ERROR" "Network diagnostics function not available."
                fi
                ;;
            "5") # Skip
                print_warning "Skipping binary installation."
                print_info "You can install the binary later using the main menu."
                print_info "Ensure it's placed at: $BIN_PATH"
                press_any_key
                return 0 # Successfully skipped
                ;;
            "0") # Cancel Installation (Matches current_exit_details[0])
                print_info "Installation cancelled."
                return 1 # Signify cancellation/failure
                ;;
            *) 
                print_warning "Invalid option selected in download workflow."
                ;;
        esac
        # If an option failed and didn't return, loop back to show menu again
        press_any_key
    done
}

# Helper function for installation menu choice
# download_installation_choice() { # No longer needed due to direct MENU_CHOICE usage
#     local choice="$1"
#     download_choice="$choice"
# }

# Helper function for fallback menu choice
# download_fallback_choice() { # No longer needed if _download_from_github doesn't have its own sub-menu loop for this
#     local choice="$1"
#     fallback_choice="$choice"
# }

_download_from_github() {
    local os="$1"
    local arch_suffix="$2"
    local latest_version=""
    
    log_message "INFO" "Fetching latest Backhaul version from GitHub API..."
    local api_response
    api_response=$(curl -s --connect-timeout 10 "https://api.github.com/repos/Musixal/Backhaul/releases/latest")

    if [[ -n "$api_response" ]] && echo "$api_response" | jq -e .tag_name >/dev/null 2>&1; then
        latest_version=$(echo "$api_response" | jq -r .tag_name)
        if [[ -z "$latest_version" || "$latest_version" == "null" ]]; then
            log_message "WARN" "Could not parse tag_name from GitHub API response. Will try a common fallback."
            latest_version="v0.6.6" # Fallback, consider making this more dynamic or removing
        else
            log_message "INFO" "Latest version from GitHub: $latest_version"
        fi
    else
        handle_error "WARNING" "Failed to fetch latest version from GitHub API. Check connectivity or API rate limits."
        log_message "WARN" "Using fallback version v0.6.6 due to API fetch failure."
        latest_version="v0.6.6"
    fi

    local download_url="https://github.com/Musixal/Backhaul/releases/download/${latest_version}/backhaul_${os}_${arch_suffix}.tar.gz"
    print_info "Attempting to download Backhaul ${latest_version} for ${os}/${arch_suffix}..."
    echo "URL: $download_url"

    if run_with_spinner "Downloading from GitHub..." \
        wget --progress=dot:giga -O /tmp/backhaul.tar.gz "$download_url"; then
        if install_downloaded_binary; then # install_downloaded_binary returns 0 on success
            return 0 # Overall success
        else
            handle_error "ERROR" "Binary installation failed after download."
            return 1 # Installation part failed
        fi
    else
        handle_error "ERROR" "Download from GitHub failed. URL: $download_url"
        return 1
    fi
}

_download_from_local_file() {
    local os="$1" # For informational purposes
    local arch_suffix="$2" # For informational purposes
    
    print_menu_header "secondary" "Local File Installation" \
        "Install Backhaul from a pre-downloaded file."
    
    print_info "Provide the full path to your local Backhaul .tar.gz archive."
    print_info "(e.g., /path/to/your/backhaul_${os}_${arch_suffix}.tar.gz)"
    
    local local_file_path
    while true; do
        read -e -r -p "Enter path to local .tar.gz file (or '0' to cancel): " local_file_path
        if [[ "$local_file_path" == "0" ]]; then print_info "Cancelled."; return 1; fi
        if [[ -z "$local_file_path" ]]; then
            if prompt_yes_no "Path cannot be empty. Cancel local file installation?" "y"; then return 1; fi
            continue
        fi
        if [[ ! -f "$local_file_path" ]]; then
            if prompt_yes_no "File not found: '$local_file_path'. Try again?" "y"; then continue; else return 1; fi
        fi
        # Relaxed check for .tar.gz, install_downloaded_binary will verify archive integrity.
        # if [[ "$local_file_path" != *.tar.gz ]]; then
        #     if prompt_yes_no "File does not end with .tar.gz. Proceed anyway?" "n"; then break; else continue; fi
        # fi
        break
    done

    log_message "INFO" "Copying local file '$local_file_path' to /tmp/backhaul.tar.gz"
    if cp "$local_file_path" /tmp/backhaul.tar.gz; then
        if install_downloaded_binary; then return 0; else return 1; fi
    else
        handle_error "ERROR" "Failed to copy local file '$local_file_path' to temporary location."
        return 1
    fi
}

_download_from_alternative_source() {
    local os="$1" # For informational purposes
    local arch_suffix="$2" # For informational purposes

    print_menu_header "secondary" "Alternative Download Source" \
        "Install Backhaul from a custom URL."
    
    print_info "Provide the full URL to the Backhaul .tar.gz archive."
    print_info "(e.g., https://your-mirror.com/backhaul_${os}_${arch_suffix}.tar.gz)"

    local alt_url
    while true; do
        read -e -r -p "Enter alternative download URL (or '0' to cancel): " alt_url
        if [[ "$alt_url" == "0" ]]; then print_info "Cancelled."; return 1; fi
        if [[ -z "$alt_url" ]]; then
            if prompt_yes_no "URL cannot be empty. Cancel alternative source installation?" "y"; then return 1; fi
            continue
        fi
        if [[ ! "$alt_url" =~ ^https?:// ]]; then # Basic URL check
            if prompt_yes_no "URL does not look valid. Try again?" "y"; then continue; else return 1; fi
        fi
        break
    done

    if run_with_spinner "Downloading from $alt_url..." \
        wget --progress=dot:giga -O /tmp/backhaul.tar.gz "$alt_url"; then
        if install_downloaded_binary; then return 0; else return 1; fi
    else
        handle_error "ERROR" "Download from alternative source '$alt_url' failed."
        return 1
    fi
}

# Network diagnostics menu (moved from menu.sh potentially, or refined)
run_network_diagnostics_menu() {
    _network_diag_help() {
        print_info "Network Diagnostics Help:"
        echo " This tests connectivity to common internet services and GitHub."
        echo " Failures can indicate network configuration issues on your VPS,"
        echo " DNS problems, or regional blocks."
        press_any_key
    }

    local diag_menu_options=("1. Run All Network Tests")
    local diag_exit_details=("0" "Back to Installation Options") # Array: [key, text]
    local user_choice diag_rc

    while true; do
        print_menu_header "secondary" "Network Connectivity Diagnostics"
        menu_loop "Select option" diag_menu_options diag_exit_details "_network_diag_help"
        user_choice="$MENU_CHOICE"
        diag_rc=$?

        case "$diag_rc" in
            3) go_to_main_menu; return ;; # m -> main menu
            4) request_script_exit; return ;; # e -> exit script
            5) return_from_menu; return ;; # r -> return/back
            2) continue ;; # ? -> help was shown
        esac

        case "$user_choice" in
            "1")
                print_info "--- Testing General Internet Connectivity ---"
                check_basic_connectivity # Uses a few common hosts like 8.8.8.8, google.com
                echo
                print_info "--- Testing GitHub Connectivity ---"
                local github_hosts=("github.com" "api.github.com" "objects.githubusercontent.com")
                local gh_success_count=0
                for gh_host in "${github_hosts[@]}"; do
                    if run_with_spinner "Pinging $gh_host..." ping -c 1 -W 2 "$gh_host"; then
                        ((gh_success_count++))
                    fi
                done
                 if (( gh_success_count == ${#github_hosts[@]} )); then
                    print_success "All GitHub hosts pingable."
                elif (( gh_success_count > 0 )); then
                    print_warning "Some GitHub hosts not pingable. Downloads might be affected."
                else
                    print_error "Cannot ping any GitHub hosts. Downloads from GitHub will likely fail."
                fi
                press_any_key
                ;;
            "0") # Default exit for this menu
                return_from_menu; return ;; # Return to previous menu (download_backhaul_binary_workflow)
            *) print_warning "Invalid option in network diagnostics."; press_any_key;;
        esac
    done
}


true # Ensure script is valid
                handle_error "ERROR" "GitHub download and installation failed."
                # If it fails, loop back to offer other options
                ;;
            "2") # Local File
                _download_from_local_file "$system_os" "$detected_arch_suffix" && return 0 || \
                handle_error "ERROR" "Local file installation failed."
                ;;
            "3") # Alternative URL
                _download_from_alternative_source "$system_os" "$detected_arch_suffix" && return 0 || \
                handle_error "ERROR" "Alternative URL installation failed."
                ;;
            "4") # Network Diagnostics
                run_network_diagnostics_menu # This function is self-contained with its own menu loop
                # After diagnostics, the user is returned here to re-choose.
                ;;
            "5") # Skip
                print_warning "Skipping binary installation."
                print_info "You can install the binary later using the main menu."
                print_info "Ensure it's placed at: $BIN_PATH"
                press_any_key
                return 0 # Successfully skipped
                ;;
            "0") # Cancel
                print_info "Installation cancelled."
                return 1 # Signify cancellation/failure
                ;;
            *) # Should be handled by menu_loop, but as a fallback
                print_warning "Invalid option selected."
                press_any_key
                ;;
        esac
        # If an option failed and didn't return, loop back to show menu again
        press_any_key
    done
}

_download_from_github() {
    local os="$1"
    local arch_suffix="$2"
    local latest_version=""
    
    log_message "INFO" "Fetching latest Backhaul version from GitHub API..."
    local api_response
    api_response=$(curl -s --connect-timeout 10 "https://api.github.com/repos/Musixal/Backhaul/releases/latest")

    if [[ -n "$api_response" ]] && echo "$api_response" | jq -e .tag_name >/dev/null 2>&1; then
        latest_version=$(echo "$api_response" | jq -r .tag_name)
        if [[ -z "$latest_version" || "$latest_version" == "null" ]]; then
            log_message "WARN" "Could not parse tag_name from GitHub API response. Will try a common fallback."
            latest_version="v0.6.6" # Fallback, consider making this more dynamic or removing
        else
            log_message "INFO" "Latest version from GitHub: $latest_version"
        fi
    else
        handle_error "WARNING" "Failed to fetch latest version from GitHub API. Check connectivity or API rate limits."
        # Could offer to input version manually or use a fixed known good version. For now, using fallback.
        log_message "WARN" "Using fallback version v0.6.6 due to API fetch failure."
        latest_version="v0.6.6"
    fi

    local download_url="https://github.com/Musixal/Backhaul/releases/download/${latest_version}/backhaul_${os}_${arch_suffix}.tar.gz"
    print_info "Attempting to download Backhaul ${latest_version} for ${os}/${arch_suffix}..."
    echo "URL: $download_url"

    if run_with_spinner "Downloading from GitHub..." \
        wget --progress=dot:giga -O /tmp/backhaul.tar.gz "$download_url"; then
        install_downloaded_binary
        return $? # Return status of install_downloaded_binary
    else
        handle_error "ERROR" "Download from GitHub failed. URL: $download_url"
        return 1
    fi
}

_download_from_local_file() {
    local os="$1" # For informational purposes
    local arch_suffix="$2" # For informational purposes

    print_menu_header "secondary" "Local File Installation" \
        "Install Backhaul from a pre-downloaded file."

    print_info "Provide the full path to your local Backhaul .tar.gz archive."
    print_info "(e.g., /path/to/your/backhaul_${os}_${arch_suffix}.tar.gz)"
    
    local local_file_path
    while true; do
        read -e -r -p "Enter path to local .tar.gz file: " local_file_path
        if [[ -z "$local_file_path" ]]; then
            if prompt_yes_no "Path cannot be empty. Cancel local file installation?" "y"; then return 1; fi
            continue
        fi
        if [[ ! -f "$local_file_path" ]]; then
            if prompt_yes_no "File not found: '$local_file_path'. Try again?" "y"; then continue; else return 1; fi
        fi
        if [[ "$local_file_path" != *.tar.gz ]]; then
            if prompt_yes_no "File does not end with .tar.gz. Proceed anyway?" "n"; then break; else continue; fi
        fi
        break
    done

    log_message "INFO" "Copying local file '$local_file_path' to /tmp/backhaul.tar.gz"
    if cp "$local_file_path" /tmp/backhaul.tar.gz; then
        install_downloaded_binary
        return $?
    else
        handle_error "ERROR" "Failed to copy local file '$local_file_path' to temporary location."
        return 1
    fi
}

_download_from_alternative_source() {
    local os="$1" # For informational purposes
    local arch_suffix="$2" # For informational purposes

    print_menu_header "secondary" "Alternative Download Source" \
        "Install Backhaul from a custom URL."
    
    print_info "Provide the full URL to the Backhaul .tar.gz archive."
    print_info "(e.g., https://your-mirror.com/backhaul_${os}_${arch_suffix}.tar.gz)"

    local alt_url
    while true; do
        read -e -r -p "Enter alternative download URL: " alt_url
        if [[ -z "$alt_url" ]]; then
            if prompt_yes_no "URL cannot be empty. Cancel alternative source installation?" "y"; then return 1; fi
            continue
        fi
        if [[ ! "$alt_url" =~ ^https?:// ]]; then # Basic URL check
            if prompt_yes_no "URL does not look valid. Try again?" "y"; then continue; else return 1; fi
        fi
        break
    done

    if run_with_spinner "Downloading from $alt_url..." \
        wget --progress=dot:giga -O /tmp/backhaul.tar.gz "$alt_url"; then
        install_downloaded_binary
        return $?
    else
        handle_error "ERROR" "Download from alternative source '$alt_url' failed."
        return 1
    fi
}

# Network diagnostics menu (moved from menu.sh potentially, or refined)
run_network_diagnostics_menu() {
    _network_diag_help() {
        print_info "Network Diagnostics Help:"
        echo " This tests connectivity to common internet services and GitHub."
        echo " Failures can indicate network configuration issues on your VPS,"
        echo " DNS problems, or regional blocks."
        press_any_key
    }

    local diag_menu_options=("1. Run All Network Tests")
    local diag_exit_options=("0. Back to Installation Options")
    local user_choice diag_rc

    while true; do
        print_menu_header "secondary" "Network Connectivity Diagnostics"
        menu_loop "Select option" diag_menu_options diag_exit_options "_network_diag_help"
        user_choice="$MENU_CHOICE"
        diag_rc=$?

        # Handle global nav from menu_loop if needed, though this is a sub-menu
        if [[ "$diag_rc" -eq 3 ]]; then go_to_main_menu; return; fi
        if [[ "$diag_rc" -eq 4 ]]; then request_script_exit; return; fi
        if [[ "$diag_rc" -eq 2 ]]; then continue; fi

        case "$user_choice" in
            "1")
                print_info "--- Testing General Internet Connectivity ---"
                check_basic_connectivity # Uses a few common hosts like 8.8.8.8, google.com
                echo
                print_info "--- Testing GitHub Connectivity ---"
                local github_hosts=("github.com" "api.github.com" "objects.githubusercontent.com")
                local gh_success_count=0
                for gh_host in "${github_hosts[@]}"; do
                    if run_with_spinner "Pinging $gh_host..." ping -c 1 -W 2 "$gh_host"; then
                        ((gh_success_count++))
                    fi
                done
                 if (( gh_success_count == ${#github_hosts[@]} )); then
                    print_success "All GitHub hosts pingable."
                elif (( gh_success_count > 0 )); then
                    print_warning "Some GitHub hosts not pingable. Downloads might be affected."
                else
                    print_error "Cannot ping any GitHub hosts. Downloads from GitHub will likely fail."
                fi
                press_any_key
                ;;
            "0")
                return # Return to previous menu (download_backhaul_binary_workflow)
                ;;
        esac
    done
}


true # Ensure script is valid