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
    local pids=()
    local temp_output_files=()

    for service_url in "${services_to_try[@]}"; do
        local temp_output_file
        temp_output_file=$(mktemp "$EASYBACKHAUL_TMP_DIR/ipinfo.XXXXXX")
        temp_output_files+=("$temp_output_file")
        (curl -s --connect-timeout 3 --max-time 8 "$service_url" > "$temp_output_file" 2>/dev/null) &
        pids+=($!)
    done

    # Wait for the first successful response
    local success=false
    while [[ ${#pids[@]} -gt 0 ]] && [[ "$success" == "false" ]]; do
        for i in "${!pids[@]}"; do
            if ! kill -0 "${pids[$i]}" 2>/dev/null; then
                # Process finished
                local response_json
                response_json=$(cat "${temp_output_files[$i]}")
                if [[ -n "$response_json" ]] && echo "$response_json" | jq -e . >/dev/null 2>&1; then
                    local ip country isp
                    ip=$(echo "$response_json" | jq -r '.ip // .query // "N/A"')
                    country=$(echo "$response_json" | jq -r '.country // .country_name // "N/A"')
                    isp=$(echo "$response_json" | jq -r '.isp // .org // "N/A"')

                    if [[ "$ip" != "N/A" && "$ip" != "null" ]]; then
                        SERVER_IP="$ip"
                        SERVER_COUNTRY="$country"
                        SERVER_ISP="$isp"
                        log_message "INFO" "Server info fetched from ${services_to_try[$i]}: IP=$SERVER_IP, Country=$SERVER_COUNTRY, ISP=$SERVER_ISP"
                        success=true
                        break
                    fi
                fi
                # Remove pid and temp file from lists
                unset 'pids[$i]'
                rm -f "${temp_output_files[$i]}"
                unset 'temp_output_files[$i]'
            fi
        done
        sleep 0.1
    done

    # Kill any remaining curl processes
    for pid in "${pids[@]}"; do
        kill "$pid" 2>/dev/null
    done

    # Clean up any remaining temp files
    for temp_file in "${temp_output_files[@]}"; do
        rm -f "$temp_file"
    done

    if [[ "$success" == "true" ]]; then
        return 0
    fi

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
    local archive_path="$EASYBACKHAUL_APP_DIR/backhaul.tar.gz"
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
    if [[ ! -r "$archive_path" ]]; then
        handle_error "ERROR" "File $archive_path is not readable."
        return 1
    fi

    local temp_extract_dir
    temp_extract_dir=$(mktemp -d "$EASYBACKHAUL_APP_DIR/backhaul_extract_XXXXXX")

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
        "2. Install from Local .tar.gz File"
        "3. Use Existing Local Binary File" # New option
        "4. Install from Alternative URL"
        "5. Run Network Diagnostics"
        "6. Skip Installation (Advanced)"
    )
    local user_choice menu_rc

    while true; do
        print_menu_header "primary" "Backhaul Binary Installation" "Choose Installation Method"
        menu_loop "Select option" menu_options "_download_menu_help"
        local menu_rc=$?
        local user_choice="$MENU_CHOICE" # Capture MENU_CHOICE after $?
        
        local install_attempted=false
        local install_succeeded=false

        case "$menu_rc" in
            0) # Numeric choice
                install_attempted=true # Assume an install attempt unless it's diagnostics/skip
                case "$user_choice" in
                    "1") # GitHub Download
                        if _download_from_github "$system_os" "$detected_arch_suffix"; then install_succeeded=true; fi
                        ;;
                    "2") # Local .tar.gz File
                        if _download_from_local_file "$system_os" "$detected_arch_suffix"; then install_succeeded=true; fi
                        ;;
                    "3") # Use Existing Local Binary File (New)
                        if _use_existing_local_binary; then install_succeeded=true; fi
                        ;;
                    "4") # Alternative URL
                        if _download_from_alternative_source "$system_os" "$detected_arch_suffix"; then install_succeeded=true; fi
                        ;;
                    "5") # Network Diagnostics
                        if type run_network_diagnostics_menu &>/dev/null; then
                            navigate_to_menu "run_network_diagnostics_menu"
                            return 0 # Let main loop call it; run_network_diagnostics_menu will return here
                        else
                            handle_error "ERROR" "Network diagnostics function not available."; press_any_key
                        fi
                        install_attempted=false # Not an install attempt
                        ;;
                    "6") # Skip
                        print_warning "Skipping binary installation."
                        print_info "You can install the binary later using the main menu."
                        print_info "Ensure it's placed at: $BIN_PATH"
                        press_any_key
                        return 0 # Successfully skipped
                        ;;
                    *)
                        print_warning "Invalid option selected in download workflow: $user_choice"; press_any_key
                        install_attempted=false
                        ;;
                esac
                ;;
            2) # '?' Help
                # Help function already called by menu_loop. Loop again to show menu.
                continue ;;
            3) # 'm' Main Menu
                # Treat 'm' as cancel for this specific workflow, as main menu might not be fully set up
                # if this is called during initial installation.
                print_info "Installation workflow cancelled via 'm' key (treated as return/cancel)."
                press_any_key
                return 1 ;; # Return 1 to indicate cancellation of the workflow
            4) # 'x' Exit script
                request_script_exit
                return 0 ;; # Return to main script loop to process exit
            5) # 'r' Return/Back/Cancel (cancel installation workflow)
               print_info "Installation workflow cancelled via 'r' key."
               press_any_key
               return 1 ;; # Return 1 to indicate cancellation
            6)  # Invalid input in menu_loop
                continue ;; # Re-display menu options
            *)
                print_warning "Unexpected menu_loop return code in download_backhaul_binary_workflow: $menu_rc (Choice: $user_choice)"
                press_any_key
                continue ;; # Re-display menu options
        esac

        if $install_attempted; then
            if $install_succeeded; then
                # install_downloaded_binary (called by _download_* helpers) already verifies.
                # If it returns success, we assume verification passed.
                return 0 # Overall success for download_backhaul_binary_workflow
            else
                # Error messages are handled within _download_* or install_downloaded_binary
                # Loop will continue to re-prompt installation method.
                # press_any_key is already called if install_succeeded is false by now
                # or if an invalid numeric choice was made.
                : # No additional press_any_key needed here, already handled.
            fi
        fi
        # If not an install attempt (like diagnostics or invalid option that didn't take action), loop continues.
        # The main case statement's default or specific error paths should call press_any_key if needed.
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
            log_message "WARN" "Could not parse tag_name from GitHub API response."
            latest_version=""
        else
            log_message "INFO" "Latest version from GitHub: $latest_version"
        fi
    else
        handle_error "WARNING" "Failed to fetch latest version from GitHub API. Check connectivity or API rate limits."
        # Try to fetch the latest tag from the releases page as a fallback
        latest_version=$(curl -s https://github.com/Musixal/Backhaul/releases | grep -oE '/Musixal/Backhaul/releases/tag/v[0-9.]+' | head -n1 | grep -oE 'v[0-9.]+' )
        if [[ -z "$latest_version" ]]; then
            print_error "Could not determine the latest Backhaul version. Please check your network connection or manually download the binary."
            print_info "You can use the 'Install from Local .tar.gz File' or 'Install from Alternative URL' options."
            press_any_key
            return 1
        else
            log_message "INFO" "Fallback: Found latest version from releases page: $latest_version"
        fi
    fi

    local download_url="https://github.com/Musixal/Backhaul/releases/download/${latest_version}/backhaul_${os}_${arch_suffix}.tar.gz"
    print_info "Attempting to download Backhaul ${latest_version} for ${os}/${arch_suffix}..."
    echo "URL: $download_url"

    if run_with_spinner "Downloading from GitHub..." \
        wget --progress=dot:giga -O "$EASYBACKHAUL_APP_DIR/backhaul.tar.gz" "$download_url"; then
        if install_downloaded_binary; then # install_downloaded_binary returns 0 on success
            return 0 # Overall success
        else
            handle_error "ERROR" "Binary installation failed after download."
            return 1 # Installation part failed
        fi
    else
        handle_error "ERROR" "Download from GitHub failed. URL: $download_url"
        print_info "You may want to try another installation method or check the available versions at: https://github.com/Musixal/Backhaul/releases"
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
        read -e -r -p "Enter path to local .tar.gz file (or type 'cancel' to return): " local_file_path
        local lower_case_input
        lower_case_input=$(echo "$local_file_path" | tr '[:upper:]' '[:lower:]')

        if [[ "$lower_case_input" == "cancel" ]]; then
            print_info "Local file installation cancelled."
            return 1 # Indicate cancellation
        fi

        if [[ -z "$local_file_path" ]]; then
            if prompt_yes_no "Path cannot be empty. Cancel local file installation?" "y"; then return 1; fi
            continue
        fi
        if [[ ! -f "$local_file_path" ]]; then
            if prompt_yes_no "File not found: '$local_file_path'. Try again?" "y"; then continue; else return 1; fi
        fi
        # Relaxed check for .tar.gz, install_downloaded_binary will verify archive integrity.
        break
    done

    log_message "INFO" "Copying local file '$local_file_path' to $EASYBACKHAUL_APP_DIR/backhaul.tar.gz"
    if cp "$local_file_path" "$EASYBACKHAUL_APP_DIR/backhaul.tar.gz"; then
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
        wget --progress=dot:giga -O "$EASYBACKHAUL_APP_DIR/backhaul.tar.gz" "$alt_url"; then
        if install_downloaded_binary; then return 0; else return 1; fi
    else
        handle_error "ERROR" "Download from alternative source '$alt_url' failed."
        return 1
    fi
}

_use_existing_local_binary() {
    print_menu_header "secondary" "Use Existing Local Binary" \
        "Point to an already extracted Backhaul binary file."

    local local_binary_path
    while true; do
        read -e -r -p "Enter full path to your local Backhaul binary file (or type 'cancel' to return): " local_binary_path
        local lower_case_input
        lower_case_input=$(echo "$local_binary_path" | tr '[:upper:]' '[:lower:]')

        if [[ "$lower_case_input" == "cancel" ]]; then
            print_info "Using existing local binary cancelled."
            return 1 # Indicate cancellation
        fi

        if [[ -z "$local_binary_path" ]]; then
            if prompt_yes_no "Path cannot be empty. Cancel providing local binary?" "y"; then return 1; fi
            continue
        fi
        if [[ ! -f "$local_binary_path" ]]; then
            if prompt_yes_no "File not found: '$local_binary_path'. Try again?" "y"; then continue; else return 1; fi
        fi
        if [[ ! -x "$local_binary_path" ]]; then
            print_warning "File '$local_binary_path' is not executable."
            if prompt_yes_no "Attempt to make it executable (chmod +x)?" "y"; then
                chmod +x "$local_binary_path"
                if [[ ! -x "$local_binary_path" ]]; then
                    handle_error "ERROR" "Failed to make '$local_binary_path' executable."
                    if prompt_yes_no "Try a different path?" "y"; then continue; else return 1; fi
                else
                    print_success "File '$local_binary_path' is now executable."
                fi
            else
                if prompt_yes_no "Try a different path?" "y"; then continue; else return 1; fi
            fi
        fi
        break # Path is valid, file exists, and is executable
    done

    local target_bin_dir
    target_bin_dir=$(dirname "$BIN_PATH")
    ensure_dir "$target_bin_dir" "755" # Ensure target directory exists (e.g., /tmp/easybackhaul_bin)

    log_message "INFO" "Copying user-provided binary '$local_binary_path' to '$BIN_PATH'"
    if cp "$local_binary_path" "$BIN_PATH"; then
        # Ensure the copied binary also has correct execute permissions
        chmod +x "$BIN_PATH"
        set_secure_file_permissions "$BIN_PATH" "755"

        if verify_binary_installation; then # verify_binary_installation uses global BIN_PATH
            handle_success "Backhaul binary copied from '$local_binary_path' and verified successfully!"
            print_info "Summary: 📁 $BIN_PATH | 🔒 $(stat -c %a "$BIN_PATH") | 📊 $(du -h "$BIN_PATH" | cut -f1)"
            return 0 # Success
        else
            handle_error "ERROR" "Binary copied to $BIN_PATH, but verification failed. It may be incompatible or corrupted."
            # Optionally, offer to remove the copied file from BIN_PATH
            secure_delete "$BIN_PATH" 2>/dev/null
            return 1 # Verification failed
        fi
    else
        handle_error "ERROR" "Failed to copy binary from '$local_binary_path' to '$BIN_PATH'."
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
    local user_choice diag_rc # Renamed from menu_rc to avoid conflict with outer scope

    while true; do
        print_menu_header "secondary" "Network Connectivity Diagnostics"
        menu_loop "Select option" diag_menu_options "_network_diag_help"
        local diag_rc=$? # Capture $? first
        local user_choice="$MENU_CHOICE" # Then MENU_CHOICE

        case "$diag_rc" in
            0) # Numeric choice
                case "$user_choice" in
                    "1")
                        print_info "--- Testing General Internet Connectivity ---"
                        check_basic_connectivity
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
                    *) print_warning "Invalid option in network diagnostics: $user_choice"; press_any_key;;
                esac
                ;;
            2) # '?' Help
                # Help function already called by menu_loop. Loop again to show menu.
                continue ;;
            3) # 'm' Main Menu
                go_to_main_menu
                return 0 ;; # Return to main script loop
            4) # 'x' Exit script
                request_script_exit
                return 0 ;; # Return to main script loop
            5) # 'r' Return/Back/Cancel (to previous menu - download_backhaul_binary_workflow)
                return_from_menu # This pops the stack
                return 0 ;; # Return to main script loop
            6)  # Invalid input in menu_loop
                continue ;; # Re-display this menu
            *)
                print_warning "Unexpected menu_loop return code in run_network_diagnostics_menu: $diag_rc (Choice: $user_choice)"
                press_any_key
                continue ;; # Re-display this menu
        esac
    done
}


true # Ensure script is valid