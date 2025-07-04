# backhaul_core.sh
# Download, install, and update Backhaul binary; get server info 

# --- Core Logic ---
SERVER_IP=""
SERVER_COUNTRY=""
SERVER_ISP=""

get_server_info() {
    local response
    response=$(curl -s --connect-timeout 5 http://ip-api.com/json)
    if [ $? -ne 0 ] || [ -z "$response" ]; then
        print_warning "Could not fetch server info from ip-api.com. Continuing without it."
        SERVER_IP="N/A"
        SERVER_COUNTRY="N/A"
        SERVER_ISP="N/A"
        return
    fi
    SERVER_IP=$(echo "$response" | jq -r '.query // "N/A"')
    SERVER_COUNTRY=$(echo "$response" | jq -r '.country // "N/A"')
    SERVER_ISP=$(echo "$response" | jq -r '.isp // "N/A"')
}

print_server_info_banner() {
    print_info "================================================================"
    print_info " Server IP: $SERVER_IP | Location: $SERVER_COUNTRY | ISP: $SERVER_ISP"
    print_info "================================================================"
}

# Verify binary installation
verify_binary_installation() {
    if [[ ! -f "$BIN_PATH" ]]; then
        print_error "Binary not found at expected location: $BIN_PATH"
        return 1
    fi
    
    if [[ ! -x "$BIN_PATH" ]]; then
        print_error "Binary is not executable. Attempting to fix permissions..."
        chmod +x "$BIN_PATH"
        if [[ ! -x "$BIN_PATH" ]]; then
            print_error "Failed to make binary executable."
            return 1
        fi
    fi
    
    # Test if binary works - try both -v and --version flags
    local version_output=""
    if "$BIN_PATH" -v >/dev/null 2>&1; then
        version_output=$("$BIN_PATH" -v 2>/dev/null | head -n1)
    elif "$BIN_PATH" --version >/dev/null 2>&1; then
        version_output=$("$BIN_PATH" --version 2>/dev/null | head -n1)
    else
        print_warning "Binary exists but version check failed."
        print_info "This might indicate an incompatible or corrupted binary."
        print_info "You can still try to use it, but some features might not work."
        return 1
    fi
    print_success "Binary verification successful: $version_output"
    return 0
}

# Test network connectivity to various sources
test_network_connectivity() {
    print_info "--- Network Connectivity Test ---"
    echo
    print_info "Testing connectivity to various sources..."
    echo
    
    local test_urls=(
        "https://api.github.com"
        "https://github.com"
        "https://google.com"
        "https://cloudflare.com"
    )
    
    local test_names=(
        "GitHub API"
        "GitHub Main"
        "Google (general internet)"
        "Cloudflare (CDN)"
    )
    
    for i in "${!test_urls[@]}"; do
        local url="${test_urls[$i]}"
        local name="${test_names[$i]}"
        
        print_info "Testing $name ($url)..."
        if curl -s --connect-timeout 5 --max-time 10 "$url" >/dev/null 2>&1; then
            print_success "✓ $name is accessible"
        else
            print_error "✗ $name is not accessible"
        fi
    done
    
    echo
    print_info "If GitHub is not accessible but other sites are, this might indicate:"
    echo "- GitHub is blocked in your region"
    echo "- Your VPS provider has restrictions"
    echo "- DNS resolution issues for GitHub"
    echo "- Firewall rules blocking GitHub"
    echo
    print_info "If all sites are inaccessible, check your VPS network configuration."
    echo
    press_any_key
}

download_backhaul() {
    print_info "--> Identifying system architecture..."
    local ARCH
    ARCH=$(uname -m)
    local OS
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')

    case $ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        *) print_error_and_exit "Unsupported architecture: $ARCH" ;;
    esac

    # Try to fetch latest version from GitHub
    print_info "--> Fetching latest version from GitHub..."
    local LATEST_VERSION_JSON
    local curl_exit_code
    LATEST_VERSION_JSON=$(curl -s --connect-timeout 10 "https://api.github.com/repos/Musixal/Backhaul/releases/latest")
    curl_exit_code=$?

    local LATEST_VERSION=""
    if [ $curl_exit_code -eq 0 ] && [ -n "$LATEST_VERSION_JSON" ]; then
        # Check if the response is valid JSON and contains tag_name
        if echo "$LATEST_VERSION_JSON" | jq -e . >/dev/null 2>&1; then
            LATEST_VERSION=$(echo "$LATEST_VERSION_JSON" | jq -r .tag_name)
            if [ -z "$LATEST_VERSION" ] || [ "$LATEST_VERSION" == "null" ]; then
                print_warning "Could not determine latest version from GitHub. Using fallback v0.6.6."
                LATEST_VERSION="v0.6.6"
            fi
        else
            print_warning "Invalid JSON response from GitHub API. Using fallback v0.6.6."
            LATEST_VERSION="v0.6.6"
        fi
    else
        print_warning "Failed to contact GitHub API. This might be due to network restrictions."
        echo
        print_info "GitHub access issues detected. Please choose an alternative method:"
        echo
        echo "1. Use local binary file (if you have downloaded it manually)"
        echo "2. Use alternative download source"
        echo "3. Use fallback version (v0.6.6) and try GitHub again"
        echo "4. Show alternative download sources and tips"
        echo "5. Test network connectivity"
        echo "6. Cancel installation"
        echo
        read -p "Select option [1-6]: " download_choice
        
        case $download_choice in
            1) download_from_local_file "$OS" "$ARCH" ;;
            2) download_from_alternative_source "$OS" "$ARCH" ;;
            3) 
                LATEST_VERSION="v0.6.6"
                download_from_github "$LATEST_VERSION" "$OS" "$ARCH"
                ;;
            4) 
                check_alternative_sources "$OS" "$ARCH"
                # After showing tips, ask again
                download_backhaul
                return 0
                ;;
            5) 
                test_network_connectivity
                # After testing, ask again
                download_backhaul
                return 0
                ;;
            6) 
                print_info "Installation cancelled."
                return 1
                ;;
            *) 
                print_error "Invalid option. Installation cancelled."
                return 1
                ;;
        esac
        return 0
    fi

    # If we got here, GitHub is accessible
    download_from_github "$LATEST_VERSION" "$OS" "$ARCH"
}

download_from_github() {
    local version="$1"
    local os="$2"
    local arch="$3"
    
    local download_url="https://github.com/Musixal/Backhaul/releases/download/${version}/backhaul_${os}_${arch}.tar.gz"
    print_info "--> Downloading Backhaul version ${version} from GitHub..."
    
    with_spinner "Downloading from GitHub" wget -q --show-progress --connect-timeout=15 --tries=3 --retry-connrefused -O /tmp/backhaul.tar.gz "$download_url"
    if [ $? -ne 0 ]; then
        print_error "GitHub download failed. Trying alternative methods..."
        echo
        print_info "GitHub download failed. Please choose an alternative method:"
        echo
        echo "1. Use local binary file (if you have downloaded it manually)"
        echo "2. Use alternative download source"
        echo "3. Cancel installation"
        echo
        read -p "Select option [1-3]: " fallback_choice
        
        case $fallback_choice in
            1) download_from_local_file "$os" "$arch" ;;
            2) download_from_alternative_source "$os" "$arch" ;;
            3) 
                print_info "Installation cancelled."
                return 1
                ;;
            *) 
                print_error "Invalid option. Installation cancelled."
                return 1
                ;;
        esac
        return 0
    fi

    install_downloaded_binary
}

download_from_local_file() {
    local os="$1"
    local arch="$2"
    
    print_info "--> Local file installation mode"
    echo
    print_info "Please provide the path to your local Backhaul binary file."
    print_info "Supported formats: .tar.gz, .zip, or direct binary file"
    echo
    print_info "Expected filename pattern: backhaul_${os}_${arch}.tar.gz"
    echo
    read -e -p "Enter path to local file: " local_file_path
    
    if [[ -z "$local_file_path" ]]; then
        print_error "No file path provided. Installation cancelled."
        return 1
    fi
    
    if [[ ! -f "$local_file_path" ]]; then
        print_error "File not found: $local_file_path"
        return 1
    fi
    
    # Determine file type and handle accordingly
    local file_extension
    file_extension=$(echo "$local_file_path" | sed 's/.*\.//' | tr '[:upper:]' '[:lower:]')
    
    case $file_extension in
        tar.gz|tgz)
            print_info "--> Detected .tar.gz file, copying to temporary location..."
            cp "$local_file_path" /tmp/backhaul.tar.gz
            ;;
        zip)
            print_info "--> Detected .zip file, extracting to temporary location..."
            if ! unzip -q "$local_file_path" -d /tmp/ 2>/dev/null; then
                print_error "Failed to extract .zip file. Please check if the file is valid."
                return 1
            fi
            # Look for the binary in the extracted contents
            if [[ -f "/tmp/backhaul" ]]; then
                # Create a tar.gz structure for consistency
                tar -czf /tmp/backhaul.tar.gz -C /tmp backhaul
                rm -f /tmp/backhaul
            else
                print_error "Could not find 'backhaul' binary in the extracted .zip file."
                rm -rf /tmp/backhaul*
                return 1
            fi
            ;;
        *)
            # Assume it's a direct binary file
            print_info "--> Detected direct binary file, creating archive structure..."
            if [[ -x "$local_file_path" ]] || [[ -f "$local_file_path" ]]; then
                # Create a tar.gz with the binary
                tar -czf /tmp/backhaul.tar.gz -C "$(dirname "$local_file_path")" "$(basename "$local_file_path")"
            else
                print_error "File is not executable or readable. Please check permissions."
                return 1
            fi
            ;;
    esac
    
    if [[ $? -ne 0 ]]; then
        print_error "Failed to prepare local file for installation."
        return 1
    fi
    
    install_downloaded_binary
}

download_from_alternative_source() {
    local os="$1"
    local arch="$2"
    
    print_info "--> Alternative download source mode"
    echo
    print_info "Please provide an alternative download URL for the Backhaul binary."
    print_info "The URL should point to a .tar.gz file containing the binary."
    echo
    print_info "Expected filename pattern: backhaul_${os}_${arch}.tar.gz"
    echo
    print_info "Example sources:"
    echo "- Your own server: https://your-server.com/backhaul_${os}_${arch}.tar.gz"
    echo "- Alternative CDN: https://cdn.example.com/backhaul_${os}_${arch}.tar.gz"
    echo "- Direct file server: http://files.example.com/backhaul_${os}_${arch}.tar.gz"
    echo
    read -p "Enter alternative download URL: " alt_url
    
    if [[ -z "$alt_url" ]]; then
        print_error "No URL provided. Installation cancelled."
        return 1
    fi
    
    print_info "--> Downloading from alternative source..."
    wget -q --show-progress --connect-timeout=15 --tries=3 --retry-connrefused -O /tmp/backhaul.tar.gz "$alt_url"
    
    if [[ $? -ne 0 ]]; then
        print_error "Alternative download failed. Please check the URL and try again."
        return 1
    fi
    
    install_downloaded_binary
}

install_downloaded_binary() {
    print_info "--> Extracting binary to $BIN_PATH..."
    
    # Check if the downloaded file is actually a tar.gz
    if ! tar -tzf /tmp/backhaul.tar.gz >/dev/null 2>&1; then
        print_error "The downloaded file is not a valid tar.gz archive."
        print_info "Please check your download source and try again."
        rm -f /tmp/backhaul.tar.gz
        return 1
    fi
    
    # Extract the binary
    tar -xzf /tmp/backhaul.tar.gz -C "$(dirname "$BIN_PATH")" "$(basename "$BIN_PATH")" 
    if [[ $? -ne 0 ]]; then
        print_error "Extraction failed. The archive might be corrupted or contain unexpected files."
        rm -f /tmp/backhaul.tar.gz
        return 1
    fi
    
    # Clean up and set permissions
    rm -f /tmp/backhaul.tar.gz
    chmod +x "$BIN_PATH"
    
    # Verify the binary works
    if verify_binary_installation; then
        print_success "Backhaul binary installation completed successfully!"
    else
        print_warning "Binary installation completed but verification failed."
        print_info "The binary might be incompatible or corrupted."
        print_info "You can still try to use it, but some features might not work correctly."
    fi
} 