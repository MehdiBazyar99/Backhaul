# prereqs.sh
# Root check and dependency installation logic

# --- Prerequisite Checks ---
check_root() {
    if [[ $EUID -ne 0 ]]; then
       print_error_and_exit "This script must be run as root or with sudo."
    fi
}

check_dependencies() {
    print_info "--> Checking for required dependencies (curl, wget, tar, jq, nc, ss)..."
    local needs_install=()
    for cmd in curl wget tar jq nc ss; do
        if ! command -v $cmd &> /dev/null; then
            # 'ss' is usually in 'iproute2' or 'iproute' package
            if [[ "$cmd" == "ss" ]]; then
                needs_install+=("iproute2")
            else
                needs_install+=("$cmd")
            fi
        fi
    done

    if [ ${#needs_install[@]} -gt 0 ]; then
        print_warning "The following dependencies are missing: ${needs_install[*]}. Attempting to install..."
        if command -v apt-get &> /dev/null; then
            with_spinner "Installing dependencies" apt-get update >/dev/null && apt-get install -y --no-install-recommends "${needs_install[@]}" >/dev/null
        elif command -v yum &> /dev/null; then
            with_spinner "Installing dependencies" yum install -y "${needs_install[@]}" >/dev/null
        else
            print_error_and_exit "Unsupported package manager. Please install '${needs_install[*]}' manually."
        fi
    fi
    print_success "All dependencies are satisfied."
}

