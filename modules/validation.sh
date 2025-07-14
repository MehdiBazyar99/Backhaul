# validation.sh
# Comprehensive configuration validation for all Backhaul protocols

# WARNING: Do not use a global CONFIG_FILE variable. Always pass config file paths explicitly to functions.

# --- Configuration Validation ---
# Validate configuration file with protocol-specific checks
validate_tunnel_config() {
    local config_file="$1"
    local errors=0
    local warnings=0
    
    if [[ ! -f "$config_file" ]]; then
        log_error "Configuration file not found: $config_file"
        return 1
    fi
    
    print_info "=== Configuration Validation ==="
    echo
    
    # Check for required sections
    local required_sections=("server" "client")
    local found_sections=()
    
    for section in "${required_sections[@]}"; do
        if grep -q "^\[$section\]" "$config_file"; then
            found_sections+=("$section")
        fi
    done
    
    if [[ ${#found_sections[@]} -eq 0 ]]; then
        log_error "Missing required section [server] or [client] in config file"
        ((errors++))
    else
        print_success "Found section(s): ${found_sections[*]}"
    fi
    
    # Check for basic syntax errors
    if ! grep -q "^\[.*\]\|^[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*=" "$config_file"; then
        log_error "Invalid configuration syntax in $config_file"
        ((errors++))
    fi
    
    # Validate port numbers
    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*port[[:space:]]*=[[:space:]]*([0-9]+) ]]; then
            local port="${BASH_REMATCH[1]}"
            if [[ $port -lt 1 || $port -gt 65535 ]]; then
                log_error "Invalid port number: $port (must be 1-65535)"
                ((errors++))
            fi
        fi
    done < "$config_file"
    
    # Protocol-specific validation
    validate_protocol_config "$config_file"
    local protocol_errors=$?
    errors=$((errors + protocol_errors))
    
    # Advanced validation checks
    validate_advanced_config "$config_file"
    local advanced_errors=$?
    local advanced_warnings=$?
    errors=$((errors + advanced_errors))
    warnings=$((warnings + advanced_warnings))
    
    if [[ $errors -gt 0 ]]; then
        log_error "Configuration validation failed with $errors error(s) and $warnings warning(s)"
        return 1
    fi
    
    if [[ $warnings -gt 0 ]]; then
        log_warn "Configuration validation passed with $warnings warning(s)"
    else
        log_info "Configuration validation passed"
    fi
    
    return 0
}

# Protocol-specific validation
validate_protocol_config() {
    local config_file="$1"
    local errors=0
    local transport=""
    
    # Detect transport protocol
    transport=$(grep '^transport[[:space:]]*=' "$config_file" | cut -d'"' -f2)
    
    if [[ -z "$transport" ]]; then
        print_error "Missing required 'transport' field"
        return 1
    fi
    
    print_info "--- Protocol Validation ($transport) ---"
    
    case "$transport" in
        "tcp")
            validate_tcp_config "$config_file"
            errors=$?
            ;;
        "tcpmux")
            validate_tcpmux_config "$config_file"
            errors=$?
            ;;
        "udp")
            validate_udp_config "$config_file"
            errors=$?
            ;;
        "ws")
            validate_ws_config "$config_file"
            errors=$?
            ;;
        "wss")
            validate_wss_config "$config_file"
            errors=$?
            ;;
        "wsmux")
            validate_wsmux_config "$config_file"
            errors=$?
            ;;
        "wssmux")
            validate_wssmux_config "$config_file"
            errors=$?
            ;;
        *)
            print_error "Unsupported transport protocol: $transport"
            return 1
            ;;
    esac
    
    return $errors
}

# TCP protocol validation
validate_tcp_config() {
    local config_file="$1"
    local errors=0
    
    # Check required fields
    if ! grep -q '^bind_addr\|^remote_addr' "$config_file"; then
        print_error "Missing required address field (bind_addr for server, remote_addr for client)"
        ((errors++))
    fi
    
    # Check optional but recommended fields
    if ! grep -q '^token' "$config_file"; then
        print_warning "No authentication token specified (recommended for security)"
    fi
    
    # Validate numeric fields
    validate_numeric_field "$config_file" "heartbeat" 1 3600
    validate_numeric_field "$config_file" "channel_size" 1 65536
    validate_numeric_field "$config_file" "keepalive_period" 1 3600
    validate_numeric_field "$config_file" "web_port" 0 65535
    
    # Validate boolean fields
    validate_boolean_field "$config_file" "accept_udp"
    validate_boolean_field "$config_file" "nodelay"
    validate_boolean_field "$config_file" "sniffer"
    
    return $errors
}

# TCP Multiplexing protocol validation
validate_tcpmux_config() {
    local config_file="$1"
    local errors=0
    
    # Include TCP validation
    validate_tcp_config "$config_file"
    errors=$?
    
    # Check multiplexing-specific fields
    validate_numeric_field "$config_file" "mux_con" 1 64
    validate_numeric_field "$config_file" "mux_version" 1 2
    validate_numeric_field "$config_file" "mux_framesize" 1024 1048576
    validate_numeric_field "$config_file" "mux_recievebuffer" 1024 16777216
    validate_numeric_field "$config_file" "mux_streambuffer" 1024 1048576
    
    return $errors
}

# UDP protocol validation
validate_udp_config() {
    local config_file="$1"
    local errors=0
    
    # Check required fields
    if ! grep -q '^bind_addr\|^remote_addr' "$config_file"; then
        print_error "Missing required address field (bind_addr for server, remote_addr for client)"
        ((errors++))
    fi
    
    # Check optional but recommended fields
    if ! grep -q '^token' "$config_file"; then
        print_warning "No authentication token specified (recommended for security)"
    fi
    
    # Validate numeric fields
    validate_numeric_field "$config_file" "heartbeat" 1 3600
    validate_numeric_field "$config_file" "channel_size" 1 65536
    validate_numeric_field "$config_file" "web_port" 0 65535
    
    # Validate boolean fields
    validate_boolean_field "$config_file" "sniffer"
    
    return $errors
}

# WebSocket protocol validation
validate_ws_config() {
    local config_file="$1"
    local errors=0
    
    # Check required fields
    if ! grep -q '^bind_addr\|^remote_addr' "$config_file"; then
        print_error "Missing required address field (bind_addr for server, remote_addr for client)"
        ((errors++))
    fi
    
    # Check optional but recommended fields
    if ! grep -q '^token' "$config_file"; then
        print_warning "No authentication token specified (recommended for security)"
    fi
    
    # Validate numeric fields and count errors
    if ! validate_numeric_field "$config_file" "heartbeat" 1 3600; then
        ((errors++))
    fi
    if ! validate_numeric_field "$config_file" "channel_size" 1 65536; then
        ((errors++))
    fi
    if ! validate_numeric_field "$config_file" "keepalive_period" 1 3600; then
        ((errors++))
    fi
    if ! validate_numeric_field "$config_file" "web_port" 0 65535; then
        ((errors++))
    fi
    
    # Validate boolean fields and count errors
    if ! validate_boolean_field "$config_file" "nodelay"; then
        ((errors++))
    fi
    if ! validate_boolean_field "$config_file" "sniffer"; then
        ((errors++))
    fi
    
    return $errors
}

# Secure WebSocket protocol validation
validate_wss_config() {
    local config_file="$1"
    local errors=0
    
    # Include WS validation
    validate_ws_config "$config_file"
    errors=$?
    
    # Check TLS certificate files
    local tls_cert tls_key
    tls_cert=$(grep '^tls_cert' "$config_file" | cut -d'"' -f2)
    tls_key=$(grep '^tls_key' "$config_file" | cut -d'"' -f2)
    
    if [[ -z "$tls_cert" ]]; then
        print_error "Missing required tls_cert field for WSS transport"
        ((errors++))
    elif [[ ! -f "$tls_cert" ]]; then
        print_error "TLS certificate file not found: $tls_cert"
        ((errors++))
    fi
    
    if [[ -z "$tls_key" ]]; then
        print_error "Missing required tls_key field for WSS transport"
        ((errors++))
    elif [[ ! -f "$tls_key" ]]; then
        print_error "TLS key file not found: $tls_key"
        ((errors++))
    fi
    
    return $errors
}

# WebSocket Multiplexing protocol validation
validate_wsmux_config() {
    local config_file="$1"
    local errors=0
    
    # Include WS validation
    validate_ws_config "$config_file"
    errors=$?
    
    # Check multiplexing-specific fields
    validate_numeric_field "$config_file" "mux_con" 1 64
    validate_numeric_field "$config_file" "mux_version" 1 2
    validate_numeric_field "$config_file" "mux_framesize" 1024 1048576
    validate_numeric_field "$config_file" "mux_recievebuffer" 1024 16777216
    validate_numeric_field "$config_file" "mux_streambuffer" 1024 1048576
    
    return $errors
}

# Secure WebSocket Multiplexing protocol validation
validate_wssmux_config() {
    local config_file="$1"
    local errors=0
    
    # Include WSS validation
    validate_wss_config "$config_file"
    errors=$?
    
    # Check multiplexing-specific fields
    validate_numeric_field "$config_file" "mux_con" 1 64
    validate_numeric_field "$config_file" "mux_version" 1 2
    validate_numeric_field "$config_file" "mux_framesize" 1024 1048576
    validate_numeric_field "$config_file" "mux_recievebuffer" 1024 16777216
    validate_numeric_field "$config_file" "mux_streambuffer" 1024 1048576
    
    return $errors
}

# Advanced configuration validation
validate_advanced_config() {
    local config_file="$1"
    local errors=0
    local warnings=0
    
    # Check for syntax errors with improved regex
    local syntax_errors
    syntax_errors=$(grep -v "^[[:space:]]*#" "$config_file" | grep -v "^[[:space:]]*$" | grep -v "^\[.*\]" | grep -v "^[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*=[[:space:]]*[^[:space:]]*" | wc -l)
    if [[ $syntax_errors -gt 0 ]]; then
        print_warning "Found $syntax_errors potential syntax issues"
        ((warnings++))
    fi
    
    # Check for deprecated or invalid fields
    local deprecated_fields=("mux_session" "edge_ip")
    for field in "${deprecated_fields[@]}"; do
        if grep -q "^$field[[:space:]]*=" "$config_file"; then
            print_warning "Deprecated field found: $field"
            ((warnings++))
        fi
    done
    
    # Check for security issues
    if grep -q '^token[[:space:]]*=[[:space:]]*""' "$config_file"; then
        print_warning "Empty authentication token (security risk)"
        ((warnings++))
    fi
    
    # Check for performance issues
    local channel_size
    channel_size=$(grep '^channel_size' "$config_file" | cut -d'"' -f2)
    if [[ -n "$channel_size" && $channel_size -gt 8192 ]]; then
        print_warning "High channel_size ($channel_size) may impact performance"
        ((warnings++))
    fi
    
    # Check for file permissions (if files exist)
    local sniffer_log
    sniffer_log=$(grep '^sniffer_log' "$config_file" | cut -d'"' -f2)
    if [[ -n "$sniffer_log" && -f "$sniffer_log" ]]; then
        if [[ ! -r "$sniffer_log" ]]; then
            print_error "Sniffer log file not readable: $sniffer_log"
            ((errors++))
        fi
    fi
    
    # Check for port conflicts
    validate_port_conflicts "$config_file"
    local port_conflicts=$?
    warnings=$((warnings + port_conflicts))
    
    return $errors
}

# Validate numeric field with range
validate_numeric_field() {
    local config_file="$1"
    local field="$2"
    local min="$3"
    local max="$4"
    
    local value
    # Handle both quoted and unquoted values
    value=$(grep "^$field[[:space:]]*=" "$config_file" | sed 's/^[^=]*=[[:space:]]*//' | sed 's/^"\(.*\)"$/\1/' | sed 's/^'\''\(.*\)'\''$/\1/')
    
    if [[ -n "$value" ]]; then
        if [[ ! "$value" =~ ^[0-9]+$ ]]; then
            print_error "Invalid $field value: $value (must be numeric)"
            return 1
        elif [[ $value -lt $min || $value -gt $max ]]; then
            print_error "Invalid $field value: $value (must be $min-$max)"
            return 1
        fi
    fi
    
    return 0
}

# Validate boolean field
validate_boolean_field() {
    local config_file="$1"
    local field="$2"
    
    local value
    # Handle both quoted and unquoted values
    value=$(grep "^$field[[:space:]]*=" "$config_file" | sed 's/^[^=]*=[[:space:]]*//' | sed 's/^"\(.*\)"$/\1/' | sed 's/^'\''\(.*\)'\''$/\1/')
    
    if [[ -n "$value" ]]; then
        if [[ ! "$value" =~ ^(true|false)$ ]]; then
            print_error "Invalid $field value: $value (must be true or false)"
            return 1
        fi
    fi
    
    return 0
}

# Validate port conflicts
validate_port_conflicts() {
    local config_file="$1"
    local warnings=0
    
    # Extract ports from config
    local ports=()
    while IFS= read -r line; do
        if [[ "$line" =~ bind_addr.*:([0-9]+) ]]; then
            ports+=("${BASH_REMATCH[1]}")
        elif [[ "$line" =~ remote_addr.*:([0-9]+) ]]; then
            ports+=("${BASH_REMATCH[1]}")
        elif [[ "$line" =~ web_port[[:space:]]*=[[:space:]]*([0-9]+) ]]; then
            ports+=("${BASH_REMATCH[1]}")
        fi
    done < "$config_file"
    
    # Check for duplicate ports
    local unique_ports=($(printf '%s\n' "${ports[@]}" | sort -u))
    if [[ ${#ports[@]} -ne ${#unique_ports[@]} ]]; then
        print_warning "Duplicate ports detected in configuration"
        ((warnings++))
    fi
    
    # Check for common port conflicts
    for port in "${ports[@]}"; do
        case $port in
            22|80|443|3306|5432|6379|8080|8443)
                print_warning "Port $port is commonly used by other services"
                ((warnings++))
                ;;
        esac
    done
    
    return $warnings
}
