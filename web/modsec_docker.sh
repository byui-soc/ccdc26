#!/usr/bin/env bash

function install_modsecurity_docker {
    print_banner "Dockerized ModSecurity Installation (Strict Mode)"
    
    # Check if Docker is installed
    if ! command -v docker &>/dev/null; then
        log_warning "Docker is not installed."
        log_info "Skipping Dockerized ModSecurity - Docker not available."
        log_info "Install Docker manually if you want to use this feature."
        return 0
    fi

    # Check if Docker service is running
    if ! sudo systemctl is-active --quiet docker 2>/dev/null && ! sudo docker ps &>/dev/null; then
        log_warning "Docker service is not running."
        log_info "Skipping Dockerized ModSecurity - Docker service not active."
        return 0
    fi

    # Determine the recommended ModSecurity Docker image
    local default_image="owasp/modsecurity-crs:nginx-alpine"
    
    # In Ansible mode, use the recommended image automatically; otherwise allow user override.
    local image
    if [ "$ANSIBLE" == "true" ]; then
        image="$default_image"
        log_info "Ansible mode: Using recommended ModSecurity Docker image: $image"
    else
        read -p "Enter ModSecurity Docker image to use [default: $default_image]: " user_image
        if [ -n "$user_image" ]; then
            image="$user_image"
        else
            image="$default_image"
        fi
    fi

    # Generate the strict configuration file for ModSecurity.
    local modsec_conf
    modsec_conf=$(generate_strict_modsec_conf)

    echo "[INFO] Pulling Docker image: $image"
    if ! sudo docker pull "$image"; then
        log_warning "Failed to pull Docker image: $image"
        log_info "Skipping Dockerized ModSecurity - image pull failed."
        return 0
    fi

    echo "[INFO] Running Dockerized ModSecurity container with strict configuration..."
    # Run the container with port mapping (adjust if needed) and mount the strict config file as read-only.
    if ! sudo docker run -d --name dockerized_modsec -p 80:80 \
         -v "$modsec_conf":/etc/modsecurity/modsecurity.conf:ro \
         "$image"; then
        log_warning "Failed to start Dockerized ModSecurity container."
        log_info "Check Docker logs for details: docker logs dockerized_modsec"
        return 0
    fi

    if sudo docker ps | grep -q dockerized_modsec; then
        log_success "Dockerized ModSecurity container 'dockerized_modsec' is running with strict settings."
        return 0
    else
        log_warning "Dockerized ModSecurity container may not have started properly."
        log_info "Check Docker status: docker ps -a"
        return 0
    fi
}
