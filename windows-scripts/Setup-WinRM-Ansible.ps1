#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Configure Windows for Ansible WinRM management
.DESCRIPTION
    Sets up WinRM to allow Ansible connections from the Ubuntu management network.
    Run this on each Windows machine that needs to be managed by Ansible.
.PARAMETER ManagementSubnet
    The subnet where the Ansible controller is located (default: 172.20.242.0/24)
.PARAMETER ControllerIP
    Specific IP of the Ansible controller (optional, adds to TrustedHosts)
.EXAMPLE
    .\Setup-WinRM-Ansible.ps1
    .\Setup-WinRM-Ansible.ps1 -ControllerIP 172.20.242.38
.NOTES
    Run as Administrator
#>

[CmdletBinding()]
param(
    [string]$ManagementSubnet = "172.20.242.0/24",
    [string]$ControllerIP = ""
)

# Require admin privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

Write-Host "`n=== Setting Up WinRM for Ansible ===" -ForegroundColor Cyan

# 1. Enable WinRM service
Write-Host "`n[1/6] Enabling WinRM service..." -ForegroundColor Yellow
try {
    $winrmService = Get-Service WinRM -ErrorAction SilentlyContinue
    if ($winrmService.Status -ne "Running") {
        Set-Service -Name WinRM -StartupType Automatic
        Start-Service WinRM
        Write-Host "  ✓ WinRM service started" -ForegroundColor Green
    } else {
        Write-Host "  ✓ WinRM service already running" -ForegroundColor Green
    }
} catch {
    Write-Error "Failed to start WinRM service: $_"
    exit 1
}

# 2. Configure WinRM to accept connections
Write-Host "`n[2/6] Configuring WinRM listeners..." -ForegroundColor Yellow
try {
    # Remove existing listeners and recreate
    Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys -contains "Transport=HTTP" } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    
    # Create HTTP listener on all interfaces
    winrm create winrm/config/Listener?Address=*+Transport=HTTP 2>$null
    Write-Host "  ✓ HTTP listener configured on port 5985" -ForegroundColor Green
} catch {
    Write-Warning "Listener may already exist: $_"
}

# 3. Configure WinRM service settings
Write-Host "`n[3/6] Configuring WinRM service settings..." -ForegroundColor Yellow
try {
    Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true -Force
    Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true -Force
    Set-Item WSMan:\localhost\MaxTimeoutms -Value 1800000 -Force
    Write-Host "  ✓ Basic auth enabled" -ForegroundColor Green
    Write-Host "  ✓ Unencrypted connections allowed (HTTP)" -ForegroundColor Green
    Write-Host "  ✓ Timeout increased" -ForegroundColor Green
} catch {
    Write-Error "Failed to configure WinRM settings: $_"
    exit 1
}

# 4. Configure TrustedHosts
Write-Host "`n[4/6] Configuring TrustedHosts..." -ForegroundColor Yellow
try {
    $currentTrustedHosts = (Get-Item WSMan:\localhost\Client\TrustedHosts).Value
    
    if ($ControllerIP) {
        if ($currentTrustedHosts -eq "" -or $currentTrustedHosts -eq "*") {
            Set-Item WSMan:\localhost\Client\TrustedHosts -Value $ControllerIP -Force
        } else {
            Set-Item WSMan:\localhost\Client\TrustedHosts -Value "$currentTrustedHosts,$ControllerIP" -Force
        }
        Write-Host "  ✓ Added controller IP: $ControllerIP" -ForegroundColor Green
    } else {
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
        Write-Host "  ✓ TrustedHosts set to * (all hosts)" -ForegroundColor Green
        Write-Host "    Warning: This is insecure but required for Ansible" -ForegroundColor Yellow
    }
} catch {
    Write-Error "Failed to configure TrustedHosts: $_"
}

# 5. Configure Windows Firewall
Write-Host "`n[5/6] Configuring Windows Firewall..." -ForegroundColor Yellow
try {
    # Remove any existing conflicting rules
    Get-NetFirewallRule -Name "CCDC-WinRM-*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    
    # Create specific rule for management subnet
    New-NetFirewallRule -Name "CCDC-WinRM-Ansible" `
        -DisplayName "WinRM (HTTP-In) - CCDC Ansible Management" `
        -Enabled True `
        -Direction Inbound `
        -Protocol TCP `
        -LocalPort 5985 `
        -RemoteAddress $ManagementSubnet `
        -Action Allow `
        -Profile Any | Out-Null
    
    Write-Host "  ✓ Firewall rule created for $ManagementSubnet" -ForegroundColor Green
    
    # Also ensure the default WinRM rule is enabled
    $defaultRule = Get-NetFirewallRule -Name "WINRM-HTTP-In-TCP" -ErrorAction SilentlyContinue
    if ($defaultRule) {
        Enable-NetFirewallRule -Name "WINRM-HTTP-In-TCP"
        Write-Host "  ✓ Default WinRM firewall rule enabled" -ForegroundColor Green
    }
} catch {
    Write-Warning "Firewall configuration warning: $_"
    Write-Host "  You may need to manually configure firewall rules" -ForegroundColor Yellow
}

# 6. Verify configuration
Write-Host "`n[6/6] Verifying configuration..." -ForegroundColor Yellow
try {
    $winrmConfig = winrm get winrm/config
    Write-Host "  ✓ WinRM configuration retrieved successfully" -ForegroundColor Green
    
    # Test WinRM locally
    $testResult = Test-WSMan -ComputerName localhost -ErrorAction SilentlyContinue
    if ($testResult) {
        Write-Host "  ✓ WinRM is responding to local requests" -ForegroundColor Green
    }
} catch {
    Write-Warning "Verification warning: $_"
}

# Summary
Write-Host "`n=== Configuration Complete ===" -ForegroundColor Cyan
Write-Host "`nWinRM Configuration Summary:" -ForegroundColor White
Write-Host "  • Service: Running, Automatic startup" -ForegroundColor Gray
Write-Host "  • Port: 5985 (HTTP)" -ForegroundColor Gray
Write-Host "  • Authentication: Basic (unencrypted)" -ForegroundColor Gray
Write-Host "  • Allowed Network: $ManagementSubnet" -ForegroundColor Gray
if ($ControllerIP) {
    Write-Host "  • TrustedHosts: $ControllerIP" -ForegroundColor Gray
} else {
    Write-Host "  • TrustedHosts: * (all)" -ForegroundColor Gray
}

Write-Host "`n⚠️  SECURITY NOTE:" -ForegroundColor Red
Write-Host "  This configuration allows unencrypted WinRM connections." -ForegroundColor Yellow
Write-Host "  This is acceptable in a CCDC isolated network environment." -ForegroundColor Yellow
Write-Host "  Do NOT use this configuration in production!" -ForegroundColor Yellow

Write-Host "`nTest from Ansible controller with:" -ForegroundColor White
Write-Host "  ansible windows -i inventory.ini -m win_ping" -ForegroundColor Cyan

Write-Host "`nDone!`n" -ForegroundColor Green
