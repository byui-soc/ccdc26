#=============================================================================
# UDP BEACON DETECTOR - Windows Version
#
# Purpose: Detect beaconing malware that uses UDP packets
# Method:  Monitor UDP connections and identify periodic/suspicious patterns
#
# Generated with AI assistance (Claude) for CCDC malware detection
#
# Usage:
#   .\Detect-UDPBeacon.ps1
#   .\Detect-UDPBeacon.ps1 -SampleDuration 120 -Quiet
#=============================================================================

param(
    [int]$SampleDuration = 60,
    [int]$BeaconThreshold = 5,
    [switch]$Quiet
)

$ErrorActionPreference = "SilentlyContinue"
$hostname = $env:COMPUTERNAME

function Write-Alert {
    param([string]$Message)
    if (-not $Quiet) {
        Write-Host "[ALERT] $Message" -ForegroundColor Red
    }
    # Log to Windows Event Log
    Write-EventLog -LogName Application -Source "UDP-Beacon-Detector" -EventId 1001 -EntryType Warning -Message $Message -ErrorAction SilentlyContinue
}

function Write-Info {
    param([string]$Message)
    if (-not $Quiet) {
        Write-Host "[INFO] $Message" -ForegroundColor Green
    }
}

function Write-Warn {
    param([string]$Message)
    if (-not $Quiet) {
        Write-Host "[WARN] $Message" -ForegroundColor Yellow
    }
}

# Register event source if not exists
try {
    New-EventLog -LogName Application -Source "UDP-Beacon-Detector" -ErrorAction SilentlyContinue
} catch {}

Write-Info "=== UDP Beacon Detection Started on $hostname ==="
Write-Info "Analyzing UDP connections..."

$foundBeacons = 0
$udpConnections = @{}
$suspiciousProcesses = @()

# Method 1: Get current UDP endpoints
Write-Info "Checking current UDP connections..."

$udpEndpoints = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Where-Object {
    $_.RemoteAddress -ne "0.0.0.0" -and 
    $_.RemoteAddress -ne "::" -and 
    $_.RemoteAddress -ne "127.0.0.1" -and
    $_.RemoteAddress -ne "::1" -and
    $_.RemoteAddress -ne "*"
}

foreach ($endpoint in $udpEndpoints) {
    $destKey = "$($endpoint.RemoteAddress):$($endpoint.RemotePort)"
    
    if ($udpConnections.ContainsKey($destKey)) {
        $udpConnections[$destKey].Count++
    } else {
        # Get process info
        $process = Get-Process -Id $endpoint.OwningProcess -ErrorAction SilentlyContinue
        
        $udpConnections[$destKey] = @{
            RemoteAddress = $endpoint.RemoteAddress
            RemotePort = $endpoint.RemotePort
            LocalPort = $endpoint.LocalPort
            PID = $endpoint.OwningProcess
            ProcessName = if ($process) { $process.ProcessName } else { "unknown" }
            ProcessPath = if ($process) { $process.Path } else { "unknown" }
            Count = 1
        }
    }
}

# Method 2: Check netstat for UDP connections
Write-Info "Checking netstat for UDP traffic..."

$netstatOutput = netstat -ano -p UDP 2>$null | Select-String "UDP"

foreach ($line in $netstatOutput) {
    if ($line -match "UDP\s+(\S+):(\d+)\s+(\S+):(\d+)\s+(\d+)") {
        $localAddr = $Matches[1]
        $localPort = $Matches[2]
        $remoteAddr = $Matches[3]
        $remotePort = $Matches[4]
        $pid = $Matches[5]
        
        # Skip listening or local
        if ($remoteAddr -eq "*" -or $remoteAddr -eq "0.0.0.0" -or $remoteAddr -eq "127.0.0.1") {
            continue
        }
        
        $destKey = "${remoteAddr}:${remotePort}"
        
        if (-not $udpConnections.ContainsKey($destKey)) {
            $process = Get-Process -Id $pid -ErrorAction SilentlyContinue
            
            $udpConnections[$destKey] = @{
                RemoteAddress = $remoteAddr
                RemotePort = $remotePort
                LocalPort = $localPort
                PID = $pid
                ProcessName = if ($process) { $process.ProcessName } else { "unknown" }
                ProcessPath = if ($process) { $process.Path } else { "unknown" }
                Count = 1
            }
        }
    }
}

# Method 3: Check for suspicious UDP processes
Write-Info "Checking for suspicious processes with UDP activity..."

$suspiciousNames = @("python", "python3", "pythonw", "perl", "ruby", "nc", "ncat", "socat", "powershell")

$processes = Get-Process | Where-Object {
    $suspiciousNames -contains $_.ProcessName.ToLower()
}

foreach ($proc in $processes) {
    # Check if this process has UDP connections
    $procUdp = Get-NetUDPEndpoint -OwningProcess $proc.Id -ErrorAction SilentlyContinue
    
    if ($procUdp) {
        $suspiciousProcesses += @{
            PID = $proc.Id
            Name = $proc.ProcessName
            Path = $proc.Path
            CommandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue).CommandLine
            UDPConnections = $procUdp.Count
        }
        
        Write-Warn "Suspicious UDP process: PID=$($proc.Id) Name=$($proc.ProcessName) Path=$($proc.Path)"
    }
}

# Method 4: Sample network traffic (if packet capture available)
Write-Info "Checking for repeated UDP destinations (beacon pattern)..."

# Use performance counters or netstat sampling
$samples = @{}
for ($i = 0; $i -lt 5; $i++) {
    $currentUdp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue
    foreach ($conn in $currentUdp) {
        if ($conn.RemoteAddress -ne "0.0.0.0" -and $conn.RemoteAddress -ne "*") {
            $key = "$($conn.RemoteAddress):$($conn.RemotePort)"
            if ($samples.ContainsKey($key)) {
                $samples[$key]++
            } else {
                $samples[$key] = 1
            }
        }
    }
    Start-Sleep -Seconds 2
}

# Report findings
Write-Host ""
Write-Info "=== UDP Connection Summary ==="

foreach ($dest in $udpConnections.Keys) {
    $conn = $udpConnections[$dest]
    $sampleCount = if ($samples.ContainsKey($dest)) { $samples[$dest] } else { 0 }
    $totalCount = $conn.Count + $sampleCount
    
    # Skip common legitimate UDP
    $port = $conn.RemotePort
    if ($port -eq 53 -or $port -eq 123 -or $port -eq 67 -or $port -eq 68 -or $port -eq 137 -or $port -eq 138) {
        continue
    }
    
    if ($totalCount -ge $BeaconThreshold) {
        $foundBeacons++
        Write-Alert "UDP BEACON DETECTED: dest=$dest count=$totalCount pid=$($conn.PID) process=$($conn.ProcessName) path=$($conn.ProcessPath)"
    } else {
        Write-Info "UDP connection: dest=$dest count=$totalCount process=$($conn.ProcessName)"
    }
}

# Report suspicious processes
if ($suspiciousProcesses.Count -gt 0) {
    Write-Host ""
    Write-Info "=== Suspicious UDP Processes ==="
    foreach ($proc in $suspiciousProcesses) {
        Write-Warn "PID=$($proc.PID) Name=$($proc.Name) UDPConns=$($proc.UDPConnections) Cmd=$($proc.CommandLine)"
    }
}

# Final summary
Write-Host ""
if ($foundBeacons -gt 0) {
    Write-Alert "Found $foundBeacons potential UDP beacon(s)"
    exit 1
} else {
    Write-Info "No UDP beaconing detected"
    exit 0
}
