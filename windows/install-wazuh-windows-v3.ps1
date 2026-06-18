#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs and configures the Wazuh Agent + stunnel client on Windows.

.DESCRIPTION
    Automates the full installation:
      1. Downloads and installs stunnel (TLS tunnel client)
      2. Writes the stunnel client config (SNI routing to port 443)
      3. Enables and starts the stunnel service
      4. Downloads and installs the Wazuh Agent MSI
      5. Patches ossec.conf to use 127.0.0.1:1514 TCP (via stunnel)
      6. Enrolls the agent with the manager via agent-auth
      7. Enables and starts the Wazuh agent service

.PARAMETER AgentName
    Name to register the agent as. Defaults to the machine hostname.

.PARAMETER WazuhVersion
    Wazuh agent version to install. Defaults to 4.14.5.

.PARAMETER EnrollmentPassword
    Optional. Shared enrollment secret — must match /var/ossec/etc/authd.pass on the manager.
    Only required if <use_password>yes</use_password> is set in the manager's ossec.conf.

.PARAMETER SkipDownload
    Skip downloading installers if they already exist in the temp folder.

.EXAMPLE
    # Run with defaults (hostname as agent name, no enrollment password)
    .\Install-WazuhAgent.ps1

.EXAMPLE
    # Custom agent name
    .\Install-WazuhAgent.ps1 -AgentName "windows-server-prod-01"

.EXAMPLE
    # With enrollment password (when manager requires it)
    .\Install-WazuhAgent.ps1 -AgentName "windows-server-prod-01" -EnrollmentPassword "YourEnrollSecret"
#>

[CmdletBinding()]
param(
    [string]$AgentName         = $env:COMPUTERNAME,
    [string]$WazuhVersion      = "4.14.5",
    [string]$EnrollmentPassword = "",
    [switch]$SkipDownload
)

# ── Configuration — edit these to match your environment ──────────────────────
$AGENTS_SNI    = "agents-wazuh.carbigdata.com.br"
$ENROLL_SNI    = "enroll-wazuh.carbigdata.com.br"
$TUNNEL_PORT   = 443
$AGENT_PORT    = 1514
$ENROLL_PORT   = 1515

# Derived paths
$STUNNEL_DIR   = "C:\Program Files (x86)\stunnel"
$STUNNEL_CONF  = "$STUNNEL_DIR\config\stunnel.conf"
$STUNNEL_CA    = "$STUNNEL_DIR\config\wazuh-ca.pem"
$STUNNEL_SVC   = "stunnel TLS wrapper"
$WAZUH_DIR     = "C:\Program Files (x86)\ossec-agent"
$WAZUH_SVC     = "WazuhSvc"
$TMP           = "$env:TEMP\wazuh-install"
$STUNNEL_INST  = "$TMP\stunnel-installer.exe"
$WAZUH_MSI     = "$TMP\wazuh-agent-$WazuhVersion-1.msi"
$STUNNEL_URL   = "https://www.stunnel.org/downloads/stunnel-latest-win64-installer.exe"
$WAZUH_URL     = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$WazuhVersion-1.msi"
$LOG_FILE      = "$TMP\install.log"
# ─────────────────────────────────────────────────────────────────────────────

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Step   { param($msg) Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-OK     { param($msg) Write-Host "    [OK] $msg" -ForegroundColor Green }
function Write-Warn   { param($msg) Write-Host "    [!!] $msg" -ForegroundColor Yellow }
function Write-Fail   { param($msg) Write-Host "    [XX] $msg" -ForegroundColor Red; throw $msg }

function Log { param($msg) $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"; "$ts  $msg" | Tee-Object -FilePath $LOG_FILE -Append | Out-Null }

function Download-File {
    param([string]$Url, [string]$Dest)
    if ($SkipDownload -and (Test-Path $Dest)) {
        Write-Warn "Skipping download — file already exists: $Dest"
        return
    }
    Write-Host "    Downloading $(Split-Path $Dest -Leaf)..." -NoNewline
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        (New-Object Net.WebClient).DownloadFile($Url, $Dest)
        Write-Host " done" -ForegroundColor Green
    } catch {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Fail "Download failed from $Url : $_"
    }
}

function Wait-Port {
    param([int]$Port, [int]$TimeoutSec = 30)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $conn = Test-NetConnection -ComputerName 127.0.0.1 -Port $Port -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        if ($conn.TcpTestSucceeded) { return $true }
        Start-Sleep -Seconds 1
    }
    return $false
}

# ── Start ─────────────────────────────────────────────────────────────────────
Clear-Host
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   Wazuh Agent + stunnel -- Automated Windows Installer" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Agent name   : $AgentName"
Write-Host "  Wazuh version: $WazuhVersion"
Write-Host "  Agents SNI   : $AGENTS_SNI"
Write-Host "  Enroll SNI   : $ENROLL_SNI"
Write-Host "  Password     : $(if ($EnrollmentPassword -ne '') { '(set)' } else { '(not set)' })"
Write-Host "  Log file     : $LOG_FILE"
Write-Host ""

Log "=== Install started. AgentName=$AgentName WazuhVersion=$WazuhVersion ==="

# Create temp directory
New-Item -ItemType Directory -Path $TMP -Force | Out-Null

# =============================================================================
# STEP 1 — Download installers
# =============================================================================
Write-Step "Step 1/7 — Downloading installers"

Download-File -Url $STUNNEL_URL  -Dest $STUNNEL_INST
Download-File -Url $WAZUH_URL    -Dest $WAZUH_MSI

Write-OK "Installers ready in $TMP"
Log "Downloads complete"

# =============================================================================
# STEP 2 — Install stunnel (silent)
# =============================================================================
Write-Step "Step 2/7 — Installing stunnel"

if (Test-Path "$STUNNEL_DIR\bin\stunnel.exe") {
    Write-Warn "stunnel already installed at $STUNNEL_DIR — skipping install"
    Log "stunnel already installed"
} else {
    Write-Host "    Running stunnel installer (silent)..."
    $proc = Start-Process -FilePath $STUNNEL_INST `
        -ArgumentList "/S" `
        -Wait -PassThru
    if ($proc.ExitCode -ne 0) {
        Write-Fail "stunnel installer exited with code $($proc.ExitCode)"
    }
    Write-OK "stunnel installed"
    Log "stunnel installed exitCode=$($proc.ExitCode)"
}

# =============================================================================
# STEP 3 — Write stunnel client config + Wazuh root CA cert
# =============================================================================
Write-Step "Step 3/7 — Writing stunnel client config"

# Ensure config directory exists
New-Item -ItemType Directory -Path "$STUNNEL_DIR\config" -Force | Out-Null

# ── Wazuh Root CA — embedded so agents validate the server cert without
#    needing to distribute any extra files.
#    Signed by: CN=Root CA, O=Wazuh  (self-signed — NOT a public CA)
$wazuhCA = @"
-----BEGIN CERTIFICATE-----
MIIDiTCCAnGgAwIBAgIUU+ijcyMy+llh/IIXDk2zAmMTiBEwDQYJKoZIhvcNAQEL
BQAwVDELMAkGA1UEBhMCVVMxEzARBgNVBAcMCkNhbGlmb3JuaWExDjAMBgNVBAoM
BVdhenVoMQ4wDAYDVQQLDAVXYXp1aDEQMA4GA1UEAwwHUm9vdCBDQTAeFw0yNjA2
MTcxOTU1MzBaFw0zNjA2MTQxOTU1MzBaMFQxCzAJBgNVBAYTAlVTMRMwEQYDVQQH
DApDYWxpZm9ybmlhMQ4wDAYDVQQKDAVXYXp1aDEOMAwGA1UECwwFV2F6dWgxEDAO
BgNVBAMMB1Jvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC5
QIKsALAPWbl91azcV8v4DfHN4uyXWCKSad+ydKKnUm/tI78885px1BhKHeuqKg0s
K/GIkwf84lgGbH5SaJgkT/LRaP35sVNAKSL4hf2Q4d5i/kt2tMmHcwPjYKQM6eKB
AdCZLJUZRxukefjxY53i6B0WfdhtobGSjufxSTKmYZzA45K22gj2XTFwsb0fe4gg
ItJeueCGvlUMM07YkX25N0jU2v7DMDnDFw77hXulmktl7haXklP+Uk8ylIdZlUTC
aPqHi0ETL8irVR23cgfCH8imtYgQZwo63DOqCJBNg4fdIhaw4JzeD9yAnbU3WeKo
wztSic1fNomTGl2BjTlpAgMBAAGjUzBRMB0GA1UdDgQWBBSiLu3D5I9dNqdu3z9u
wBg4jGFtXjAfBgNVHSMEGDAWgBSiLu3D5I9dNqdu3z9uwBg4jGFtXjAPBgNVHRMB
Af8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAm30tRLxFgRHyUBQawGwUBf6gx
y19BXYM8MZLeHPDpv3p8/jaxGrqa71Gr8jRZC9tFjRWBxHZmu+6bkDTnwAumJyXF
YW47G4xu9S1/xoiNHe9HH70UuAirDbnPpyyd2xumhvf8/IIzo14oS57eIswSfA+9
sMH2c87qXA2vpx7oWkhMLDnTDkA8hrDqvnaKQ/m9gojnFB0l86BcI5FtbVrWpYWh
wMNVI55Ub1c9mlqlSCINDfnPqsXL0wWBVKcWtAnCJ+0hBvChIb+NOeaPLw8G9wig
s42W3g+5JrsPoS87PGvwrHZKeC/Ef/2GtzS9BCzvDuGKCu5gyYgqrAVqatGz
-----END CERTIFICATE-----
"@

Set-Content -Path $STUNNEL_CA -Value $wazuhCA.Trim() -Encoding ASCII
Write-OK "Wazuh root CA written to $STUNNEL_CA"
Log "wazuh-ca.pem written"

# ── stunnel client config
# verifyChain = yes  → validates the full cert chain against CAfile (prevents MITM)
# checkHost          → enforces hostname matches the cert SAN
# CAfile             → Wazuh Root CA (server cert is signed by this CA, not a public one)
# No 'sni =' — causes issues with stunnel 5.69+ in client sections
$stunnelConf = @"
; stunnel client config — Wazuh agent tunnel
; Wraps Wazuh binary protocol in TLS with SNI so it can be routed
; through the external-ingress on port $TUNNEL_PORT.
;
; DO NOT EDIT — managed by Install-WazuhAgent.ps1

client = yes

; Agent keepalive communication (ossec-agentd → wazuh-master:$AGENT_PORT)
[wazuh-agents]
accept       = 127.0.0.1:$AGENT_PORT
connect      = ${AGENTS_SNI}:${TUNNEL_PORT}
verifyChain  = yes
checkHost    = $AGENTS_SNI
CAfile       = $($STUNNEL_CA -replace '\\','/')

; Agent enrollment (agent-auth → wazuh-master:$ENROLL_PORT)
[wazuh-enrollment]
accept       = 127.0.0.1:$ENROLL_PORT
connect      = ${ENROLL_SNI}:${TUNNEL_PORT}
verifyChain  = yes
checkHost    = $ENROLL_SNI
CAfile       = $($STUNNEL_CA -replace '\\','/')
"@

Set-Content -Path $STUNNEL_CONF -Value $stunnelConf -Encoding ASCII
Write-OK "Config written to $STUNNEL_CONF"
Log "stunnel.conf written"

# =============================================================================
# STEP 4 — Enable and start stunnel service
# =============================================================================
Write-Step "Step 4/7 — Starting stunnel service"

# stunnel installer registers the service; just configure and start it
$svc = Get-Service -Name $STUNNEL_SVC -ErrorAction SilentlyContinue
if (-not $svc) {
    # Register it manually if the installer didn't
    Write-Host "    Registering stunnel service..."
    & "$STUNNEL_DIR\bin\stunnel.exe" -install 2>&1 | Out-Null
    Start-Sleep -Seconds 2
    $svc = Get-Service -Name $STUNNEL_SVC -ErrorAction SilentlyContinue
    if (-not $svc) { Write-Fail "Failed to register stunnel service" }
}

Set-Service -Name $STUNNEL_SVC -StartupType Automatic
Restart-Service -Name $STUNNEL_SVC -Force
Start-Sleep -Seconds 3

if ((Get-Service -Name $STUNNEL_SVC).Status -ne "Running") {
    Write-Fail "stunnel service failed to start. Check: $STUNNEL_DIR\log\stunnel.log"
}
Write-OK "stunnel service running"
Log "stunnel service started"

# Verify ports are open
Write-Host "    Waiting for stunnel to listen on ports $AGENT_PORT and $ENROLL_PORT..."
if (-not (Wait-Port -Port $AGENT_PORT)) { Write-Fail "stunnel not listening on $AGENT_PORT after 30s" }
if (-not (Wait-Port -Port $ENROLL_PORT)) { Write-Fail "stunnel not listening on $ENROLL_PORT after 30s" }
Write-OK "Ports $AGENT_PORT and $ENROLL_PORT confirmed open"
Log "stunnel ports verified"

# =============================================================================
# STEP 5 — Install Wazuh Agent (silent MSI)
# =============================================================================
Write-Step "Step 5/7 — Installing Wazuh Agent"

if (Test-Path "$WAZUH_DIR\ossec-agent.exe") {
    Write-Warn "Wazuh Agent already installed — skipping MSI install"
    Log "Wazuh already installed"
} else {
    Write-Host "    Running Wazuh MSI installer (silent, ~1 min)..."
    $msiArgs = @(
        "/i", $WAZUH_MSI,
        "WAZUH_MANAGER=127.0.0.1",
        "WAZUH_MANAGER_PORT=$AGENT_PORT",
        "WAZUH_PROTOCOL=TCP",
        "WAZUH_AGENT_NAME=$AgentName",
        "WAZUH_REGISTRATION_SERVER=127.0.0.1",
        "WAZUH_REGISTRATION_PORT=$ENROLL_PORT",
        "/qn",
        "/l*v", "$TMP\wazuh-msi.log"
    )
    $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
    if ($proc.ExitCode -ne 0) {
        Write-Fail "Wazuh MSI installer failed (exit $($proc.ExitCode)). See $TMP\wazuh-msi.log"
    }
    Write-OK "Wazuh Agent installed"
    Log "Wazuh MSI installed exitCode=$($proc.ExitCode)"
}

# =============================================================================
# STEP 6 — Patch ossec.conf (ensure TCP to 127.0.0.1:1514)
# =============================================================================
Write-Step "Step 6/7 — Verifying ossec.conf"

$ossecConf = "$WAZUH_DIR\ossec.conf"
if (-not (Test-Path $ossecConf)) {
    Write-Fail "ossec.conf not found at $ossecConf"
}

[xml]$xml = Get-Content $ossecConf -Raw
$serverNode = $xml.SelectSingleNode("//client/server")

$needsWrite = $false

if ($serverNode.address -ne "127.0.0.1") {
    $serverNode.address = "127.0.0.1"
    $needsWrite = $true
    Write-Warn "Patched: server address → 127.0.0.1"
}
if ($serverNode.port -ne "$AGENT_PORT") {
    $serverNode.port = "$AGENT_PORT"
    $needsWrite = $true
    Write-Warn "Patched: server port → $AGENT_PORT"
}
if ($serverNode.protocol -ne "tcp") {
    $serverNode.protocol = "tcp"
    $needsWrite = $true
    Write-Warn "Patched: server protocol → tcp"
}

if ($needsWrite) {
    $xml.Save($ossecConf)
    Write-OK "ossec.conf patched and saved"
    Log "ossec.conf patched"
} else {
    Write-OK "ossec.conf already correct — no changes needed"
    Log "ossec.conf OK"
}

# =============================================================================
# STEP 7 — Enroll agent + start service
# =============================================================================
Write-Step "Step 7/7 — Enrolling agent and starting service"

# Check if already enrolled (client.keys exists and non-empty)
$clientKeys = "$WAZUH_DIR\client.keys"
$alreadyEnrolled = (Test-Path $clientKeys) -and ((Get-Item $clientKeys).Length -gt 0)

if ($alreadyEnrolled) {
    Write-Warn "client.keys already exists — skipping enrollment (agent already registered)"
    Log "Enrollment skipped — already enrolled"
} else {
    Write-Host "    Enrolling agent with manager..."

    # Build agent-auth args — only include -P if an enrollment password was provided
    $authArgs = @("-m", "127.0.0.1", "-p", $ENROLL_PORT, "-A", $AgentName)
    if ($EnrollmentPassword -ne "") {
        $authArgs += @("-P", $EnrollmentPassword)
        Write-Host "    (using enrollment password)"
    }

    $authOut = & "$WAZUH_DIR\agent-auth.exe" @authArgs 2>&1
    $authOut | ForEach-Object { Log "agent-auth: $_" }

    if ($authOut -match "Valid key received") {
        Write-OK "Agent enrolled successfully"
        Log "Enrollment successful"
    } else {
        Write-Host ""
        Write-Host "  agent-auth output:" -ForegroundColor Yellow
        $authOut | ForEach-Object { Write-Host "    $_" }
        Write-Fail "Enrollment failed — check stunnel connectivity to $ENROLL_SNI`:$TUNNEL_PORT"
    }
}

# Start Wazuh service
Set-Service  -Name $WAZUH_SVC -StartupType Automatic
Restart-Service -Name $WAZUH_SVC -Force
Start-Sleep -Seconds 5

$wazuhStatus = (Get-Service -Name $WAZUH_SVC).Status
if ($wazuhStatus -eq "Running") {
    Write-OK "WazuhSvc running"
    Log "WazuhSvc started"
} else {
    Write-Warn "WazuhSvc status: $wazuhStatus — check $WAZUH_DIR\ossec.log"
    Log "WazuhSvc status=$wazuhStatus"
}

# =============================================================================
# Summary
# =============================================================================
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "   Installation complete" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Agent name  : $AgentName"

$keysContent = if (Test-Path $clientKeys) { Get-Content $clientKeys } else { "" }
if ($keysContent -match "^(\d+) ") { Write-Host "  Agent ID    : $($Matches[1])" }

Write-Host ""
Write-Host "  Services    :"
Write-Host "    stunnel   : $((Get-Service $STUNNEL_SVC).Status)"
Write-Host "    WazuhSvc  : $((Get-Service $WAZUH_SVC).Status)"
Write-Host ""
Write-Host "  Log files   :"
Write-Host "    Install   : $LOG_FILE"
Write-Host "    Wazuh MSI : $TMP\wazuh-msi.log"
Write-Host "    Wazuh     : $WAZUH_DIR\ossec.log"
Write-Host "    stunnel   : $STUNNEL_DIR\log\stunnel.log"
Write-Host ""
Write-Host "  Verify on the manager:" -ForegroundColor Cyan
Write-Host "    docker exec -it `$(docker ps -q -f name=wazuh-master) \"
Write-Host "      /var/ossec/bin/agent_control -l"
Write-Host ""

Log "=== Install finished ==="
