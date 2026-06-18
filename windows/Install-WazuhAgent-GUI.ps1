?#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Wazuh Agent + stunnel -- Graphical Installer for Windows.

.DESCRIPTION
    Same logic as Install-WazuhAgent.ps1 but wrapped in a Windows Forms GUI.
    Presents input fields for Agent Name and optional Enrollment Password,
    runs installation steps in the foreground with a live log panel, and
    shows colour-coded status for each step.

.EXAMPLE
    .\Install-WazuhAgent-GUI.ps1
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# =============================================================================
# Configuration -- edit these to match your environment
# =============================================================================
$CFG = @{
    AgentsSNI   = "agents-wazuh.carbigdata.com.br"
    EnrollSNI   = "enroll-wazuh.carbigdata.com.br"
    TunnelPort  = 443
    AgentPort   = 1514
    EnrollPort  = 1515
    WazuhVer    = "4.14.5"
    StunnelDir  = "C:\Program Files (x86)\stunnel"
    WazuhDir    = "C:\Program Files (x86)\ossec-agent"
    StunnelSvc  = "stunnel TLS wrapper"
    WazuhSvc    = "WazuhSvc"
    StunnelURL  = "https://www.stunnel.org/downloads/stunnel-latest-win64-installer.exe"
    WazuhURL    = "https://packages.wazuh.com/4.x/windows/wazuh-agent-{0}-1.msi"
    TmpDir      = "$env:TEMP\wazuh-install"
}
$CFG.StunnelConf = "$($CFG.StunnelDir)\config\stunnel.conf"
$CFG.StunnelCA   = "$($CFG.StunnelDir)\config\wazuh-ca.pem"
$CFG.LogFile     = "$($CFG.TmpDir)\install.log"

# =============================================================================
# Wazuh Root CA (embedded -- signed by Wazuh self-signed CA)
# =============================================================================
$WAZUH_CA_PEM = @"
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

# =============================================================================
# GUI -- logging helpers (write into the RichTextBox)
# =============================================================================
$script:LogBox = $null
$script:Failed = $false

function Append-Log {
    param([string]$Text, [System.Drawing.Color]$Color)
    $script:LogBox.SelectionStart  = $script:LogBox.TextLength
    $script:LogBox.SelectionLength = 0
    $script:LogBox.SelectionColor  = $Color
    $ts = (Get-Date).ToString("HH:mm:ss")
    $script:LogBox.AppendText("[$ts]  $Text`n")
    $script:LogBox.ScrollToCaret()
    [System.Windows.Forms.Application]::DoEvents()
}

function Log-Step { param($m) Append-Log "==> $m"      ([System.Drawing.Color]::Cyan) }
function Log-OK   { param($m) Append-Log "    [OK] $m" ([System.Drawing.Color]::LimeGreen) }
function Log-Warn { param($m) Append-Log "    [!!] $m" ([System.Drawing.Color]::Yellow) }
function Log-Info { param($m) Append-Log "        $m"  ([System.Drawing.Color]::LightGray) }
function Log-Fail {
    param($m)
    Append-Log "    [XX] $m" ([System.Drawing.Color]::Tomato)
    $script:Failed = $true
}

function Log-File { param($m) "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))  $m" | Out-File $CFG.LogFile -Append -Encoding UTF8 }

# =============================================================================
# Installation logic
# =============================================================================
function Start-Install {
    param([string]$AgentName, [string]$Password, [string]$WazuhVersion)

    $script:Failed = $false
    New-Item -ItemType Directory -Path $CFG.TmpDir -Force | Out-Null
    $logFile = $CFG.LogFile
    Log-File "=== Install started. Agent=$AgentName Version=$WazuhVersion ==="

    $stunnelInst = "$($CFG.TmpDir)\stunnel-installer.exe"
    $wazuhMsi    = "$($CFG.TmpDir)\wazuh-agent-$WazuhVersion-1.msi"
    $wazuhUrl    = $CFG.WazuhURL -f $WazuhVersion

    # ------------------------------------------------------------------
    # STEP 1 -- Download installers
    # ------------------------------------------------------------------
    Log-Step "Step 1/7 -- Downloading installers"

    foreach ($dl in @(
        @{ Url = $CFG.StunnelURL; Dest = $stunnelInst; Name = "stunnel" }
        @{ Url = $wazuhUrl;       Dest = $wazuhMsi;    Name = "Wazuh Agent MSI" }
    )) {
        if (Test-Path $dl.Dest) {
            Log-Warn "$($dl.Name) already in temp -- skipping download"
        } else {
            Log-Info "Downloading $($dl.Name)..."
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                (New-Object Net.WebClient).DownloadFile($dl.Url, $dl.Dest)
                Log-OK "$($dl.Name) downloaded"
            } catch {
                Log-Fail "Download failed: $($dl.Url)`n        $_"
                return
            }
        }
    }

    # ------------------------------------------------------------------
    # STEP 2 -- Install stunnel
    # ------------------------------------------------------------------
    Log-Step "Step 2/7 -- Installing stunnel"

    if (Test-Path "$($CFG.StunnelDir)\bin\stunnel.exe") {
        Log-Warn "stunnel already installed -- skipping"
    } else {
        Log-Info "Running stunnel installer (silent)..."
        $p = Start-Process -FilePath $stunnelInst -ArgumentList "/S" -Wait -PassThru
        if ($p.ExitCode -ne 0) { Log-Fail "stunnel installer failed (exit $($p.ExitCode))"; return }
        Log-OK "stunnel installed"
    }

    # ------------------------------------------------------------------
    # STEP 3 -- Write stunnel config + Wazuh CA
    # ------------------------------------------------------------------
    Log-Step "Step 3/7 -- Writing stunnel config + Wazuh CA"

    New-Item -ItemType Directory -Path "$($CFG.StunnelDir)\config" -Force | Out-Null

    Set-Content -Path $CFG.StunnelCA -Value $WAZUH_CA_PEM.Trim() -Encoding ASCII
    Log-OK "Wazuh root CA written"

    $caPathFwd = $CFG.StunnelCA -replace '\\', '/'
    $conf = @"
; stunnel client config -- Wazuh agent tunnel
; DO NOT EDIT -- managed by Install-WazuhAgent-GUI.ps1
client = yes

[wazuh-agents]
accept       = 127.0.0.1:$($CFG.AgentPort)
connect      = $($CFG.AgentsSNI):$($CFG.TunnelPort)
verifyChain  = yes
checkHost    = $($CFG.AgentsSNI)
CAfile       = $caPathFwd

[wazuh-enrollment]
accept       = 127.0.0.1:$($CFG.EnrollPort)
connect      = $($CFG.EnrollSNI):$($CFG.TunnelPort)
verifyChain  = yes
checkHost    = $($CFG.EnrollSNI)
CAfile       = $caPathFwd
"@
    Set-Content -Path $CFG.StunnelConf -Value $conf -Encoding ASCII
    Log-OK "stunnel.conf written"

    # ------------------------------------------------------------------
    # STEP 4 -- Start stunnel service
    # ------------------------------------------------------------------
    Log-Step "Step 4/7 -- Starting stunnel service"

    $svc = Get-Service -Name $CFG.StunnelSvc -ErrorAction SilentlyContinue
    if (-not $svc) {
        Log-Info "Registering stunnel service..."
        & "$($CFG.StunnelDir)\bin\stunnel.exe" -install 2>&1 | Out-Null
        Start-Sleep 2
        $svc = Get-Service -Name $CFG.StunnelSvc -ErrorAction SilentlyContinue
        if (-not $svc) { Log-Fail "Failed to register stunnel service"; return }
    }
    Set-Service  -Name $CFG.StunnelSvc -StartupType Automatic
    Restart-Service -Name $CFG.StunnelSvc -Force
    Start-Sleep 3

    if ((Get-Service -Name $CFG.StunnelSvc).Status -ne "Running") {
        Log-Fail "stunnel service failed to start -- check $($CFG.StunnelDir)\log\stunnel.log"
        return
    }
    Log-OK "stunnel service running"

    # ------------------------------------------------------------------
    # STEP 5 -- Install Wazuh Agent MSI
    # ------------------------------------------------------------------
    Log-Step "Step 5/7 -- Installing Wazuh Agent"

    if (Test-Path "$($CFG.WazuhDir)\ossec-agent.exe") {
        Log-Warn "Wazuh Agent already installed -- skipping MSI"
    } else {
        Log-Info "Running Wazuh MSI (silent, may take ~1 min)..."
        $msiArgs = @(
            "/i", $wazuhMsi,
            "WAZUH_MANAGER=127.0.0.1",
            "WAZUH_MANAGER_PORT=$($CFG.AgentPort)",
            "WAZUH_PROTOCOL=TCP",
            "WAZUH_AGENT_NAME=$AgentName",
            "WAZUH_REGISTRATION_SERVER=127.0.0.1",
            "WAZUH_REGISTRATION_PORT=$($CFG.EnrollPort)",
            "/qn",
            "/l*v", "$($CFG.TmpDir)\wazuh-msi.log"
        )
        $p = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
        if ($p.ExitCode -ne 0) {
            Log-Fail "Wazuh MSI failed (exit $($p.ExitCode)) -- see $($CFG.TmpDir)\wazuh-msi.log"
            return
        }
        Log-OK "Wazuh Agent installed"
    }

    # ------------------------------------------------------------------
    # STEP 6 -- Patch ossec.conf
    # ------------------------------------------------------------------
    Log-Step "Step 6/7 -- Verifying ossec.conf"

    $ossecConf = "$($CFG.WazuhDir)\ossec.conf"
    if (-not (Test-Path $ossecConf)) { Log-Fail "ossec.conf not found at $ossecConf"; return }

    [xml]$xml     = Get-Content $ossecConf -Raw
    $srv          = $xml.SelectSingleNode("//client/server")
    $needsWrite   = $false

    foreach ($patch in @(
        @{ Attr = "address";  Want = "127.0.0.1"           }
        @{ Attr = "port";     Want = "$($CFG.AgentPort)"   }
        @{ Attr = "protocol"; Want = "tcp"                  }
    )) {
        if ($srv.$($patch.Attr) -ne $patch.Want) {
            $srv.$($patch.Attr) = $patch.Want
            $needsWrite = $true
            Log-Warn "Patched <$($patch.Attr)> -> $($patch.Want)"
        }
    }
    if ($needsWrite) { $xml.Save($ossecConf); Log-OK "ossec.conf patched" }
    else { Log-OK "ossec.conf already correct" }

    # ------------------------------------------------------------------
    # STEP 7 -- Enroll + start service
    # ------------------------------------------------------------------
    Log-Step "Step 7/7 -- Enrolling agent"

    $clientKeys      = "$($CFG.WazuhDir)\client.keys"
    $alreadyEnrolled = (Test-Path $clientKeys) -and ((Get-Item $clientKeys).Length -gt 0)

    if ($alreadyEnrolled) {
        Log-Warn "client.keys exists -- skipping enrollment (already registered)"
    } else {
        $authArgs = @("-m", "127.0.0.1", "-p", $CFG.EnrollPort, "-A", $AgentName)
        if ($Password -ne "") { $authArgs += @("-P", $Password) }

        $authOut = & "$($CFG.WazuhDir)\agent-auth.exe" @authArgs 2>&1
        $authOut | ForEach-Object { Log-File "agent-auth: $_" }

        if ($authOut -match "Valid key received") {
            Log-OK "Agent enrolled -- key received"
        } else {
            $authOut | ForEach-Object { Log-Info $_ }
            Log-Fail "Enrollment failed -- check stunnel connectivity to $($CFG.EnrollSNI):$($CFG.TunnelPort)"
            return
        }
    }

    Set-Service     -Name $CFG.WazuhSvc -StartupType Automatic
    Restart-Service -Name $CFG.WazuhSvc -Force
    Start-Sleep 5

    $wStat = (Get-Service -Name $CFG.WazuhSvc).Status
    if ($wStat -eq "Running") { Log-OK "WazuhSvc running" }
    else { Log-Warn "WazuhSvc status: $wStat -- check $($CFG.WazuhDir)\ossec.log" }

    Log-File "=== Install finished ==="
}

# =============================================================================
# Build the form
# =============================================================================
$form = New-Object System.Windows.Forms.Form
$form.Text            = "Wazuh Agent Installer"
$form.Size            = New-Object System.Drawing.Size(620, 600)
$form.MinimumSize     = New-Object System.Drawing.Size(620, 550)
$form.StartPosition   = "CenterScreen"
$form.BackColor       = [System.Drawing.Color]::FromArgb(30, 30, 35)
$form.ForeColor       = [System.Drawing.Color]::White
$form.Font            = New-Object System.Drawing.Font("Segoe UI", 9)
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox     = $false

# -- Header banner -------------------------------------------------------------
$header = New-Object System.Windows.Forms.Panel
$header.Dock      = "Top"
$header.Height    = 64
$header.BackColor = [System.Drawing.Color]::FromArgb(0, 107, 119)   # Wazuh teal

$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text      = "  Wazuh Agent Installer"
$lblTitle.Font      = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
$lblTitle.ForeColor = [System.Drawing.Color]::White
$lblTitle.Dock      = "Fill"
$lblTitle.TextAlign = "MiddleLeft"
$header.Controls.Add($lblTitle)
$form.Controls.Add($header)

# -- Input panel ---------------------------------------------------------------
$panel = New-Object System.Windows.Forms.TableLayoutPanel
$panel.ColumnCount    = 2
$panel.RowCount       = 4
$panel.Dock           = "Top"
$panel.Height         = 140
$panel.Padding        = New-Object System.Windows.Forms.Padding(16, 10, 16, 0)
$panel.BackColor      = [System.Drawing.Color]::FromArgb(40, 40, 48)

$panel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 140))) | Out-Null
$panel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))  | Out-Null

function Add-Row {
    param($Panel, [string]$Label, [System.Windows.Forms.Control]$Ctrl)
    $lbl            = New-Object System.Windows.Forms.Label
    $lbl.Text       = $Label
    $lbl.ForeColor  = [System.Drawing.Color]::LightGray
    $lbl.TextAlign  = "MiddleRight"
    $lbl.Dock       = "Fill"
    $Panel.Controls.Add($lbl)
    $Ctrl.Dock      = "Fill"
    $Ctrl.BackColor = [System.Drawing.Color]::FromArgb(55, 55, 65)
    $Ctrl.ForeColor = [System.Drawing.Color]::White
    $Panel.Controls.Add($Ctrl)
}

$txtAgent = New-Object System.Windows.Forms.TextBox
$txtAgent.Text = $env:COMPUTERNAME
Add-Row $panel "Agent Name:" $txtAgent

$txtVersion = New-Object System.Windows.Forms.TextBox
$txtVersion.Text = $CFG.WazuhVer
Add-Row $panel "Wazuh Version:" $txtVersion

$txtPwd = New-Object System.Windows.Forms.TextBox
$txtPwd.PasswordChar = [char]0x25CF   # bullet
$txtPwd.Text = ""
Add-Row $panel "Password (opt.):" $txtPwd

$form.Controls.Add($panel)

# -- Button row ----------------------------------------------------------------
$btnPanel = New-Object System.Windows.Forms.FlowLayoutPanel
$btnPanel.Dock          = "Top"
$btnPanel.Height        = 48
$btnPanel.Padding       = New-Object System.Windows.Forms.Padding(16, 6, 16, 6)
$btnPanel.BackColor     = [System.Drawing.Color]::FromArgb(40, 40, 48)
$btnPanel.FlowDirection = "LeftToRight"

$btnInstall = New-Object System.Windows.Forms.Button
$btnInstall.Text      = "  Install"
$btnInstall.Width     = 130
$btnInstall.Height    = 34
$btnInstall.BackColor = [System.Drawing.Color]::FromArgb(0, 140, 155)
$btnInstall.ForeColor = [System.Drawing.Color]::White
$btnInstall.FlatStyle = "Flat"
$btnInstall.FlatAppearance.BorderSize = 0
$btnInstall.Font      = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)

$btnClose = New-Object System.Windows.Forms.Button
$btnClose.Text      = "Close"
$btnClose.Width     = 90
$btnClose.Height    = 34
$btnClose.BackColor = [System.Drawing.Color]::FromArgb(80, 80, 90)
$btnClose.ForeColor = [System.Drawing.Color]::White
$btnClose.FlatStyle = "Flat"
$btnClose.FlatAppearance.BorderSize = 0
$btnClose.Font      = New-Object System.Drawing.Font("Segoe UI", 10)

$btnPanel.Controls.Add($btnInstall)
$btnPanel.Controls.Add($btnClose)
$form.Controls.Add($btnPanel)

# -- Progress bar --------------------------------------------------------------
$progress = New-Object System.Windows.Forms.ProgressBar
$progress.Dock       = "Top"
$progress.Height     = 6
$progress.Minimum    = 0
$progress.Maximum    = 7
$progress.Value      = 0
$progress.Style      = "Continuous"
$progress.BackColor  = [System.Drawing.Color]::FromArgb(30, 30, 35)
$progress.ForeColor  = [System.Drawing.Color]::FromArgb(0, 200, 170)
$form.Controls.Add($progress)

# -- Log area (RichTextBox) ----------------------------------------------------
$logBox = New-Object System.Windows.Forms.RichTextBox
$logBox.Dock          = "Fill"
$logBox.BackColor     = [System.Drawing.Color]::FromArgb(18, 18, 22)
$logBox.ForeColor     = [System.Drawing.Color]::LightGray
$logBox.Font          = New-Object System.Drawing.Font("Consolas", 9)
$logBox.ReadOnly      = $true
$logBox.BorderStyle   = "None"
$logBox.ScrollBars    = "Vertical"
$logBox.Padding       = New-Object System.Windows.Forms.Padding(8)
$script:LogBox        = $logBox
$form.Controls.Add($logBox)

# -- Status strip -------------------------------------------------------------
$statusBar = New-Object System.Windows.Forms.StatusStrip
$statusBar.BackColor  = [System.Drawing.Color]::FromArgb(0, 107, 119)
$lblStatus = New-Object System.Windows.Forms.ToolStripStatusLabel
$lblStatus.Text       = "Ready"
$lblStatus.ForeColor  = [System.Drawing.Color]::White
$statusBar.Items.Add($lblStatus) | Out-Null
$form.Controls.Add($statusBar)

# =============================================================================
# Button handlers
# =============================================================================
$btnClose.Add_Click({ $form.Close() })

$btnInstall.Add_Click({
    $agentName = $txtAgent.Text.Trim()
    $password  = $txtPwd.Text
    $version   = $txtVersion.Text.Trim()

    if (-not $agentName) {
        [System.Windows.Forms.MessageBox]::Show(
            "Agent Name cannot be empty.", "Validation",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        ) | Out-Null
        return
    }

    # Lock UI
    $btnInstall.Enabled = $false
    $btnClose.Enabled   = $false
    $txtAgent.Enabled   = $false
    $txtVersion.Enabled = $false
    $txtPwd.Enabled     = $false
    $progress.Value     = 0
    $script:LogBox.Clear()
    $lblStatus.Text     = "Installing..."

    Append-Log "Agent  : $agentName"   ([System.Drawing.Color]::LightGray)
    Append-Log "Version: $version"     ([System.Drawing.Color]::LightGray)
    Append-Log "Tunnel : $($CFG.AgentsSNI):$($CFG.TunnelPort)" ([System.Drawing.Color]::LightGray)
    Append-Log "" ([System.Drawing.Color]::White)

    # Run install -- progress bar advances in each step
    try {
        New-Item -ItemType Directory -Path $CFG.TmpDir -Force | Out-Null

        $stunnelInst = "$($CFG.TmpDir)\stunnel-installer.exe"
        $wazuhMsi    = "$($CFG.TmpDir)\wazuh-agent-$version-1.msi"
        $wazuhUrl    = $CFG.WazuhURL -f $version

        # Step 1 -- Download
        Log-Step "Step 1/7 -- Downloading installers"
        foreach ($dl in @(
            @{ Url = $CFG.StunnelURL; Dest = $stunnelInst; Name = "stunnel installer" }
            @{ Url = $wazuhUrl;       Dest = $wazuhMsi;    Name = "Wazuh Agent MSI"   }
        )) {
            if (Test-Path $dl.Dest) {
                Log-Warn "$($dl.Name) already in temp -- skipping"
            } else {
                Log-Info "Downloading $($dl.Name)..."
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                (New-Object Net.WebClient).DownloadFile($dl.Url, $dl.Dest)
                Log-OK "$($dl.Name) downloaded"
            }
        }
        $progress.Value = 1

        # Step 2 -- Install stunnel
        Log-Step "Step 2/7 -- Installing stunnel"
        if (Test-Path "$($CFG.StunnelDir)\bin\stunnel.exe") {
            Log-Warn "stunnel already installed -- skipping"
        } else {
            Log-Info "Running installer (silent)..."
            $p = Start-Process $stunnelInst -ArgumentList "/S" -Wait -PassThru
            if ($p.ExitCode -ne 0) { throw "stunnel installer failed (exit $($p.ExitCode))" }
            Log-OK "stunnel installed"
        }
        $progress.Value = 2

        # Step 3 -- Write config
        Log-Step "Step 3/7 -- Writing stunnel config + Wazuh CA"
        New-Item -ItemType Directory -Path "$($CFG.StunnelDir)\config" -Force | Out-Null
        Set-Content -Path $CFG.StunnelCA -Value $WAZUH_CA_PEM.Trim() -Encoding ASCII
        Log-OK "Wazuh root CA written to $($CFG.StunnelCA)"
        $caFwd = $CFG.StunnelCA -replace '\\','/'
        $conf = @"
; stunnel client config -- Wazuh agent tunnel
; DO NOT EDIT -- managed by Install-WazuhAgent-GUI.ps1
client = yes

[wazuh-agents]
accept       = 127.0.0.1:$($CFG.AgentPort)
connect      = $($CFG.AgentsSNI):$($CFG.TunnelPort)
verifyChain  = yes
checkHost    = $($CFG.AgentsSNI)
CAfile       = $caFwd

[wazuh-enrollment]
accept       = 127.0.0.1:$($CFG.EnrollPort)
connect      = $($CFG.EnrollSNI):$($CFG.TunnelPort)
verifyChain  = yes
checkHost    = $($CFG.EnrollSNI)
CAfile       = $caFwd
"@
        Set-Content -Path $CFG.StunnelConf -Value $conf -Encoding ASCII
        Log-OK "stunnel.conf written"
        $progress.Value = 3

        # Step 4 -- Start stunnel
        Log-Step "Step 4/7 -- Starting stunnel service"
        $svc = Get-Service -Name $CFG.StunnelSvc -ErrorAction SilentlyContinue
        if (-not $svc) {
            Log-Info "Registering stunnel service..."
            & "$($CFG.StunnelDir)\bin\stunnel.exe" -install 2>&1 | Out-Null
            Start-Sleep 2
            $svc = Get-Service -Name $CFG.StunnelSvc -ErrorAction SilentlyContinue
            if (-not $svc) { throw "Failed to register stunnel service" }
        }
        Set-Service     -Name $CFG.StunnelSvc -StartupType Automatic
        Restart-Service -Name $CFG.StunnelSvc -Force
        Start-Sleep 3
        if ((Get-Service $CFG.StunnelSvc).Status -ne "Running") {
            throw "stunnel did not start -- check $($CFG.StunnelDir)\log\stunnel.log"
        }
        Log-OK "stunnel service running"
        $progress.Value = 4

        # Step 5 -- Install Wazuh MSI
        Log-Step "Step 5/7 -- Installing Wazuh Agent"
        if (Test-Path "$($CFG.WazuhDir)\ossec-agent.exe") {
            Log-Warn "Wazuh Agent already installed -- skipping MSI"
        } else {
            Log-Info "Running Wazuh MSI (silent, ~1 min)..."
            $msiArgs = @(
                "/i", $wazuhMsi,
                "WAZUH_MANAGER=127.0.0.1",
                "WAZUH_MANAGER_PORT=$($CFG.AgentPort)",
                "WAZUH_PROTOCOL=TCP",
                "WAZUH_AGENT_NAME=$agentName",
                "WAZUH_REGISTRATION_SERVER=127.0.0.1",
                "WAZUH_REGISTRATION_PORT=$($CFG.EnrollPort)",
                "/qn", "/l*v", "$($CFG.TmpDir)\wazuh-msi.log"
            )
            $p = Start-Process "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
            if ($p.ExitCode -ne 0) {
                throw "Wazuh MSI failed (exit $($p.ExitCode)) -- see $($CFG.TmpDir)\wazuh-msi.log"
            }
            Log-OK "Wazuh Agent installed"
        }
        $progress.Value = 5

        # Step 6 -- Patch ossec.conf
        Log-Step "Step 6/7 -- Verifying ossec.conf"
        $ossec = "$($CFG.WazuhDir)\ossec.conf"
        if (-not (Test-Path $ossec)) { throw "ossec.conf not found at $ossec" }
        [xml]$xml = Get-Content $ossec -Raw
        $srv = $xml.SelectSingleNode("//client/server")
        $changed = $false
        foreach ($p in @(
            @{A="address";  W="127.0.0.1"}
            @{A="port";     W="$($CFG.AgentPort)"}
            @{A="protocol"; W="tcp"}
        )) {
            if ($srv.$($p.A) -ne $p.W) {
                $srv.$($p.A) = $p.W
                $changed = $true
                Log-Warn "Patched <$($p.A)> -> $($p.W)"
            }
        }
        if ($changed) { $xml.Save($ossec); Log-OK "ossec.conf patched" }
        else           { Log-OK "ossec.conf already correct" }
        $progress.Value = 6

        # Step 7 -- Enroll
        Log-Step "Step 7/7 -- Enrolling agent"
        $keys = "$($CFG.WazuhDir)\client.keys"
        if ((Test-Path $keys) -and (Get-Item $keys).Length -gt 0) {
            Log-Warn "client.keys exists -- skipping enrollment"
        } else {
            $args = @("-m","127.0.0.1","-p",$CFG.EnrollPort,"-A",$agentName)
            if ($password -ne "") { $args += @("-P",$password) }
            $out = & "$($CFG.WazuhDir)\agent-auth.exe" @args 2>&1
            $out | ForEach-Object { Log-Info $_ }
            if (-not ($out -match "Valid key received")) {
                throw "Enrollment failed -- verify stunnel connectivity to $($CFG.EnrollSNI):$($CFG.TunnelPort)"
            }
            Log-OK "Agent enrolled -- key received"
        }

        Set-Service     -Name $CFG.WazuhSvc -StartupType Automatic
        Restart-Service -Name $CFG.WazuhSvc -Force
        Start-Sleep 5
        $ws = (Get-Service $CFG.WazuhSvc).Status
        if ($ws -eq "Running") { Log-OK "WazuhSvc running" }
        else                   { Log-Warn "WazuhSvc status: $ws" }

        $progress.Value  = 7
        $lblStatus.Text  = "Done -- agent '$agentName' registered successfully."
        $lblStatus.ForeColor = [System.Drawing.Color]::LightGreen

        Append-Log "" ([System.Drawing.Color]::White)
        Append-Log "================================================================" ([System.Drawing.Color]::LimeGreen)
        Append-Log "  Installation complete!  Agent: $agentName" ([System.Drawing.Color]::LimeGreen)
        Append-Log "================================================================" ([System.Drawing.Color]::LimeGreen)

    } catch {
        Log-Fail "Fatal: $_"
        $lblStatus.Text = "Installation failed -- see log above."
        $lblStatus.ForeColor = [System.Drawing.Color]::Tomato
    }

    # Unlock UI
    $btnInstall.Enabled = $true
    $btnClose.Enabled   = $true
    $txtAgent.Enabled   = $true
    $txtVersion.Enabled = $true
    $txtPwd.Enabled     = $true
    $btnInstall.Text    = "  Re-Install"
})

# =============================================================================
# Show
# =============================================================================
[System.Windows.Forms.Application]::Run($form)
