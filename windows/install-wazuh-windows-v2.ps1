#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Instala e configura o Agente Wazuh + cliente stunnel no Windows.

.DESCRIPTION
    Automatiza a instalação completa:
      1. Baixa e instala o stunnel (cliente de túnel TLS)
      2. Grava a configuração do cliente stunnel (roteamento SNI na porta 443)
      3. Habilita e inicia o serviço stunnel
      4. Baixa e instala o MSI do Agente Wazuh
      5. Corrige o ossec.conf para usar 127.0.0.1:1514 TCP (via stunnel)
      6. Registra o agente no manager via agent-auth
      7. Habilita e inicia o serviço do agente Wazuh

.PARAMETER AgentName
    Nome para registrar o agente. Padrão: hostname da máquina.

.PARAMETER WazuhVersion
    Versão do agente Wazuh a instalar. Padrão: 4.14.5.

.PARAMETER EnrollmentPassword
    Senha de registro opcional, caso configurada no manager Wazuh.

.PARAMETER SkipDownload
    Ignora o download dos instaladores se eles já existirem na pasta temporária.

.EXAMPLE
    # Executar com padrões (hostname como nome do agente)
    .\Install-WazuhAgent.ps1

.EXAMPLE
    # Nome de agente personalizado
    .\Install-WazuhAgent.ps1 -AgentName "windows-server-prod-01"

.EXAMPLE
    # Com senha de registro
    .\Install-WazuhAgent.ps1 -EnrollmentPassword "MinhaSenha123"
#>

[CmdletBinding()]
param(
    [string]$AgentName         = $env:COMPUTERNAME,
    [string]$WazuhVersion      = "4.14.5",
    [string]$EnrollmentPassword = "",
    [switch]$SkipDownload
)

# ── Configuração — edite estas variáveis conforme seu ambiente ────────────────
$AGENTS_SNI    = "agents-wazuh.carbigdata.com.br"
$ENROLL_SNI    = "enroll-wazuh.carbigdata.com.br"
$TUNNEL_PORT   = 443
$AGENT_PORT    = 1514
$ENROLL_PORT   = 1515

# Caminhos derivados
$STUNNEL_DIR   = "C:\Program Files (x86)\stunnel"
$STUNNEL_CONF  = "$STUNNEL_DIR\config\stunnel.conf"
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

# ── Funções auxiliares ────────────────────────────────────────────────────────
function Write-Step   { param($msg) Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-OK     { param($msg) Write-Host "    [OK] $msg" -ForegroundColor Green }
function Write-Warn   { param($msg) Write-Host "    [!!] $msg" -ForegroundColor Yellow }
function Write-Fail   { param($msg) Write-Host "    [XX] $msg" -ForegroundColor Red; throw $msg }

function Log { param($msg) $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"; "$ts  $msg" | Tee-Object -FilePath $LOG_FILE -Append | Out-Null }

function Download-File {
    param([string]$Url, [string]$Dest)
    if ($SkipDownload -and (Test-Path $Dest)) {
        Write-Warn "Download ignorado — arquivo já existe: $Dest"
        return
    }
    Write-Host "    Baixando $(Split-Path $Dest -Leaf)..." -NoNewline
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        (New-Object Net.WebClient).DownloadFile($Url, $Dest)
        Write-Host " concluído" -ForegroundColor Green
    } catch {
        Write-Host " FALHOU" -ForegroundColor Red
        Write-Fail "Falha no download de $Url : $_"
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

# ── Início ────────────────────────────────────────────────────────────────────
Clear-Host
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   Agente Wazuh + stunnel — Instalador Automático Windows     ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Nome do agente  : $AgentName"
Write-Host "  Versão Wazuh    : $WazuhVersion"
Write-Host "  SNI dos agentes : $AGENTS_SNI"
Write-Host "  SNI de registro : $ENROLL_SNI"
Write-Host "  Arquivo de log  : $LOG_FILE"
Write-Host ""

Log "=== Instalação iniciada. AgentName=$AgentName WazuhVersion=$WazuhVersion ==="

# Criar diretório temporário
New-Item -ItemType Directory -Path $TMP -Force | Out-Null

# =============================================================================
# PASSO 1 — Baixar instaladores
# =============================================================================
Write-Step "Passo 1/7 — Baixando instaladores"

Download-File -Url $STUNNEL_URL  -Dest $STUNNEL_INST
Download-File -Url $WAZUH_URL    -Dest $WAZUH_MSI

Write-OK "Instaladores prontos em $TMP"
Log "Downloads concluídos"

# =============================================================================
# PASSO 2 — Instalar stunnel (silencioso)
# =============================================================================
Write-Step "Passo 2/7 — Instalando stunnel"

if (Test-Path "$STUNNEL_DIR\bin\stunnel.exe") {
    Write-Warn "stunnel já instalado em $STUNNEL_DIR — ignorando instalação"
    Log "stunnel já instalado"
} else {
    Write-Host "    Executando instalador do stunnel (silencioso)..."
    $proc = Start-Process -FilePath $STUNNEL_INST `
        -ArgumentList "/S" `
        -Wait -PassThru
    if ($proc.ExitCode -ne 0) {
        Write-Fail "Instalador do stunnel encerrou com código $($proc.ExitCode)"
    }
    Write-OK "stunnel instalado"
    Log "stunnel instalado exitCode=$($proc.ExitCode)"
}

# =============================================================================
# PASSO 3 — Gravar configuração do cliente stunnel
# =============================================================================
Write-Step "Passo 3/7 — Gravando configuração do cliente stunnel"

$stunnelConf = @"
; Configuração do cliente stunnel — túnel do agente Wazuh
; Encapsula o protocolo binário do Wazuh em TLS com SNI para que possa ser
; roteado pelo ingress externo na porta $TUNNEL_PORT.
;
; NÃO EDITE — gerenciado por Install-WazuhAgent.ps1

client = yes
foreground = no

; Comunicação keepalive do agente (ossec-agentd → wazuh-master:$AGENT_PORT)
[wazuh-agents]
accept  = 127.0.0.1:$AGENT_PORT
connect = ${AGENTS_SNI}:${TUNNEL_PORT}
sni     = $AGENTS_SNI
verify  = 0

; Registro do agente (agent-auth → wazuh-master:$ENROLL_PORT)
[wazuh-enrollment]
accept  = 127.0.0.1:$ENROLL_PORT
connect = ${ENROLL_SNI}:${TUNNEL_PORT}
sni     = $ENROLL_SNI
verify  = 0
"@

# Garantir que o diretório de configuração exista
New-Item -ItemType Directory -Path "$STUNNEL_DIR\config" -Force | Out-Null
Set-Content -Path $STUNNEL_CONF -Value $stunnelConf -Encoding ASCII
Write-OK "Configuração gravada em $STUNNEL_CONF"
Log "stunnel.conf gravado"

# =============================================================================
# PASSO 4 — Habilitar e iniciar o serviço stunnel
# =============================================================================
Write-Step "Passo 4/7 — Iniciando serviço stunnel"

# O instalador do stunnel registra o serviço; basta configurar e iniciá-lo
$svc = Get-Service -Name $STUNNEL_SVC -ErrorAction SilentlyContinue
if (-not $svc) {
    # Registrar manualmente caso o instalador não o tenha feito
    Write-Host "    Registrando serviço stunnel..."
    & "$STUNNEL_DIR\bin\stunnel.exe" -install 2>&1 | Out-Null
    Start-Sleep -Seconds 2
    $svc = Get-Service -Name $STUNNEL_SVC -ErrorAction SilentlyContinue
    if (-not $svc) { Write-Fail "Falha ao registrar o serviço stunnel" }
}

Set-Service -Name $STUNNEL_SVC -StartupType Automatic
Restart-Service -Name $STUNNEL_SVC -Force
Start-Sleep -Seconds 3

if ((Get-Service -Name $STUNNEL_SVC).Status -ne "Running") {
    Write-Fail "Serviço stunnel falhou ao iniciar. Verifique: $STUNNEL_DIR\log\stunnel.log"
}
Write-OK "Serviço stunnel em execução"
Log "Serviço stunnel iniciado"

# Verificar se as portas estão abertas
Write-Host "    Aguardando stunnel escutar nas portas $AGENT_PORT e $ENROLL_PORT..."
if (-not (Wait-Port -Port $AGENT_PORT)) { Write-Fail "stunnel não está escutando na porta $AGENT_PORT após 30s" }
if (-not (Wait-Port -Port $ENROLL_PORT)) { Write-Fail "stunnel não está escutando na porta $ENROLL_PORT após 30s" }
Write-OK "Portas $AGENT_PORT e $ENROLL_PORT confirmadas abertas"
Log "Portas stunnel verificadas"

# =============================================================================
# PASSO 5 — Instalar Agente Wazuh (MSI silencioso)
# =============================================================================
Write-Step "Passo 5/7 — Instalando Agente Wazuh"

if (Test-Path "$WAZUH_DIR\ossec-agent.exe") {
    Write-Warn "Agente Wazuh já instalado — ignorando instalação do MSI"
    Log "Wazuh já instalado"
} else {
    Write-Host "    Executando instalador MSI do Wazuh (silencioso, ~1 min)..."
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
        Write-Fail "Instalador MSI do Wazuh falhou (saída $($proc.ExitCode)). Veja $TMP\wazuh-msi.log"
    }
    Write-OK "Agente Wazuh instalado"
    Log "MSI do Wazuh instalado exitCode=$($proc.ExitCode)"
}

# =============================================================================
# PASSO 6 — Corrigir ossec.conf (garantir TCP para 127.0.0.1:1514)
# =============================================================================
Write-Step "Passo 6/7 — Verificando ossec.conf"

$ossecConf = "$WAZUH_DIR\ossec.conf"
if (-not (Test-Path $ossecConf)) {
    Write-Fail "ossec.conf não encontrado em $ossecConf"
}

[xml]$xml = Get-Content $ossecConf -Raw
$serverNode = $xml.SelectSingleNode("//client/server")

$needsWrite = $false

if ($serverNode.address -ne "127.0.0.1") {
    $serverNode.address = "127.0.0.1"
    $needsWrite = $true
    Write-Warn "Corrigido: endereço do servidor → 127.0.0.1"
}
if ($serverNode.port -ne "$AGENT_PORT") {
    $serverNode.port = "$AGENT_PORT"
    $needsWrite = $true
    Write-Warn "Corrigido: porta do servidor → $AGENT_PORT"
}
if ($serverNode.protocol -ne "tcp") {
    $serverNode.protocol = "tcp"
    $needsWrite = $true
    Write-Warn "Corrigido: protocolo do servidor → tcp"
}

if ($needsWrite) {
    $xml.Save($ossecConf)
    Write-OK "ossec.conf corrigido e salvo"
    Log "ossec.conf corrigido"
} else {
    Write-OK "ossec.conf já está correto — nenhuma alteração necessária"
    Log "ossec.conf OK"
}

# =============================================================================
# PASSO 7 — Registrar agente + iniciar serviço
# =============================================================================
Write-Step "Passo 7/7 — Registrando agente e iniciando serviço"

# Verificar se já está registrado (client.keys existe e não está vazio)
$clientKeys = "$WAZUH_DIR\client.keys"
$alreadyEnrolled = (Test-Path $clientKeys) -and ((Get-Item $clientKeys).Length -gt 0)

if ($alreadyEnrolled) {
    Write-Warn "client.keys já existe — ignorando registro (agente já registrado)"
    Log "Registro ignorado — agente já registrado"
} else {
    Write-Host "    Registrando agente no manager..."

    $authArgs = "-m 127.0.0.1 -p $ENROLL_PORT -A `"$AgentName`""
    if ($EnrollmentPassword -ne "") {
        $authArgs += " -P `"$EnrollmentPassword`""
    }

    $authOut = & "$WAZUH_DIR\agent-auth.exe" -m 127.0.0.1 -p $ENROLL_PORT -A "$AgentName" 2>&1
    $authOut | ForEach-Object { Log "agent-auth: $_" }

    if ($authOut -match "Valid key received") {
        Write-OK "Agente registrado com sucesso"
        Log "Registro concluído com sucesso"
    } else {
        Write-Host ""
        Write-Host "  Saída do agent-auth:" -ForegroundColor Yellow
        $authOut | ForEach-Object { Write-Host "    $_" }
        Write-Fail "Registro falhou — verifique a conectividade do stunnel com $ENROLL_SNI`:$TUNNEL_PORT"
    }
}

# Iniciar serviço Wazuh
Set-Service  -Name $WAZUH_SVC -StartupType Automatic
Restart-Service -Name $WAZUH_SVC -Force
Start-Sleep -Seconds 5

$wazuhStatus = (Get-Service -Name $WAZUH_SVC).Status
if ($wazuhStatus -eq "Running") {
    Write-OK "WazuhSvc em execução"
    Log "WazuhSvc iniciado"
} else {
    Write-Warn "Status do WazuhSvc: $wazuhStatus — verifique $WAZUH_DIR\ossec.log"
    Log "WazuhSvc status=$wazuhStatus"
}

# =============================================================================
# Resumo
# =============================================================================
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║   Instalação concluída                                        ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Nome do agente  : $AgentName"

$keysContent = if (Test-Path $clientKeys) { Get-Content $clientKeys } else { "" }
if ($keysContent -match "^(\d+) ") { Write-Host "  ID do agente    : $($Matches[1])" }

Write-Host ""
Write-Host "  Serviços        :"
Write-Host "    stunnel       : $((Get-Service $STUNNEL_SVC).Status)"
Write-Host "    WazuhSvc      : $((Get-Service $WAZUH_SVC).Status)"
Write-Host ""
Write-Host "  Arquivos de log :"
Write-Host "    Instalação    : $LOG_FILE"
Write-Host "    Wazuh MSI     : $TMP\wazuh-msi.log"
Write-Host "    Wazuh         : $WAZUH_DIR\ossec.log"
Write-Host "    stunnel       : $STUNNEL_DIR\log\stunnel.log"
Write-Host ""
Write-Host "  Verificar no manager:" -ForegroundColor Cyan
Write-Host "    docker exec -it `$(docker ps -q -f name=wazuh-master) \"
Write-Host "      /var/ossec/bin/agent_control -l"
Write-Host ""

Log "=== Instalação finalizada ==="
