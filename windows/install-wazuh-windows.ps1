#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$SenhaDeEnrollment = "",
    [int]$TentativasDeRetry = 3,
    [int]$SegundosEntreRetry = 5,
    [string]$DiretorioDeLog = "C:\ProgramData\WazuhBootstrap\Logs"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# =========================
# Pergunta inicial — única interação do usuário
# =========================
$NomeDoRecurso = Read-Host "Informe o nome do recurso para identificar esta máquina no Wazuh"
if ([string]::IsNullOrWhiteSpace($NomeDoRecurso)) {
    throw "O nome do recurso não pode estar vazio."
}

# =========================
# Constantes
# =========================
$StunnelPaginaDownload   = "https://www.stunnel.org/downloads.html"
$WazuhMsiUrl             = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.5-1.msi"

$StunnelCaminhoBase      = "C:\Program Files (x86)\stunnel"
$StunnelExePath          = Join-Path $StunnelCaminhoBase "bin\stunnel.exe"
$StunnelConfDir          = Join-Path $StunnelCaminhoBase "config"
$StunnelConfPath         = Join-Path $StunnelConfDir "stunnel.conf"
$StunnelLogPath          = Join-Path $StunnelCaminhoBase "log\stunnel.log"

$WazuhCaminhoBase        = "C:\Program Files (x86)\ossec-agent"
$WazuhConfPath           = Join-Path $WazuhCaminhoBase "ossec.conf"
$WazuhLogPath            = Join-Path $WazuhCaminhoBase "ossec.log"
$AgentAuthExe            = Join-Path $WazuhCaminhoBase "agent-auth.exe"

$DiretorioDeTrabalho     = Join-Path $env:TEMP "wazuh-windows-install"
$StunnelInstalador       = Join-Path $DiretorioDeTrabalho "stunnel-installer.exe"
$WazuhInstalador         = Join-Path $DiretorioDeTrabalho "wazuh-agent-4.14.5-1.msi"

$NomeServicoStunnel      = "stunnel TLS wrapper"
$NomeServicoWazuh        = "WazuhSvc"

$HostLoopback            = "127.0.0.1"
$PortaAgente             = 1514
$PortaEnrollment         = 1515

$HostTunelAgente         = "agents-wazuh.carbigdata.com.br"
$HostTunelEnrollment     = "enroll-wazuh.carbigdata.com.br"

$DataHora                = Get-Date -Format "yyyyMMdd-HHmmss"
$CaminhoTranscricao      = Join-Path $DiretorioDeLog "wazuh-bootstrap-$DataHora.log"

# =========================
# Funcoes auxiliares
# =========================
function Write-Etapa {
    param([string]$Mensagem)
    Write-Host ""
    Write-Host "==== $Mensagem ====" -ForegroundColor Cyan
}

function Write-Info {
    param([string]$Mensagem)
    Write-Host "[INFO] $Mensagem" -ForegroundColor Gray
}

function Write-Ok {
    param([string]$Mensagem)
    Write-Host "[OK] $Mensagem" -ForegroundColor Green
}

function Write-Aviso {
    param([string]$Mensagem)
    Write-Host "[AVISO] $Mensagem" -ForegroundColor Yellow
}

function Verificar-Administrador {
    $identidade = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal  = New-Object Security.Principal.WindowsPrincipal($identidade)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Este script deve ser executado como Administrador."
    }
}

function Garantir-Diretorio {
    param([Parameter(Mandatory)][string]$Caminho)
    if (-not (Test-Path -LiteralPath $Caminho)) {
        New-Item -Path $Caminho -ItemType Directory -Force | Out-Null
    }
}

function Invocar-ComRetry {
    param(
        [Parameter(Mandatory)][string]$Nome,
        [Parameter(Mandatory)][scriptblock]$Bloco,
        [int]$Tentativas = $TentativasDeRetry,
        [int]$SegundosEspera = $SegundosEntreRetry
    )

    for ($i = 1; $i -le $Tentativas; $i++) {
        try {
            Write-Info "$Nome (tentativa $i/$Tentativas)"
            return & $Bloco
        }
        catch {
            if ($i -ge $Tentativas) {
                throw "$Nome falhou apos $Tentativas tentativa(s). Erro: $($_.Exception.Message)"
            }
            Write-Aviso "$Nome falhou: $($_.Exception.Message). Aguardando $SegundosEspera segundo(s) antes de tentar novamente..."
            Start-Sleep -Seconds $SegundosEspera
        }
    }
}

function Baixar-Arquivo {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Destino
    )

    Invocar-ComRetry -Nome "Baixar $Url" -Bloco {
        Invoke-WebRequest -Uri $Url -OutFile $Destino -UseBasicParsing
        if (-not (Test-Path -LiteralPath $Destino)) {
            throw "Arquivo baixado nao encontrado em: $Destino"
        }
    } | Out-Null
}

function Obter-UrlInstaladorStunnel {
    # Acessa a pagina de downloads do stunnel e extrai a URL do instalador Win64 mais recente
    $resposta = Invocar-ComRetry -Nome "Acessar pagina de downloads do stunnel" -Bloco {
        Invoke-WebRequest -Uri $StunnelPaginaDownload -UseBasicParsing
    }

    $candidatos = @()

    if ($resposta.Links) {
        $candidatos += $resposta.Links |
            Where-Object { $_.href -match 'stunnel-.*-win64-installer\.exe$' } |
            Select-Object -ExpandProperty href -Unique
    }

    if (-not $candidatos) {
        $encontrados = [regex]::Matches(
            $resposta.Content,
            'https?://[^"'' ]*stunnel-[^"'' ]*-win64-installer\.exe|/downloads/stunnel-[^"'' ]*-win64-installer\.exe'
        )
        if ($encontrados.Count -gt 0) {
            $candidatos += $encontrados.Value | Select-Object -Unique
        }
    }

    if (-not $candidatos) {
        throw "Nao foi possivel determinar a URL do instalador stunnel win64 a partir de $StunnelPaginaDownload"
    }

    $linksAbsolutos = foreach ($link in $candidatos) {
        if ($link -match '^https?://') {
            $link
        }
        else {
            [System.Uri]::new([System.Uri]$StunnelPaginaDownload, $link).AbsoluteUri
        }
    }

    $selecionado = $linksAbsolutos |
        Sort-Object {
            if ($_ -match 'stunnel-([0-9]+(?:\.[0-9]+)+)-win64-installer\.exe') {
                [version]$Matches[1]
            }
            else {
                [version]"0.0"
            }
        } -Descending |
        Select-Object -First 1

    if (-not $selecionado) {
        throw "Nenhuma URL de instalador stunnel valida pode ser selecionada."
    }

    return $selecionado
}

function Instalar-Stunnel {
    param([Parameter(Mandatory)][string]$CaminhoInstalador)

    # Instalacao silenciosa sem geracao de certificado local (modo cliente apenas)
    $argumentosSilenciosos = "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-"

    $proc = Start-Process -FilePath $CaminhoInstalador -ArgumentList $argumentosSilenciosos -Wait -PassThru
    if ($proc.ExitCode -ne 0) {
        throw "Instalador do stunnel encerrou com codigo $($proc.ExitCode)"
    }

    if (-not (Test-Path -LiteralPath $StunnelExePath)) {
        throw "Executavel do stunnel nao encontrado no caminho esperado: $StunnelExePath"
    }
}

function Configurar-Stunnel {
    # Escreve a configuracao do stunnel como cliente TLS com SNI para os dois tuneis do Wazuh
    $conteudo = @"
; Configuracao do stunnel como cliente - tunel do agente Wazuh
; Todo o trafego Wazuh e encapsulado em TLS e roteado por SNI na porta 443.
client = yes
foreground = quiet

; Comunicacao do agente (ossec-agentd -> wazuh-master:1514)
[wazuh-agents]
accept  = 127.0.0.1:1514
connect = ${HostTunelAgente}:443
sni     = $HostTunelAgente
verify  = 0

; Enrollment do agente (agent-auth -> wazuh-master:1515)
[wazuh-enrollment]
accept  = 127.0.0.1:1515
connect = ${HostTunelEnrollment}:443
sni     = $HostTunelEnrollment
verify  = 0
"@

    Garantir-Diretorio -Caminho $StunnelConfDir
    Set-Content -Path $StunnelConfPath -Value $conteudo -Encoding ASCII -Force

    if (-not (Test-Path -LiteralPath $StunnelConfPath)) {
        throw "O arquivo stunnel.conf nao foi criado."
    }
}

function Garantir-ServicoRodando {
    param(
        [Parameter(Mandatory)][string]$Nome,
        [ValidateSet("Automatic","Manual","Disabled")][string]$TipoInicializacao = "Automatic"
    )

    $servico = Get-Service -Name $Nome -ErrorAction SilentlyContinue
    if (-not $servico) {
        throw "Servico '$Nome' nao encontrado."
    }

    Set-Service -Name $Nome -StartupType $TipoInicializacao

    if ($servico.Status -ne "Running") {
        Start-Service -Name $Nome
        Start-Sleep -Seconds 3
    }

    $servico = Get-Service -Name $Nome
    if ($servico.Status -ne "Running") {
        throw "Servico '$Nome' nao esta em execucao apos a inicializacao."
    }
}

function Testar-PortaLocal {
    param([Parameter(Mandatory)][int]$Porta)

    $conexoes = Get-NetTCPConnection -State Listen -LocalAddress $HostLoopback -LocalPort $Porta -ErrorAction SilentlyContinue
    return [bool]$conexoes
}

function Validar-Stunnel {
    # Verifica se o stunnel esta escutando nas portas locais 1514 e 1515
    $p1514 = Testar-PortaLocal -Porta $PortaAgente
    $p1515 = Testar-PortaLocal -Porta $PortaEnrollment

    if (-not $p1514 -or -not $p1515) {
        if (Test-Path -LiteralPath $StunnelLogPath) {
            Write-Aviso "Ultimas linhas do log do stunnel:"
            Get-Content -Path $StunnelLogPath -Tail 40 -ErrorAction SilentlyContinue
        }
        throw "O stunnel nao esta escutando em ${HostLoopback}:${PortaAgente} e ${HostLoopback}:${PortaEnrollment}"
    }
}

function Testar-ConectividadeTCP {
    param(
        [Parameter(Mandatory)][string]$Servidor,
        [Parameter(Mandatory)][int]$Porta
    )

    $resultado = Test-NetConnection -ComputerName $Servidor -Port $Porta -WarningAction SilentlyContinue
    if (-not $resultado.TcpTestSucceeded) {
        throw "Teste de conectividade falhou para ${Servidor}:${Porta}"
    }
}

function Instalar-WazuhAgent {
    param(
        [Parameter(Mandatory)][string]$CaminhoMsi,
        [Parameter(Mandatory)][string]$NomeAgente
    )

    # Instala o agente Wazuh apontando para o stunnel local em vez do servidor remoto
    $argumentos = @(
        "/i `"$CaminhoMsi`"",
        "WAZUH_MANAGER=`"$HostLoopback`"",
        "WAZUH_MANAGER_PORT=`"$PortaAgente`"",
        "WAZUH_PROTOCOL=`"TCP`"",
        "WAZUH_AGENT_NAME=`"$NomeAgente`"",
        "WAZUH_REGISTRATION_SERVER=`"$HostLoopback`"",
        "WAZUH_REGISTRATION_PORT=`"$PortaEnrollment`"",
        "/qn"
    )

    if (-not [string]::IsNullOrWhiteSpace($SenhaDeEnrollment)) {
        $argumentos += "WAZUH_REGISTRATION_PASSWORD=`"$SenhaDeEnrollment`""
    }

    $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList ($argumentos -join " ") -Wait -PassThru
    if ($proc.ExitCode -ne 0) {
        throw "Instalacao do MSI do Wazuh encerrou com codigo $($proc.ExitCode)"
    }

    if (-not (Test-Path -LiteralPath $WazuhCaminhoBase)) {
        throw "Diretorio de instalacao do agente Wazuh nao encontrado: $WazuhCaminhoBase"
    }
}

function Garantir-OssecConf {
    # Valida e corrige o ossec.conf para garantir endereco 127.0.0.1, porta 1514 e protocolo TCP
    if (-not (Test-Path -LiteralPath $WazuhConfPath)) {
        throw "ossec.conf nao encontrado em $WazuhConfPath"
    }

    [xml]$xml = Get-Content -Path $WazuhConfPath

    if (-not $xml.ossec_config) {
        throw "Formato invalido do ossec.conf."
    }

    if (-not $xml.ossec_config.client) {
        $noClient = $xml.CreateElement("client")
        $xml.ossec_config.AppendChild($noClient) | Out-Null
    }

    $noClient = $xml.ossec_config.client

    if (-not $noClient.server) {
        $noServer = $xml.CreateElement("server")
        $noClient.AppendChild($noServer) | Out-Null
    }

    $noServer = $noClient.server

    foreach ($campo in @("address", "port", "protocol")) {
        if (-not $noServer.$campo) {
            $novoNo = $xml.CreateElement($campo)
            $noServer.AppendChild($novoNo) | Out-Null
        }
    }

    $noServer.address  = $HostLoopback
    $noServer.port     = [string]$PortaAgente
    $noServer.protocol = "tcp"

    $xml.Save($WazuhConfPath)

    # Verificacao pos-escrita
    [xml]$verificar = Get-Content -Path $WazuhConfPath
    if ($verificar.ossec_config.client.server.address -ne $HostLoopback) {
        throw "Validacao do endereco no ossec.conf falhou."
    }
    if ([string]$verificar.ossec_config.client.server.port -ne [string]$PortaAgente) {
        throw "Validacao da porta no ossec.conf falhou."
    }
    if ($verificar.ossec_config.client.server.protocol -ne "tcp") {
        throw "Validacao do protocolo no ossec.conf falhou."
    }
}

function Enroll-WazuhAgent {
    param([Parameter(Mandatory)][string]$NomeAgente)

    if (-not (Test-Path -LiteralPath $AgentAuthExe)) {
        throw "agent-auth.exe nao encontrado em $AgentAuthExe"
    }

    $argumentos = @(
        "-m $HostLoopback",
        "-p $PortaEnrollment",
        "-A `"$NomeAgente`""
    )

    if (-not [string]::IsNullOrWhiteSpace($SenhaDeEnrollment)) {
        $argumentos += "-P `"$SenhaDeEnrollment`""
    }

    $proc = Start-Process `
        -FilePath $AgentAuthExe `
        -ArgumentList ($argumentos -join " ") `
        -WorkingDirectory $WazuhCaminhoBase `
        -Wait `
        -PassThru `
        -NoNewWindow

    if ($proc.ExitCode -ne 0) {
        if (Test-Path -LiteralPath $WazuhLogPath) {
            Write-Aviso "Ultimas linhas do log do Wazuh:"
            Get-Content -Path $WazuhLogPath -Tail 40 -ErrorAction SilentlyContinue
        }
        throw "agent-auth encerrou com codigo $($proc.ExitCode)"
    }
}

function Reiniciar-ServicoWazuh {
    $servico = Get-Service -Name $NomeServicoWazuh -ErrorAction SilentlyContinue
    if (-not $servico) {
        throw "Servico '$NomeServicoWazuh' nao encontrado."
    }

    Set-Service -Name $NomeServicoWazuh -StartupType Automatic

    if ($servico.Status -eq "Running") {
        Restart-Service -Name $NomeServicoWazuh -Force
    }
    else {
        Start-Service -Name $NomeServicoWazuh
    }

    Start-Sleep -Seconds 5

    $servico = Get-Service -Name $NomeServicoWazuh
    if ($servico.Status -ne "Running") {
        throw "Servico '$NomeServicoWazuh' nao esta em execucao apos reinicializacao."
    }
}

function Validar-LogWazuh {
    # Verifica o ossec.log em busca da mensagem de conexao bem-sucedida
    if (-not (Test-Path -LiteralPath $WazuhLogPath)) {
        throw "Log do Wazuh nao encontrado em $WazuhLogPath"
    }

    $linhas = Get-Content -Path $WazuhLogPath -Tail 80 -ErrorAction Stop
    Write-Info "Ultimas entradas do log do Wazuh:"
    $linhas | ForEach-Object { Write-Host $_ }

    $conteudo = $linhas -join "`n"
    if ($conteudo -match 'Connected to the server') {
        Write-Ok "Mensagem 'Connected to the server' detectada no ossec.log"
    }
    else {
        Write-Aviso "Mensagem 'Connected to the server' nao encontrada nas ultimas 80 linhas do log."
    }
}

function Exibir-Diagnostico {
    # Exibe as ultimas linhas dos logs de ambos os servicos para facilitar diagnostico em caso de erro
    Write-Host ""
    Write-Host "==== Diagnostico ====" -ForegroundColor Yellow

    if (Test-Path -LiteralPath $StunnelLogPath) {
        Write-Host "--- stunnel.log (ultimas 30 linhas) ---" -ForegroundColor Yellow
        Get-Content -Path $StunnelLogPath -Tail 30 -ErrorAction SilentlyContinue
    }

    if (Test-Path -LiteralPath $WazuhLogPath) {
        Write-Host "--- ossec.log (ultimas 30 linhas) ---" -ForegroundColor Yellow
        Get-Content -Path $WazuhLogPath -Tail 30 -ErrorAction SilentlyContinue
    }
}

# =========================
# Execucao principal
# =========================
try {
    Verificar-Administrador
    Garantir-Diretorio -Caminho $DiretorioDeTrabalho
    Garantir-Diretorio -Caminho $DiretorioDeLog

    Start-Transcript -Path $CaminhoTranscricao -Append | Out-Null

    Write-Etapa "Contexto da instalacao"
    Write-Info "Transcricao salva em: $CaminhoTranscricao"
    Write-Info "Nome do recurso: $NomeDoRecurso"
    Write-Info "Tentativas de retry: $TentativasDeRetry"
    Write-Info "Espera entre retries: $SegundosEntreRetry segundo(s)"

    # ---- Conectividade externa ----
    Write-Etapa "Validacao de conectividade"

    Invocar-ComRetry -Nome "Testar alcancabilidade do tunel de agente" -Bloco {
        Testar-ConectividadeTCP -Servidor $HostTunelAgente -Porta 443
    } | Out-Null
    Write-Ok "${HostTunelAgente}:443 alcancavel"

    Invocar-ComRetry -Nome "Testar alcancabilidade do tunel de enrollment" -Bloco {
        Testar-ConectividadeTCP -Servidor $HostTunelEnrollment -Porta 443
    } | Out-Null
    Write-Ok "${HostTunelEnrollment}:443 alcancavel"

    # ---- stunnel ----
    Write-Etapa "Instalacao do stunnel"

    $urlStunnel = Obter-UrlInstaladorStunnel
    Write-Info "URL do instalador stunnel mais recente: $urlStunnel"

    Baixar-Arquivo -Url $urlStunnel -Destino $StunnelInstalador
    Write-Ok "Instalador do stunnel baixado"

    Invocar-ComRetry -Nome "Instalar stunnel" -Bloco {
        Instalar-Stunnel -CaminhoInstalador $StunnelInstalador
    } | Out-Null
    Write-Ok "stunnel instalado"

    Configurar-Stunnel
    Write-Ok "stunnel.conf configurado"

    Invocar-ComRetry -Nome "Iniciar servico do stunnel" -Bloco {
        Garantir-ServicoRodando -Nome $NomeServicoStunnel -TipoInicializacao Automatic
    } | Out-Null
    Write-Ok "$NomeServicoStunnel em execucao"

    Invocar-ComRetry -Nome "Validar listeners do stunnel" -Bloco {
        Validar-Stunnel
    } | Out-Null
    Write-Ok "stunnel escutando em ${HostLoopback}:${PortaAgente} e ${HostLoopback}:${PortaEnrollment}"

    # ---- Wazuh Agent ----
    Write-Etapa "Instalacao do agente Wazuh"

    Baixar-Arquivo -Url $WazuhMsiUrl -Destino $WazuhInstalador
    Write-Ok "MSI do agente Wazuh baixado"

    Invocar-ComRetry -Nome "Instalar MSI do agente Wazuh" -Bloco {
        Instalar-WazuhAgent -CaminhoMsi $WazuhInstalador -NomeAgente $NomeDoRecurso
    } | Out-Null
    Write-Ok "Agente Wazuh instalado"

    Invocar-ComRetry -Nome "Validar ossec.conf" -Bloco {
        Garantir-OssecConf
    } | Out-Null
    Write-Ok "ossec.conf configurado para ${HostLoopback}:${PortaAgente} tcp"

    # ---- Enrollment ----
    Write-Etapa "Enrollment do agente Wazuh"

    Invocar-ComRetry -Nome "Realizar enrollment do agente Wazuh" -Bloco {
        Enroll-WazuhAgent -NomeAgente $NomeDoRecurso
    } | Out-Null
    Write-Ok "Agente Wazuh registrado com sucesso"

    Invocar-ComRetry -Nome "Iniciar ou reiniciar o servico Wazuh" -Bloco {
        Reiniciar-ServicoWazuh
    } | Out-Null
    Write-Ok "$NomeServicoWazuh em execucao"

    # ---- Validacao final ----
    Write-Etapa "Validacao pos-instalacao"
    Validar-LogWazuh

    Write-Host ""
    Write-Host "==== Instalacao concluida ====" -ForegroundColor Green
    Write-Ok "Recurso '$NomeDoRecurso' configurado com sucesso."
    Write-Info "Recomenda-se confirmar o status do agente no servidor com: agent_control -l (no host wazuh-master)."
}
catch {
    Write-Host ""
    Write-Host "ERRO: $($_.Exception.Message)" -ForegroundColor Red
    Exibir-Diagnostico
    exit 1
}
finally {
    try {
        Stop-Transcript | Out-Null
    }
    catch {
        # Ignora erros ao encerrar a transcricao
    }
}
