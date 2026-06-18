#!/usr/bin/env bash
# install-wazuh-agent.sh
#
# Instala e configura o Wazuh Agent + cliente stunnel no Ubuntu.
#
# Fluxo:
#   1. Instalar stunnel4 (apt)
#   2. Gravar configuração do cliente stunnel com túneis SNI na porta 443
#   3. Habilitar e iniciar o serviço stunnel4
#   4. Adicionar repositório apt do Wazuh e instalar o agente
#   5. Corrigir /var/ossec/etc/ossec.conf (127.0.0.1:1514 TCP)
#   6. Registrar o agente no manager via agent-auth (-P senha)
#   7. Habilitar e iniciar o serviço wazuh-agent
#
# Requisitos:
#   - Ubuntu 20.04 / 22.04 / 24.04 (x86_64)
#   - Executar como root (sudo bash install-wazuh-agent.sh ...)
#   - TCP 443 de saída liberado para agents-wazuh.carbigdata.com.br
#                                        enroll-wazuh.carbigdata.com.br
#
# Uso:
#   sudo bash install-wazuh-agent.sh -n <nome-do-agente> [opções]
#
# Opções:
#   -n <nome>    Nome do agente exibido no Wazuh Dashboard  (OBRIGATÓRIO)
#   -w <versão>  Versão do Wazuh a instalar (padrão: 4.14.5)
#   -s           Ignorar apt-get update (usar listas de pacotes em cache)
#   -h           Exibir esta ajuda
#
# Exemplos:
#   sudo bash install-wazuh-agent.sh -n ubuntu-prod-01
#   sudo bash install-wazuh-agent.sh -n db-server-02 -w 4.14.5

set -euo pipefail

# ── Helpers de cor ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; RESET='\033[0m'

step()  { echo -e "\n${CYAN}==> $*${RESET}"; }
ok()    { echo -e "    ${GREEN}[OK]${RESET} $*"; }
warn()  { echo -e "    ${YELLOW}[!!]${RESET} $*"; }
fail()  { echo -e "    ${RED}[XX]${RESET} $*" >&2; exit 1; }
log()   { echo "$(date '+%Y-%m-%d %H:%M:%S')  $*" >> "$LOG_FILE"; }

# ── Configuração — ajuste conforme seu ambiente ───────────────────────────────
AGENTS_SNI="agents-wazuh.carbigdata.com.br"
ENROLL_SNI="enroll-wazuh.carbigdata.com.br"
TUNNEL_PORT=443
AGENT_PORT=1514
ENROLL_PORT=1515

# Caminhos
STUNNEL_CONF="/etc/stunnel/wazuh-agent.conf"
STUNNEL_DEFAULT="/etc/default/stunnel4"
WAZUH_DIR="/var/ossec"
OSSEC_CONF="$WAZUH_DIR/etc/ossec.conf"
CLIENT_KEYS="$WAZUH_DIR/etc/client.keys"
LOG_FILE="/tmp/wazuh-agent-install.log"
# ──────────────────────────────────────────────────────────────────────────────

# ── Valores padrão ────────────────────────────────────────────────────────────
AGENT_NAME=""
WAZUH_VERSION="4.14.5"
SKIP_UPDATE=false

usage() {
    grep '^#' "$0" | grep -E '^\# ' | sed 's/^# //' | head -40
    exit 0
}

while getopts "n:w:sh" opt; do
    case "$opt" in
        n) AGENT_NAME="$OPTARG" ;;
        w) WAZUH_VERSION="$OPTARG" ;;
        s) SKIP_UPDATE=true ;;
        h) usage ;;
        *) fail "Opção desconhecida. Execute com -h para ver a ajuda." ;;
    esac
done

# ── Verificações iniciais ─────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && fail "Este script deve ser executado como root. Use: sudo bash $0 $*"

[[ -z "$AGENT_NAME" ]] && fail "Nome do agente é obrigatório. Use: -n <nome-do-agente>"

# Detectar arquitetura
ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m)
[[ "$ARCH" == "x86_64" ]] && ARCH="amd64"
[[ "$ARCH" =~ ^(amd64|arm64|armhf)$ ]] || fail "Arquitetura não suportada: $ARCH"

# Detectar versão do Ubuntu
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    DISTRO_NAME="$NAME"
    DISTRO_VERSION="$VERSION_ID"
else
    fail "Não foi possível identificar o sistema operacional. /etc/os-release não encontrado."
fi

echo -e "\n${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗"
echo -e   "║   Wazuh Agent + stunnel — Instalador Ubuntu                  ║"
echo -e   "╚══════════════════════════════════════════════════════════════╝${RESET}\n"
echo -e "  Nome do agente : ${BOLD}$AGENT_NAME${RESET}"
echo -e "  Versão Wazuh   : $WAZUH_VERSION"
echo -e "  SNI agentes    : $AGENTS_SNI"
echo -e "  SNI registro   : $ENROLL_SNI"
echo -e "  Sistema        : $DISTRO_NAME $DISTRO_VERSION ($ARCH)"
echo -e "  Arquivo de log : $LOG_FILE"
echo ""

log "=== Instalação iniciada. AgentName=$AGENT_NAME WazuhVersion=$WAZUH_VERSION OS=$DISTRO_NAME $DISTRO_VERSION ==="

# =============================================================================
# PASSO 1 — Instalar stunnel4
# =============================================================================
step "Passo 1/7 — Instalando stunnel4"

if command -v stunnel4 &>/dev/null || command -v stunnel &>/dev/null; then
    warn "stunnel já está instalado — ignorando esta etapa"
    log "stunnel já instalado"
else
    if [[ "$SKIP_UPDATE" == false ]]; then
        echo "    Atualizando lista de pacotes..."
        apt-get update -qq
    fi
    apt-get install -y stunnel4 curl gnupg2 >/dev/null
    ok "stunnel4 instalado"
    log "stunnel4 instalado"
fi

# =============================================================================
# PASSO 2 — Gravar configuração do cliente stunnel
# =============================================================================
step "Passo 2/7 — Gravando configuração do stunnel"

mkdir -p /etc/stunnel

cat > "$STUNNEL_CONF" << EOF
; Configuração do cliente stunnel — túnel do agente Wazuh
; Encapsula o protocolo binário do Wazuh em TLS com SNI para roteamento
; pelo external-ingress na porta $TUNNEL_PORT.
;
; NÃO EDITAR — gerenciado pelo install-wazuh-agent.sh
;
; Validação do certificado do servidor:
;   verifyChain = yes  — valida a cadeia contra o root-ca.pem do Wazuh
;   checkHost         — garante que o CN/SAN do cert coincide com o hostname
;                       (funciona porque o cert foi gerado com os SANs corretos
;                        via generate-stunnel-cert.sh)

client = yes
pid    = /run/stunnel4/wazuh-agent.pid

; Comunicação contínua do agente (ossec-agentd -> wazuh-master:$AGENT_PORT)
[wazuh-agents]
accept       = 127.0.0.1:$AGENT_PORT
connect      = ${AGENTS_SNI}:${TUNNEL_PORT}
verifyChain  = yes
checkHost    = $AGENTS_SNI
CAfile       = /etc/stunnel/wazuh-ca.pem

; Registro do agente (agent-auth -> wazuh-master:$ENROLL_PORT)
[wazuh-enrollment]
accept       = 127.0.0.1:$ENROLL_PORT
connect      = ${ENROLL_SNI}:${TUNNEL_PORT}
verifyChain  = yes
checkHost    = $ENROLL_SNI
CAfile       = /etc/stunnel/wazuh-ca.pem
EOF

# Gravar o CA cert do Wazuh (embutido no script)
cat > /etc/stunnel/wazuh-ca.pem << 'WAZUH_CA'
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
WAZUH_CA
chmod 644 /etc/stunnel/wazuh-ca.pem
ok "CA cert gravado em /etc/stunnel/wazuh-ca.pem"

ok "Configuração gravada em $STUNNEL_CONF"
log "stunnel.conf gravado"

# =============================================================================
# PASSO 3 — Habilitar e iniciar o serviço stunnel4
# =============================================================================
step "Passo 3/7 — Habilitando o serviço stunnel4"

# O pacote stunnel4 no Debian/Ubuntu usa /etc/default/stunnel4 para habilitar o daemon
if [[ -f "$STUNNEL_DEFAULT" ]]; then
    # Habilitar o daemon (substitui ENABLED=0 por ENABLED=1, ou adiciona se não existir)
    if grep -q '^ENABLED=' "$STUNNEL_DEFAULT"; then
        sed -i 's/^ENABLED=.*/ENABLED=1/' "$STUNNEL_DEFAULT"
    else
        echo 'ENABLED=1' >> "$STUNNEL_DEFAULT"
    fi
    # Garantir que FILES aponte para nossa configuração
    if grep -q '^FILES=' "$STUNNEL_DEFAULT"; then
        sed -i 's|^FILES=.*|FILES="/etc/stunnel/*.conf"|' "$STUNNEL_DEFAULT"
    else
        echo 'FILES="/etc/stunnel/*.conf"' >> "$STUNNEL_DEFAULT"
    fi
fi

# O stunnel precisa que o diretório do pid file exista antes de iniciar.
# /run é um tmpfs — o diretório some a cada reboot. Criar entrada no tmpfiles.d
# para recriá-lo automaticamente na inicialização do sistema.
mkdir -p /run/stunnel4
chown root:root /run/stunnel4
echo 'd /run/stunnel4 0755 root root -' > /etc/tmpfiles.d/stunnel4.conf

systemctl daemon-reload
systemctl enable stunnel4 --quiet
systemctl restart stunnel4

# Aguardar o processo fazer o bind nas portas
sleep 2

if ! systemctl is-active --quiet stunnel4; then
    journalctl -u stunnel4 --no-pager -n 20 >&2
    fail "stunnel4 falhou ao iniciar — veja o log acima"
fi
ok "stunnel4 em execução"
log "stunnel4 iniciado"

# Verificar se as portas estão escutando
for PORT in $AGENT_PORT $ENROLL_PORT; do
    echo -n "    Aguardando stunnel escutar na porta $PORT..."
    DEADLINE=$(( $(date +%s) + 30 ))
    until ss -tlnp 2>/dev/null | grep -q ":$PORT "; do
        [[ $(date +%s) -gt $DEADLINE ]] && fail "stunnel não está escutando na porta $PORT após 30s"
        sleep 1
    done
    echo -e " ${GREEN}OK${RESET}"
done
log "Portas stunnel $AGENT_PORT e $ENROLL_PORT verificadas"

# =============================================================================
# PASSO 4 — Adicionar repositório apt do Wazuh e instalar o agente
# =============================================================================
step "Passo 4/7 — Instalando o Wazuh Agent"

if systemctl is-active --quiet wazuh-agent 2>/dev/null || \
   [[ -f "$WAZUH_DIR/bin/wazuh-agentd" ]]; then
    warn "Wazuh Agent já está instalado — ignorando instalação do pacote"
    log "Wazuh já instalado"
else
    WAZUH_GPG="/usr/share/keyrings/wazuh.gpg"
    WAZUH_LIST="/etc/apt/sources.list.d/wazuh.list"

    if [[ ! -f "$WAZUH_GPG" ]]; then
        echo "    Importando chave GPG do Wazuh..."
        curl -sS https://packages.wazuh.com/key/GPG-KEY-WAZUH \
            | gpg --no-default-keyring \
                  --keyring gnupg-ring:"$WAZUH_GPG" \
                  --import
        chmod 644 "$WAZUH_GPG"
    fi

    if [[ ! -f "$WAZUH_LIST" ]]; then
        echo "deb [signed-by=$WAZUH_GPG] https://packages.wazuh.com/4.x/apt/ stable main" \
            > "$WAZUH_LIST"
    fi

    if [[ "$SKIP_UPDATE" == false ]]; then
        apt-get update -qq
    fi

    echo "    Instalando wazuh-agent=$WAZUH_VERSION-1 (pode levar alguns minutos)..."
    WAZUH_MANAGER="127.0.0.1"              \
    WAZUH_MANAGER_PORT="$AGENT_PORT"       \
    WAZUH_PROTOCOL="TCP"                   \
    WAZUH_AGENT_NAME="$AGENT_NAME"         \
    WAZUH_REGISTRATION_SERVER="127.0.0.1"  \
    WAZUH_REGISTRATION_PORT="$ENROLL_PORT" \
    apt-get install -y "wazuh-agent=$WAZUH_VERSION-1" >/dev/null

    ok "Wazuh Agent instalado"
    log "wazuh-agent $WAZUH_VERSION instalado"
fi

# =============================================================================
# PASSO 5 — Verificar / corrigir ossec.conf
# =============================================================================
step "Passo 5/7 — Verificando ossec.conf"

[[ -f "$OSSEC_CONF" ]] || fail "ossec.conf não encontrado em $OSSEC_CONF"

PATCHED=false

patch_xml_value() {
    local field="$1" expected="$2"
    # Captura o valor atual, removendo espaços/quebras de linha ao redor
    local current
    current=$(grep -oP "(?<=<${field}>)[^<]+" "$OSSEC_CONF" 2>/dev/null | head -1 | tr -d '[:space:]' || true)

    if [[ -z "$current" ]]; then
        warn "Campo <$field> não encontrado em ossec.conf — ignorando"
        return
    fi

    if [[ "$current" != "$expected" ]]; then
        # Usa [^<]* no padrão — substitui qualquer valor entre as tags sem
        # interpolar $current no sed (evita erros com espaços, pipes ou newlines)
        sed -i "s|<${field}>[^<]*</${field}>|<${field}>${expected}</${field}>|g" "$OSSEC_CONF"
        warn "Corrigido: <$field> '$current' → '$expected'"
        PATCHED=true
    fi
}

patch_xml_value "address"  "127.0.0.1"
patch_xml_value "port"     "$AGENT_PORT"
patch_xml_value "protocol" "tcp"

if [[ "$PATCHED" == false ]]; then
    ok "ossec.conf já está correto — nenhuma alteração necessária"
else
    ok "ossec.conf corrigido e salvo"
fi
log "ossec.conf verificado PATCHED=$PATCHED"

# =============================================================================
# PASSO 6 — Registrar o agente
# =============================================================================
step "Passo 6/7 — Registrando o agente"

if [[ -s "$CLIENT_KEYS" ]]; then
    warn "client.keys já existe — ignorando registro (agente já cadastrado)"
    log "Registro ignorado — agente já registrado"
else
    echo "    Executando agent-auth..."
    AUTH_OUT=$("$WAZUH_DIR/bin/agent-auth" \
        -m 127.0.0.1 \
        -p "$ENROLL_PORT" \
        -A "$AGENT_NAME" 2>&1) || true

    log "Saída do agent-auth: $AUTH_OUT"

    if echo "$AUTH_OUT" | grep -q "Valid key received"; then
        ok "Agente registrado com sucesso"
        log "Registro concluído com sucesso"
    else
        echo ""
        echo -e "  ${YELLOW}Saída do agent-auth:${RESET}"
        echo "$AUTH_OUT" | sed 's/^/    /'
        fail "Registro falhou — verifique a conectividade do stunnel com ${ENROLL_SNI}:${TUNNEL_PORT}"
    fi
fi

# =============================================================================
# PASSO 7 — Habilitar e iniciar wazuh-agent
# =============================================================================
step "Passo 7/7 — Iniciando o serviço wazuh-agent"

systemctl daemon-reload
systemctl enable wazuh-agent --quiet
systemctl restart wazuh-agent

sleep 3

WAZUH_STATUS=$(systemctl is-active wazuh-agent 2>/dev/null || echo "desconhecido")
if [[ "$WAZUH_STATUS" == "active" ]]; then
    ok "wazuh-agent em execução"
    log "wazuh-agent iniciado"
else
    warn "Status do wazuh-agent: $WAZUH_STATUS — verifique $WAZUH_DIR/logs/ossec.log"
    log "wazuh-agent status=$WAZUH_STATUS"
fi

# =============================================================================
# Resumo
# =============================================================================
AGENT_ID=$(awk '{print $1}' "$CLIENT_KEYS" 2>/dev/null || echo "—")

echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════════════╗"
echo -e   "║   Instalação concluída                                        ║"
echo -e   "╚══════════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  Nome do agente : ${BOLD}$AGENT_NAME${RESET}"
echo -e "  ID do agente   : $AGENT_ID"
echo ""
echo "  Serviços:"
printf "    %-12s: %s\n" "stunnel4"     "$(systemctl is-active stunnel4 2>/dev/null)"
printf "    %-12s: %s\n" "wazuh-agent"  "$(systemctl is-active wazuh-agent 2>/dev/null)"
echo ""
echo "  Arquivos de log:"
echo "    Instalação : $LOG_FILE"
echo "    Wazuh      : $WAZUH_DIR/logs/ossec.log"
echo "    stunnel    : journalctl -u stunnel4 -f"
echo ""
echo -e "  ${CYAN}Verificar no manager:${RESET}"
echo "    docker exec -it \$(docker ps -q -f name=wazuh-master) \\"
echo "      /var/ossec/bin/agent_control -l"
echo ""

log "=== Instalação finalizada ==="