# wazuh-agents

Instalação automatizada do Agente Wazuh para Windows e Linux, com suporte a túnel TLS via **stunnel** para ambientes que expõem apenas a porta 443.

---

## Estrutura do repositório

```
wazuh-agents/
├── windows/
│   └── install-wazuh-windows-v2.ps1   # Instalador automatizado para Windows
└── README.md
```

---

## Windows — `install-wazuh-windows-v2.ps1`

Script PowerShell que automatiza a instalação completa do **Agente Wazuh + stunnel** em hosts Windows, incluindo:

1. Download e instalação do **stunnel** (cliente de túnel TLS)
2. Geração automática do `stunnel.conf` com roteamento SNI na porta 443
3. Habilitação e inicialização do serviço stunnel
4. Download e instalação do **MSI do Agente Wazuh**
5. Correção automática do `ossec.conf` para usar `127.0.0.1:1514` via TCP (através do stunnel)
6. Registro do agente no manager via `agent-auth`
7. Habilitação e inicialização do serviço `WazuhSvc`

### Pré-requisitos

- Windows 10 / Windows Server 2016 ou superior
- PowerShell 5.1+
- **Executar como Administrador** (`#Requires -RunAsAdministrator`)
- Acesso à internet para baixar os instaladores (ou usar `-SkipDownload` com os arquivos já presentes)
- Porta 443 de saída liberada para os SNIs configurados

### Configuração

Edite o bloco de variáveis no início do script conforme seu ambiente:

| Variável | Padrão | Descrição |
|---|---|---|
| `$AGENTS_SNI` | `agents-wazuh.carbigdata.com.br` | FQDN do ingress para comunicação do agente (porta 1514) |
| `$ENROLL_SNI` | `enroll-wazuh.carbigdata.com.br` | FQDN do ingress para registro do agente (porta 1515) |
| `$TUNNEL_PORT` | `443` | Porta externa do ingress TLS |
| `$AGENT_PORT` | `1514` | Porta local stunnel → manager (agentd) |
| `$ENROLL_PORT` | `1515` | Porta local stunnel → manager (enrollment) |

### Parâmetros

| Parâmetro | Tipo | Padrão | Descrição |
|---|---|---|---|
| `-AgentName` | string | `$env:COMPUTERNAME` | Nome com o qual o agente será registrado no manager |
| `-WazuhVersion` | string | `4.14.5` | Versão do agente Wazuh a instalar |
| `-EnrollmentPassword` | string | *(vazio)* | Senha de registro, caso configurada no manager |
| `-SkipDownload` | switch | *(não ativo)* | Ignora o download se os instaladores já existirem em `%TEMP%\wazuh-install` |

### Uso

```powershell
# Instalação com padrões (hostname como nome do agente)
.\install-wazuh-windows-v2.ps1

# Nome de agente personalizado
.\install-wazuh-windows-v2.ps1 -AgentName "windows-server-prod-01"

# Com senha de registro
.\install-wazuh-windows-v2.ps1 -EnrollmentPassword "MinhaSenha123"

# Versão específica do Wazuh + pular download
.\install-wazuh-windows-v2.ps1 -WazuhVersion "4.12.0" -SkipDownload
```

> **Dica:** Para executar o script sem restrição de política de execução:
> ```powershell
> powershell.exe -ExecutionPolicy Bypass -File .\install-wazuh-windows-v2.ps1
> ```

### Fluxo de instalação (7 passos)

```
Passo 1 — Baixa stunnel-installer.exe e wazuh-agent-<versão>-1.msi
Passo 2 — Instala stunnel silenciosamente (/S)
Passo 3 — Grava stunnel.conf com dois listeners (1514 e 1515)
Passo 4 — Habilita/reinicia o serviço stunnel e verifica as portas
Passo 5 — Instala o MSI do Wazuh apontando para 127.0.0.1 via TCP
Passo 6 — Corrige ossec.conf (address/port/protocol) se necessário
Passo 7 — Executa agent-auth e inicia WazuhSvc
```

### Arquivos de log

| Arquivo | Conteúdo |
|---|---|
| `%TEMP%\wazuh-install\install.log` | Log geral da instalação |
| `%TEMP%\wazuh-install\wazuh-msi.log` | Log detalhado do MSI do Wazuh |
| `C:\Program Files (x86)\ossec-agent\ossec.log` | Log do agente Wazuh |
| `C:\Program Files (x86)\stunnel\log\stunnel.log` | Log do serviço stunnel |

### Verificar no manager

Após a instalação, confirme que o agente está ativo no manager Wazuh:

```bash
docker exec -it $(docker ps -q -f name=wazuh-master) \
  /var/ossec/bin/agent_control -l
```

### Arquitetura de rede

```
 [Windows Host]
  ossec-agentd  →  127.0.0.1:1514
  agent-auth    →  127.0.0.1:1515
        │
   [stunnel client]
        │  TLS + SNI
        ▼
  agents-wazuh.<domínio>:443  →  Wazuh Manager :1514
  enroll-wazuh.<domínio>:443  →  Wazuh Manager :1515
```

---

## Licença

MIT
