# Wazuh Agent — Instalação em Windows (via stunnel + TLS)

Este diretório contém o script PowerShell para instalação automatizada do agente Wazuh em máquinas Windows, com tunelamento TLS via stunnel e roteamento por SNI na porta 443.

## Fluxo de tráfego

```
Wazuh Agent (Windows)
  → stunnel client (127.0.0.1:1514 / :1515)
    → TLS tunnel com SNI
      → external-ingress (porta 443, roteamento SNI)
        → stunnel server (x-security)
          → wazuh-master (:1514 / :1515)
```

## Pré-requisitos

- Windows 10/11 ou Windows Server 2016+
- PowerShell 5.1 ou superior
- Execução como **Administrador**
- Acesso de saída na **porta TCP 443** para os hosts:
  - `agents-wazuh.carbigdata.com.br`
  - `enroll-wazuh.carbigdata.com.br`

## Arquivos

| Arquivo | Descrição |
|---|---|
| `install-wazuh-windows.ps1` | Script principal de instalação automatizada |

## O que o script faz

O script executa automaticamente todas as etapas abaixo, sem interação adicional após a pergunta inicial:

1. Valida conectividade TCP 443 com os endpoints externos
2. Baixa e instala a versão mais recente do **stunnel** (win64)
3. Configura o `stunnel.conf` com os dois túneis (agente e enrollment)
4. Inicia e configura o serviço `stunnel TLS wrapper` como automático
5. Valida que stunnel está escutando em `127.0.0.1:1514` e `127.0.0.1:1515`
6. Baixa e instala o **Wazuh Agent 4.14.5** via MSI silencioso
7. Valida e corrige o `ossec.conf` (endereço, porta e protocolo TCP)
8. Realiza o **enrollment** do agente via `agent-auth.exe`
9. Inicia e configura o serviço `WazuhSvc` como automático
10. Verifica o `ossec.log` em busca de confirmação de conexão

## Como executar

Abra o **PowerShell como Administrador** e execute:

### Execução simples

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\install-wazuh-windows.ps1
```

O script solicitará apenas o nome do recurso (identificação do agente no Wazuh):

```
Informe o nome do recurso para identificar esta máquina no Wazuh: MINHA-VM-PRODUCAO
```

### Com senha de enrollment

Utilize o parâmetro `-SenhaDeEnrollment` caso o servidor Wazuh exija autenticação no enrollment:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\install-wazuh-windows.ps1 `
    -SenhaDeEnrollment "sua-senha-de-enrollment"
```

### Customizando retries e delay

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\install-wazuh-windows.ps1 `
    -TentativasDeRetry 5 `
    -SegundosEntreRetry 10
```

### Todos os parâmetros disponíveis

| Parâmetro | Padrão | Descrição |
|---|---|---|
| `SenhaDeEnrollment` | *(vazio)* | Senha de enrollment do servidor Wazuh (opcional) |
| `TentativasDeRetry` | `3` | Número de tentativas em operações que podem falhar |
| `SegundosEntreRetry` | `5` | Segundos de espera entre cada tentativa |
| `DiretorioDeLog` | `C:\ProgramData\WazuhBootstrap\Logs` | Diretório onde a transcrição será salva |

## Logs e diagnóstico

O script grava uma transcrição completa da execução em:

```
C:\ProgramData\WazuhBootstrap\Logs\wazuh-bootstrap-YYYYMMDD-HHmmss.log
```

Em caso de falha, os logs internos dos serviços também são exibidos automaticamente:

| Log | Caminho |
|---|---|
| stunnel | `C:\Program Files (x86)\stunnel\log\stunnel.log` |
| Wazuh Agent | `C:\Program Files (x86)\ossec-agent\ossec.log` |

## Validação no servidor (wazuh-master)

Após a instalação, confirme o status do agente no host `x-security`:

```bash
docker exec -it $(docker ps -q -f name=wazuh-master) \
  /var/ossec/bin/agent_control -l
```

O agente deve aparecer como **Active**.

## Solução de problemas

| Sintoma | Verificação |
|---|---|
| stunnel não escuta em 1514/1515 | Verifique `C:\Program Files (x86)\stunnel\log\stunnel.log` |
| `agent-auth` expira sem resposta | Confirme que DNS resolve `enroll-wazuh.carbigdata.com.br` e que a porta 443 está acessível |
| Agente registra mas fica "Never connected" | Confirme `<protocol>tcp</protocol>` no `ossec.conf` e reinicie o `WazuhSvc` |
| Firewall bloqueando | Libere saída TCP 443 a partir da VM |

Teste rápido de conectividade (PowerShell):

```powershell
Test-NetConnection -ComputerName agents-wazuh.carbigdata.com.br -Port 443
Test-NetConnection -ComputerName enroll-wazuh.carbigdata.com.br -Port 443
```
