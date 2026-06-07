# AEGIS Anti-Phishing Pipeline

> Detecção de domínios de phishing em tempo real via Certificate Transparency, com arquitetura de dupla costimulação e análise por IA.

[![Python](https://img.shields.io/badge/Python-3.12-blue)](https://python.org)
[![n8n](https://img.shields.io/badge/n8n-self--hosted-orange)](https://n8n.io)
[![Docker](https://img.shields.io/badge/Docker-compose-blue)](https://docker.com)
[![Gemini](https://img.shields.io/badge/Gemini-API-green)](https://aistudio.google.com)
[![Telegram](https://img.shields.io/badge/Alertas-Telegram-blue)](https://t.me/phishing_alerts_aegis)

---

## O problema

Domínios de phishing que imitam marcas (bancos, fintechs, e-commerce) são registrados aos milhares por dia. Eles aparecem nos logs públicos de **Certificate Transparency** assim que emitem um certificado SSL geralmente **antes** de entrarem em qualquer blacklist ou serem reportados ao VirusTotal.

A janela entre o registro e a primeira vítima é onde esse pipeline atua.

O maior inimigo de um sistema de detecção não é perder alertas é o falso positivo. Um sistema que gera muito ruído satura o analista e destrói a confiança nos alertas. Por isso a arquitetura central do projeto é de **dupla costimulação**: nenhum alerta é emitido com base num único sinal. Cada suspeito passa por dois filtros independentes antes de virar alerta.

---

## Arquitetura

```
┌──────────────────────────────────────────────────────────┐
│              Certificate Transparency Logs               │
│   (Google, Let's Encrypt, Sectigo, DigiCert — públicos)  │
└─────────────────────────┬────────────────────────────────┘
                          │ milhares de certificados/min
┌─────────────────────────▼────────────────────────────────┐
│           CertStream Server (self-hosted, Docker)        │
│   Consome os logs CT e transmite via WebSocket local     │
└─────────────────────────┬────────────────────────────────┘
                          │ ws://localhost:8888/
┌─────────────────────────▼────────────────────────────────┐
│         CAMADA 1 — Triagem Heurística (Python)           │
│                                                          │
│  • Extração de tokens por domínio registrável (SLD)      │
│  • Normalização de homóglifos (leet, Unicode, cirílico)  │
│  • Match exato + Levenshtein (typosquatting)             │
│  • Detecção de combosquatting fundido                    │
│  • Allowlist de domínios oficiais e infraestrutura       │
│  • Costimulação TEXTUAL: marca + 2º sinal independente   │
│                                                          │
│  Resultado: descarta ~99% → envia só candidatos reais    │
└─────────────────────────┬────────────────────────────────┘
                          │ HTTP POST (candidatos apenas)
┌─────────────────────────▼────────────────────────────────┐
│         CAMADA 2 — Confirmação Factual (n8n)             │
│                                                          │
│  Webhook → VirusTotal API → RDAP (idade do domínio)      │
│                    ↓                                     │
│  IF (OR): VT malicioso > 0                               │
│         | VT suspeito > 0                                │
│         | score heurístico > 69                          │
│                    ↓ true                                │
│  Costimulação FACTUAL: dado externo verificável          │
│                    ↓ false → descarta silenciosamente    │
└─────────────────────────┬────────────────────────────────┘
                          │
┌─────────────────────────▼────────────────────────────────┐
│              Análise por IA (Google Gemini)              │
│                                                          │
│  Prompt estruturado → JSON com:                          │
│  veredito, marca_alvo, tecnica, confianca,               │
│  modus_operandi, indicadores_chave, acao_recomendada     │
└─────────────────────────┬────────────────────────────────┘
                          │
┌─────────────────────────▼────────────────────────────────┐
│         Formatação (n8n Code) + Entrega (Telegram)       │
│         Canal público: t.me/phishing_alerts_aegis        │
└──────────────────────────────────────────────────────────┘
```

**Workflow completo 6 nós conectados:**
![Pipeline n8n](https://raw.githubusercontent.com/mateusdias96cs/aegis-antiphishing-pipeline/main/assets/3.png)
---

**Execuções em tempo real pipeline processando alertas automaticamente:**
![Execuções n8n](https://raw.githubusercontent.com/mateusdias96cs/aegis-antiphishing-pipeline/main/assets/1.png)


## Como funciona — passo a passo

### 1. Coleta via Certificate Transparency

Todo site HTTPS precisa emitir um certificado SSL registrado publicamente. O servidor CertStream self-hosted consome esses logs em tempo real e transmite cada novo certificado como stream WebSocket local.

**Por que self-hosted:** o servidor público da Calidog estava degradado. Rodar a própria infraestrutura elimina o ponto único de falha e remove a dependência de serviços externos instáveis.

```bash
docker run -d --name certstream --restart unless-stopped \
  -p 8888:8080 0rickyy0/certstream-server-go
```

### 2. Triagem heurística (Camada 1)

O script Python processa cada certificado e aplica quatro técnicas de detecção:

**Match por token (não por substring)**

O domínio é quebrado no rótulo registrável (SLD) e tokenizado por separadores. Só os tokens são comparados com as marcas não o domínio inteiro.

```
meliuz-login.xyz  →  tokens: ["meliuz", "login"]  →  match em "meliuz"
amazonaws.com     →  token: ["amazonaws"]          →  sem match com "amazon"
```

Isso elimina na raiz os falsos positivos estruturais que a comparação por substring produz.

**Normalização de homóglifos**

Antes de qualquer comparação, o domínio é reduzido à forma canônica:

```
m3liuz   →  meliuz   (leet speak: 3→e)
mеliuz   →  meliuz   (cirílico: е→e, visualmente idêntico)
méliuz   →  meliuz   (acento Unicode)
```

O uso de homóglifo na marca é, por si só, sinal de evasão deliberada.

**Distância de Levenshtein (typosquatting)**

Mede quantas edições separam um token da marca. Captura variações nunca previstas, sem lista manual.

```
melluz   →  distância 1 de "meliuz"  →  typosquatting detectado
paybank  →  distância 1 de "pagbank" →  detectado (mas descartado se sem 2º sinal)
```

Tolerância proporcional ao tamanho da marca: marcas com até 4 caracteres só aceitam match exato (evita ruído de marcas curtas como `itau`).

**Combosquatting fundido**

Detecta `meliuzlogin`, `nubankconta` — marca colada a uma keyword sem separador. Só confirma se o restante for uma palavra do dicionário de risco:

```
meliuzlogin   →  "meliuz" + "login" (KEYWORDS_HIGH)  →  combosquatting
meliuzxkqbz   →  "meliuz" + "xkqbz" (não é keyword)  →  ignorado
```

**Costimulação textual**

Marca sozinha geralmente não basta para gerar alerta. Exige um segundo sinal independente:

| Sinal | Exemplo |
|---|---|
| Homóglifo na marca | `m3liuz-login.com` |
| Combosquatting | `meliuzconta.net` |
| Palavra crítica | `meliuz-secure.com` |
| TLD suspeito | `meliuz.xyz` |
| Marca exata no SLD (impersonação direta) | `meliuz.online` |

Typosquatting puro sem nenhum outro sinal é descartado:

```
paybank.de  →  typo de "pagbank" + nada mais  →  DESCARTADO
paybank-login.xyz  →  typo + keyword + TLD suspeito  →  CANDIDATO
```

### 3. Confirmação factual (Camada 2)

Os candidatos da camada 1 chegam ao n8n via webhook. O n8n consulta:

**VirusTotal:** reputação do domínio detecções maliciosas, suspeitas, tags (`dga`, etc.).

**RDAP:** data de criação do domínio. Um 404 indica domínio recém-criado ou ainda não propagado nos registros sinal de risco alto.

O nó **IF** decide em OR: se qualquer condição factual for verdadeira, o domínio avança. Caso contrário, é descartado silenciosamente.

```
IF: VT malicioso > 0  OR  VT suspeito > 0  OR  score > 69
```

A diferença essencial da camada 2: o sinal de confirmação não é a string é um fato externo verificável. Isso elimina domínios legítimos que passaram na camada 1 por semelhança de nome.

### 4. Análise por IA

Só o que passou nas duas camadas chega ao Gemini. O prompt inclui todos os dados coletados e retorna JSON estruturado:

```json
{
  "veredito": "CRITICO",
  "marca_alvo": "Méliuz",
  "tecnica": "combosquatting",
  "confianca": "ALTA",
  "modus_operandi": "O atacante associa o nome da marca a um termo de ação crítica para induzir o usuário a inserir credenciais em uma página fraudulenta.",
  "indicadores_chave": [
    "Combosquatting com a marca Méliuz no SLD",
    "TLD de baixa reputação (.xyz)",
    "Presença da palavra crítica login no domínio"
  ],
  "acao_recomendada": "Bloqueio imediato nos firewalls/DNS e submissão do domínio para takedown junto ao registrador.",
  "justificativa": "A estrutura clássica de impersonação e o score heurístico elevado indicam ataque zero-day."
}
```

**Por que JSON:** a saída estruturada é auditável, reaproveitável e pode alimentar dashboards e estatísticas — não apenas o alerta imediato. Separa análise (responsabilidade do LLM) de apresentação (responsabilidade do nó seguinte).

### 5. Entrega

Um nó Code formata o JSON e o bot publica no canal público do Telegram com veredito, modus operandi, indicadores-chave e ação recomendada.

---

## Stack

| Componente | Tecnologia | Função |
|---|---|---|
| Coleta | CertStream Go (Docker) | Consome logs CT em tempo real |
| Triagem | Python 3.12, rapidfuzz | Detecção e filtragem heurística |
| Orquestração | n8n (self-hosted, Docker) | Pipeline de confirmação e análise |
| Threat Intel | VirusTotal API | Reputação de domínios |
| Registro | RDAP (rdap.org) | Idade e registro de domínios |
| Análise | Google Gemini | Laudo estruturado em JSON |
| Entrega | Telegram Bot + Canal | Alertas em tempo real |
| Serviço | systemd | Script Python como serviço permanente |

---

## Técnicas aplicadas

- Certificate Transparency monitoring
- Typosquatting, combosquatting e homoglyph (IDN) attack detection
- Distância de Levenshtein com tolerância proporcional ao tamanho da marca
- Normalização de homóglifos: leet speak, Unicode, caracteres cirílicos
- Extração de domínio registrável (eTLD+1) e allowlisting
- Costimulação em duas camadas (textual + factual)
- Enriquecimento com threat intelligence (VirusTotal, RDAP)
- Engenharia de prompt com saída estruturada (JSON)
- Orquestração low-code com integração de LLM

---

## Resultados observados

Comparação do filtro antes/depois da arquitetura de costimulação, sobre tráfego real do CertStream:

| Domínio | Marca | Decisão | Motivo |
|---|---|---|---|
| `meliuz-login.xyz` | Méliuz | ✅ ALERTA | combosquatting + TLD suspeito + keyword |
| `paybank.de` | PagBank | ❌ descartado | typo sem 2º sinal (semelhança de nome apenas) |
| `food-spotting.de` | iFood | ❌ descartado | typo sem 2º sinal |
| `américanhg.com` | Americanas | ❌ descartado | typo sem 2º sinal |
| `amazonaws.com` | Amazon | ❌ allowlist | infraestrutura oficial |
| `bradesco.blip.ai` | Bradesco | ❌ descartado | marca em subdomínio de terceiro sem 2º sinal |
| `meliuz-seguro.online` | Méliuz | ✅ ALERTA | marca no SLD + keyword + TLD suspeito |

---

**Alerta real detectado  `game-amazon.best` (14 detecções no VirusTotal):**
![Alerta Telegram](https://raw.githubusercontent.com/mateusdias96cs/aegis-antiphishing-pipeline/main/assets/2.jpeg)


## Execução

**Pré-requisitos:** Docker, Python 3.12, n8n self-hosted.

```bash
# 1. Subir o servidor CertStream
docker run -d --name certstream --restart unless-stopped \
  -p 8888:8080 0rickyy0/certstream-server-go

# 2. Instalar dependências Python
pip install rapidfuzz requests websocket-client --break-system-packages

# 3. Rodar como serviço permanente (systemd)
sudo systemctl enable phishing-monitor
sudo systemctl start phishing-monitor

# 4. Ver logs em tempo real
tail -f ~/phishing.log
```

**Variáveis de configuração** (topo do script `phishing_monitor.py`):

```python
N8N_WEBHOOK = "http://localhost:5678/webhook/phishing"  # endpoint n8n
CERTSTREAM_URL = "ws://localhost:8888/"                 # servidor CT local
DEBUG = True                                            # logs detalhados
SEND_THRESHOLD = 50                                     # score mínimo para candidato
```

---

## Próximos passos

- Tratar 404 do RDAP como sinal de risco explícito no nó IF (domínio recém-criado)
- Persistir alertas em banco de dados para estatísticas e dashboard
- Adicionar retry automático no nó Gemini para rate limits transitórios
- Métricas de precisão e recall com dataset rotulado
- Expandir lista de marcas e keywords com base na telemetria acumulada
- Exportar alertas no formato STIX/TAXII para integração com plataformas CTI

---

## Autor

**Mateus Camara Dias**
Estudante de Tecnólogo em Cibersegurança  SENAC Santa Catarina
Especialização Blue Team  Hackers do Bem (SENAI, Programa Federal)

[![LinkedIn](https://img.shields.io/badge/LinkedIn-mateusdiascs-blue)](https://linkedin.com/in/mateusdiascs)
[![GitHub](https://img.shields.io/badge/GitHub-mateusdias96cs-black)](https://github.com/mateusdias96cs)
[![AEGIS CTI](https://img.shields.io/badge/AEGIS_CTI-aegiscti.me-green)](https://aegiscti.me)
