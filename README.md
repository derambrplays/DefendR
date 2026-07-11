# 🛡 DefendR

**DefendR** é um antivírus desktop completo para Linux com interface PyQt5, feito para Kali Linux e outras distribuições. Combina proteção em tempo real, firewall, scanner de arquivos com 3 níveis (Leve/Médio/Pesado), monitor de rede, detector de rootkit, anti-ransomware, scanner de HD, sistema de contas com telemetria, e dezenas de outras ferramentas de segurança — com interface estilo iOS.

> **🌐 7 idiomas:** Português · English · Español · Français · Deutsch · Italiano · Русский

---

## 📦 Funcionalidades

### 🔍 Scanner de Arquivos (3 níveis)
- **Light (quick)** — extensões suspeitas e heurística rápida
- **Medium (balanced)** — signature + heurística + strings ofuscadas
- **Heavy (deep)** — varredura completa com scan de entropia e packers
- Detecção por **assinatura** (PE, ELF, ZIP, GZip, PNG)
- **Whitelist** automática com **87+ ferramentas pentest**
- Scan de arquivo, pasta, USB

### 💿 HD Scanner
- Botão estilo Avast com gradiente radial
- Varredura completa de drives com 4 classificações
- Resultados em árvore + recomendações inteligentes
- Análise de uso de disco via psutil

### 🛡 Proteção em Tempo Real
- Monitora diretórios com watchdog
- Detecta criação/modificação de arquivos automaticamente
- Notificação na bandeja do sistema

### 🔒 Firewall (iptables)
- Ativar/desativar firewall
- Bloquear/liberar portas
- Listar regras ativas
- Flush (limpar todas as regras)

### 🌐 Monitor de Rede
- **Detecção de ARP Spoofing**
- **DNS Hijack Detection**
- **Port Scan Listener**
- **C2 Connection Monitor**
- ARP Table, DNS Servers, Conexões ativas

### 👤 Sistema de Contas (Telemetria)
- Login/registro com servidor remoto
- Envio de relatórios de erro (Bug, Feature Request, Falso Positivo, Crash)
- Scan results via API
- Heartbeat e informações do PC

### ⚙ Gerenciador de Processos
- Tabela com PID, Nome, CPU%, MEM%, Conexões, Status
- Classificação automática (suspicious, network, pentest)
- Atualização em tempo real (timer 5s)

### 🌐 Web Blocker
- Bloqueia domínios via `/etc/hosts`
- Lista com refresh

### 🎣 Anti-Phishing
- Analisa URLs por score
- Checa domínios conhecidos, keywords suspeitas
- Classificação: Safe / Suspicious / Dangerous

### 📦 Quarentena
- Isola arquivos suspeitos com metadados
- Restaurar ou excluir permanentemente

### 📥 Sandbox
- firejail ou bubblewrap
- Detecção automática

### 🔐 Anti-Ransomware
- Monitora diretórios do usuário
- Detecta extensões de ransomware conhecidas

### 🕵️ Rootkit Detector
- Processos ocultos, módulos de kernel suspeitos
- LD_PRELOAD anormal, modo promíscuo, SUID

### 💾 USB Scanner
- Auto-scan ao montar dispositivo

### 📡 VPN Manager
- Gerencia configurações OpenVPN

### 🔑 Password Manager
- Cofre criptografado com master password

### 📅 Scheduler
- Scans agendados por intervalo persistente em JSON

### 🔄 Signature Updater
- Assinaturas atualizadas do GitHub

### 🎮 Game Mode
- Detecta fullscreen, suprime notificações

## 🧰 Ferramentas Avançadas

### 📡 WiFi Inspector
- Scan de roteador (nmap)
- Credenciais padrão
- Monitor contínuo de dispositivos
- Análise de segurança (FTP 21, Telnet 23, SMB 445, UPnP 1900)

### 🗑 Data Shredder
- 6 padrões: DoD 5220.22-M, Schneier, Gutmann, Nuke
- Wipe de espaço livre
- Barra de progresso

### 📦 Software Updater
- apt, pip3, Flatpak, Snap
- Instalação em lote

### 📷 Webcam Protection
- Monitora `/dev/video*` com lsof
- Whitelist de apps confiáveis
- Bloqueio físico via modprobe

### 🌐 DNS-over-HTTPS / DNS-over-TLS
- Cloudflare, Quad9, Google, Mullvad
- Suporte a DNSSEC

### 🧹 System Cleanup
- 14 categorias: APT cache, kernels antigos, logs, cache, Docker, Flatpak, pip, thumbnails, lixeira, /tmp, broken symlinks
- Preview antes de limpar

### 🔍 Network Inspector
- ARP Scan, Router Info

---

## 🚀 Instalação

### Via Instalador (recomendado)

```bash
git clone https://github.com/derambrplays/DefendR.git
cd DefendR
python3 install.py
```

O instalador guia você por:
1. **Idioma** — escolha entre 7 idiomas
2. **Dependências** — verifica PyQt5, psutil e opcionais
3. **Permissões root** — atalho com pkexec
4. **Instalação** — ícones, atalhos no menu e Área de Trabalho
5. **Concluir** — opção de iniciar o DefendR

### Manual

```bash
sudo apt install python3-pyqt5 python3-psutil
# Opcionais:
sudo apt install firejail nmap openvpn lsof

git clone https://github.com/derambrplays/DefendR.git
cd DefendR
python3 defendr.py
```

### Com privilégios root

```bash
python3 defendr.py --sudo
```

---

## ⚙ Requisitos

| Pacote | Obrigatório | Função |
|--------|-------------|--------|
| Python 3 | ✅ | Runtime |
| PyQt5 | ✅ | Interface gráfica |
| psutil | ✅ | Monitoramento do sistema |
| firejail | ❌ Opcional | Sandbox |
| nmap | ❌ Opcional | WiFi Inspector |
| openvpn | ❌ Opcional | VPN Manager |
| lsof | ❌ Opcional | Webcam Protection |

---

## 📁 Estrutura

```
~/DefendR/
├── defendr.py              # Entry point
├── install.py              # Instalador com wizard e splash image
├── README.md
├── defendr/
│   ├── __init__.py         # App bootstrap (splash 7s, lock)
│   ├── ui.py               # Interface PyQt5 (~2000 linhas)
│   ├── constants.py        # Cores, assinaturas, whitelist
│   ├── lang.py             # Sistema de tradução (7 idiomas)
│   ├── engine.py           # Motor de scan (3 níveis)
│   ├── telemetry.py        # Cliente HTTP para servidor remoto
│   ├── splash.png          # Imagem de splash personalizada
│   ├── monitors.py         # RT, ransomware, webcam, USB, game mode
│   ├── security.py         # Firewall, web blocker, anti-phishing, sandbox, rootkit
│   ├── tools.py            # Shredder, updater, cleanup, password manager, VPN
│   ├── network_tools.py    # Network inspector, WiFi, DNS-over-HTTPS
│   ├── quarantine.py       # Gerenciador de quarentena
│   ├── scheduler.py        # Scans agendados, signature updater
│   └── filelock.py         # Prevenção de múltiplas instâncias
```

---

## 🧪 Testado em

- Kali Linux (XFCE) ✅
- Debian 12 ✅
- Ubuntu 24.04 ✅
- Linux Mint 22 ✅

---

## 📄 Licença

MIT
