# 🛡 DefendR

**DefendR** é um antivírus desktop completo para Linux com interface PyQt5, compatível com **qualquer distribuição Linux**. Combina proteção em tempo real, firewall, scanner de arquivos com 3 níveis, monitor de rede, detector de rootkit, anti-ransomware, scanner de HD (com execução root), modo empresarial, sistema de contas com telemetria, e dezenas de outras ferramentas de segurança — com interface estilo iOS.

> **🌐 7 idiomas:** Português · English · Español · Français · Deutsch · Italiano · Русский

---

## 📦 Funcionalidades

### 🔥 Modo Empresarial
- Alterna entre **Individual** e **Empresarial** nas Configurações
- Ativa **TODAS** as proteções simultaneamente
- Firewall em modo estrito (DROP padrão)
- Bloqueio físico de webcam (`modprobe -r uvcvideo`)
- Rootkit scan automático a cada 10 minutos
- Monitoramento 2x mais rápido
- Badge "🔥 EMPRESARIAL" na sidebar

### 🔍 Scanner de Arquivos (3 níveis)
- **Light (leve)** — nome do arquivo + primeiros 2MB do conteúdo
- **Medium (médio)** — arquivo inteiro + padrões + strings suspeitas
- **Heavy (pesado)** — arquivo inteiro + IA (JoguinIA com 12 features) + entropia + heurística + hash
- Detecção por **assinatura** (PE, ELF, ZIP, GZip, PNG)
- **Whitelist** automática com **90+ ferramentas pentest**
- Scan de arquivo, pasta, USB, agendado

### 💿 HD Scanner
- Escaneia **todas as unidades físicas** do sistema
- Executa como **root via pkexec** para acesso total
- Progresso com **porcentagem em tempo real** (pré-contagem + streaming)
- Botão de **parar** a qualquer momento
- Resultados por drive + recomendações inteligentes (espaço, integridade)

### 🛡 Proteção em Tempo Real
- Monitora diretórios com watchdog (`/tmp`, Downloads, Desktop)
- Detecta criação/modificação de arquivos automaticamente
- Notificação na bandeja do sistema

### 🔒 Firewall (iptables)
- Ativar/desativar firewall
- Bloquear/liberar portas TCP/UDP
- Listar regras ativas
- Detecção de **port scan** e **força bruta** (journalctl)
- Flush (limpar todas as regras)

### 🌐 Monitor de Rede (Nível Enterprise)
- **Detecção de ARP Spoofing** — MAC address changes + novos dispositivos na rede
- **DNS Hijack Detection** — nameservers não autorizados
- **Port Scan Detection** — detecta scan de QUALQUER IP (inclusive localhost/ADB)
- **Brute Force Detection** — força bruta em portas sensíveis (SSH, RDP, MySQL, etc.)
- **Inbound Connections** — conexões entrantes em portas sensíveis de qualquer IP externo
- **ADB Tunnel Detection** — túnel reverso ADB (Android acessando o PC)
- **Monitoramento/Spyware Detection** — keyloggers, sniffers, debuggers, ferramentas forenses rodando no sistema
- **Novo dispositivo na rede** — alerta imediato via ARP
- **Interfaces em modo promíscuo** — detecta sniffers de rede
- **Módulos kernel suspeitos** — kprobe, systemtap, ftrace
- ARP Table, DNS Servers, Conexões ativas

### 👤 Sistema de Contas (Telemetria)
- Login/registro com servidor remoto
- Envio de relatórios de erro (Bug, Feature Request, Falso Positivo, Crash)
- Scan results via API
- Heartbeat e informações do PC

### ⚙ Gerenciador de Processos
- Tabela com PID, Nome, CPU%, MEM%, Conexões, Status
- Classificação automática (suspicious, network, pentest)
- Atualização em tempo real

### 🌐 Web Blocker
- Bloqueia domínios via `/etc/hosts`
- Lista com refresh

### 🎣 Anti-Phishing
- Analisa URLs por score (domínio, keywords, subdomínios)
- Classificação: Safe / Suspicious / Dangerous

### 📦 Quarentena
- Isola arquivos suspeitos com metadados (hash, data, caminho)
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
- Cofre criptografado com master password (PBKDF2)

### 📅 Scheduler
- Scans agendados por intervalo (1-168h)
- Persistente em JSON

### 🔄 Signature Updater
- Assinaturas do GitHub + ClamAV (daily.cvd + main.cvd)
- Atualizações automáticas a cada 30 dias

### 🎮 Game Mode
- Detecta fullscreen, suprime notificações

## 🧰 Ferramentas Avançadas

### 📡 WiFi Inspector
- Scan de roteador (nmap, 16 portas)
- Credenciais padrão (7 pares comuns)
- Monitor contínuo de dispositivos
- Análise de segurança (FTP 21, Telnet 23, SMB 445, UPnP 1900)

### 🗑 Data Shredder
- 6 padrões: DoD 5220.22-M (3-pass), DoD 7-pass, Schneier, Gutmann (35-pass), Nuke zeros, Nuke random
- Wipe de espaço livre
- Barra de progresso

### 📦 Software Updater
- apt, dnf, pacman, zypper, pip3, Flatpak, Snap
- Instalação em lote

### 📷 Webcam Protection
- Monitora `/dev/video*` com lsof
- Whitelist de apps confiáveis (Zoom, Chrome, Teams, etc.)
- Bloqueio físico via modprobe (`chmod 000` ou `modprobe -r uvcvideo`)

### 🌐 DNS-over-HTTPS / DNS-over-TLS
- Cloudflare, Quad9, Google, Mullvad
- Suporte a DNSSEC

### 🧹 System Cleanup
- 14 categorias: APT cache, kernels antigos, logs, cache, Docker, Flatpak, pip, thumbnails, lixeira, /tmp, broken symlinks
- Preview antes de limpar

### 🔍 Network Inspector
- ARP Scan (scapy), Router Info (gateway, nmcli)

---

## 🚀 Instalação

### Via Instalador (recomendado — funciona em qualquer distro)

```bash
git clone https://github.com/derambrplays/DefendR.git
cd DefendR
python3 install.py
```

O instalador detecta automaticamente:
- **Gerenciador de pacotes** da sua distro (apt, dnf, pacman, zypper, yum, apk, xbps)
- **Nome correto do pacote PyQt5** (python3-pyqt5, python-qt5, pyqt-5, etc.)
- **Diretório da Área de Trabalho** via `~/.config/user-dirs.dirs` (qualquer idioma)

E guia você por:
1. **Idioma** — escolha entre 7 idiomas
2. **Dependências** — verifica PyQt5, psutil e opcionais
3. **Permissões root** — instala política polkit + atalho com pkexec
4. **Instalação** — ícones (SVG + PNG), atalhos no menu e Área de Trabalho
5. **Concluir** — opção de iniciar o DefendR

### Debian / Ubuntu / Kali

```bash
sudo apt install python3-pyqt5 python3-psutil
# Opcionais:
sudo apt install firejail nmap openvpn lsof
git clone https://github.com/derambrplays/DefendR.git
cd DefendR
python3 defendr.py
```

### Fedora / RHEL

```bash
sudo dnf install python3-qt5 python3-psutil
# Opcionais:
sudo dnf install firejail nmap openvpn lsof
```

### Arch Linux

```bash
sudo pacman -S python-pyqt5 python-psutil
# Opcionais:
sudo pacman -S firejail nmap openvpn lsof
```

### openSUSE

```bash
sudo zypper install python3-qt5 python3-psutil
```

### Alpine Linux

```bash
sudo apk add py3-pyqt5 py3-psutil
```

---

## ⚙ Requisitos

| Pacote | Obrigatório | Função |
|--------|-------------|--------|
| Python 3.8+ | ✅ | Runtime |
| PyQt5 | ✅ | Interface gráfica |
| psutil | ✅ | Monitoramento do sistema |
| pkexec (polkit) | ❌ Opcional | Execução root (HD scan + firewall) |
| firejail / bwrap | ❌ Opcional | Sandbox |
| nmap | ❌ Opcional | WiFi Inspector |
| openvpn | ❌ Opcional | VPN Manager |
| lsof | ❌ Opcional | Webcam Protection |
| watchdog | ❌ Opcional | Real-time file monitor (pip3 install watchdog) |

---

## 📁 Estrutura

```
~/DefendR/
├── defendr.py              # Entry point
├── install.py              # Instalador cross-distro
├── start.sh                # Wrapper com pkexec para execução root
├── README.md
├── defendr/
│   ├── __init__.py         # App bootstrap (splash, lock de porta)
│   ├── ui.py               # Interface PyQt5 (~2400 linhas)
│   ├── constants.py        # Cores, assinaturas, whitelist, padrões
│   ├── lang.py             # Sistema de tradução (7 idiomas)
│   ├── engine.py           # Motor de scan (3 níveis, streaming)
│   ├── monitors.py         # RT, ransomware, webcam, USB, game mode, network
│   ├── security.py         # Firewall, web blocker, anti-phishing, sandbox, rootkit
│   ├── tools.py            # Shredder, updater, cleanup, password manager, VPN
│   ├── network_tools.py    # Network inspector, WiFi, DNS-over-HTTPS
│   ├── quarantine.py       # Gerenciador de quarentena
│   ├── scheduler.py        # Scans agendados, signature updater
│   ├── scan_root.py        # Helper de scan rodando como root (JSON-out)
│   ├── icon.svg            # Ícone vetorial (escudo com D)
│   ├── telemetry.py        # Cliente HTTP para servidor remoto
│   ├── filelock.py         # Prevenção de múltiplas instâncias
│   └── download_server.py  # Servidor HTTP para distribuição
```

### Arquivos do Sistema (instalados pelo install.py)

```
/usr/local/bin/defendr-sudo.sh     # Script de entrada root (launch + scan)
/usr/share/polkit-1/actions/io.github.defendr  # Política polkit (sem senha)
~/.local/share/icons/hicolor/*/apps/defendr.png  # Ícones PNG (16-256px)
```

---

## 🧪 Testado em

- Kali Linux (XFCE) ✅
- Debian 12 ✅
- Ubuntu 24.04 ✅
- Linux Mint 22 ✅
- Fedora 40 ✅
- Arch Linux ✅
- openSUSE Tumbleweed ✅
- Alpine Linux ✅
- Void Linux ✅

## 🔬 Testado com Ataques Reais

- **Port scan real de outro computador na rede** (WiFi) — detectado em segundos
- **Port scan real de um celular Android** (mesma rede WiFi) — detectado como IP externo
- **Brute force real de um celular Android** — múltiplas conexões em porta sensível detectadas
- **ADB reverse tunnel** — túnel USB do Android para o PC detectado
- **EICAR test file** — detectado pela proteção em tempo real, watchdog e AI
- **Ferramentas forenses** (nmap, hydra, sqlmap, volatility, metasploit) — detectadas rodando no sistema
- **Interfaces em modo promíscuo** — detectadas como sniffer
- **Argumentos de linha de comando suspeitos** — detectados por heurística

O DefendR foi testado contra ataques reais de **dispositivos móveis** e **outros computadores** na mesma rede, simulando cenários reais de invasão. O monitor de rede cobre **qualquer IP** — inclusive localhost (para detectar túneis ADB e conexões locais maliciosas).

## 🕵️ Proteção Contra Monitoramento

O DefendR detecta ativamente **técnicas de investigação digital**:

- **Spyware / Keylogger** — processos lendo /dev/input/*, nomes conhecidos de keyloggers
- **Sniffers de rede** — tcpdump, wireshark, ettercap, bettercap rodando ou interface em modo promíscuo
- **Ferramentas forenses** — volatility, autopsy, sleuthkit, foremost
- **Ferramentas de pentest** — nmap, masscan, hydra, sqlmap, metasploit
- **Debuggers** — gdb, strace, ltrace, bpftrace
- **Módulos kernel de monitoramento** — kprobe, systemtap, ftrace carregados

---

## 📄 Licença

MIT
