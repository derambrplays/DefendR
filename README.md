# 🛡 DefendR

**DefendR** é um antivírus desktop completo para Linux com interface PyQt5, feito para Kali Linux e outras distribuições. Ele combina proteção em tempo real, firewall, scanner de arquivos, monitor de rede, detector de rootkit, anti-ransomware, e dezenas de outras ferramentas de segurança — tudo em uma interface roxa escura inspirada no Avast.

> **🌐 7 idiomas:** Português · English · Español · Français · Deutsch · Italiano · Русский

---

## 📦 Funcionalidades

### 🔍 Scanner de Arquivos
- Detecção por **assinatura** (PE, ELF, ZIP, GZip, PNG)
- **Heurística** inteligente (strings suspeitas: `CreateRemoteThread`, `VirtualAllocEx`, `base64`, `Invoke-`, etc.)
- **Whitelist** automática com **87+ ferramentas pentest** (Metasploit, nmap, Burp, SQLmap, Hydra, John, Aircrack, Bettercap, Impacket, Responder, etc.)
- Scan de arquivo individual, pasta inteira ou dispositivos USB
- Resultados coloridos: 🟢 Safe · 🟡 Suspicious · 🔴 Malicious · 🔵 Pentest

### 🛡 Proteção em Tempo Real
- Monitora `~/Downloads`, `~/Desktop`, `/tmp` com **watchdog**
- Detecta criação/modificação de arquivos automaticamente
- Notificação instantânea na bandeja do sistema

### 🔒 Firewall (iptables)
- Ativar/desativar firewall
- Bloquear/liberar portas específicas
- Listar regras ativas
- Flush (limpar todas as regras)

### 🌐 Monitor de Rede
- **Detecção de ARP Spoofing** — alerta se um IP muda de MAC (com verificação dupla pra evitar falso positivo)
- **DNS Hijack Detection** — monitora servidores DNS, alerta se não forem padrão
- **Port Scan Listener** — detecta portas suspeitas abertas (4444, 5555, 6666, 1337, 31337, etc.)
- **C2 Connection Monitor** — alerta conexões remotas para portas de comando & controle
- **ARP Table** — visualização completa da tabela ARP

### ⚙ Gerenciador de Processos
- Tabela com PID, Nome, CPU%, MEM%, Conexões, Status
- Classificação automática (suspicious, network, pentest)
- Atualização em tempo real

### 🌐 Web Blocker
- Bloqueia domínios via `/etc/hosts`
- Lista de domínios bloqueados com refresh

### 🎣 Anti-Phishing
- Analisa URLs por score
- Checa: domínios conhecidos, keywords suspeitas (`login`, `secure`, `bank`, `verify`), subdomínios, comprimento
- Classificação: Safe / Suspicious / Dangerous

### 📦 Quarentena
- Isola arquivos suspeitos com metadados (data, hash, motivo)
- Restaurar arquivo ao local original
- Excluir permanentemente
- Interface com lista e refresh

### 📥 Sandbox
- Executa arquivos em ambiente isolado
- Suporte a **firejail** ou **bubblewrap** (`--net=none`)
- Detecta automaticamente qual está disponível

### 🔐 Anti-Ransomware
- Monitora diretórios do usuário em tempo real
- Detecta extensões de ransomware conhecidas (`.encrypted`, `.locked`, `.wncry`, `.onion`, `.cerber`, etc.)
- Alerta ao encontrar arquivos criptografados em massa

### 🕵️ Rootkit Detector
- Varre por **processos ocultos** (comparação `/proc` vs `ps`)
- Detecta **módulos de kernel suspeitos** (hideproc, suterusu, adore, knark)
- Verifica **LD_PRELOAD** e **LD_LIBRARY_PATH** anormais
- Detecta **modo promíscuo** na rede (sniffing)
- Lista **binários SUID** suspeitos

### 💾 USB Scanner
- Monitora `/media` e `/run/media`
- Auto-scan ao montar dispositivo
- Alerta se encontrar ameaças

### 📡 VPN Manager
- Gerencia configurações OpenVPN
- Adicionar/Conectar/Desconectar
- Status de conexão

### 🔑 Password Manager
- Cofre criptografado (XOR + base64)
- Proteção por **master password**
- Adicionar/Listar/Travar/Destravar entradas
- Armazena site, usuário e senha

### 📅 Scheduler
- Agendamento de scans por intervalo (horas)
- Persistente em JSON
- Execução automática em background

### 🔄 Signature Updater
- Baixa assinaturas atualizadas do GitHub
- Atualiza whitelist e MALICIOUS_SIGS
- Status de atualização na interface

### 🎮 Game Mode
- Detecta processos fullscreen (Steam, CS2, Valorant, etc.)
- Suprime notificações durante o jogo
- Alterna automaticamente

## 🧰 Ferramentas Avançadas

### 📡 WiFi Inspector
- **Scan de roteador** — usa nmap para escanear portas abertas no gateway
- **Verificação de credenciais padrão** — testa admin/admin, root/root, etc.
- **Monitor contínuo de dispositivos** — detecta novos dispositivos na rede
- **Análise de segurança** — portas de risco (FTP 21, Telnet 23, SMB 445, UPnP 1900)
- **IP público** — mostra seu IP externo

### 🗑 Data Shredder
- **6 padrões de destruição segura:**
  | Padrão | Passes |
  |--------|--------|
  | DoD 5220.22-M (3 passes) | `0x00` → `0xFF` → `0x00` |
  | DoD 5220.22-M ECE (7 passes) | 7 passes alternados |
  | Schneier (7 passes) | dados aleatórios + fixos |
  | Gutmann (35 passes) | 35 passes aleatórios |
  | Nuke (1 pass zeros) | rápida, apenas zeros |
  | Nuke (1 pass random) | rápida, dados aleatórios |
- **Wipe de espaço livre** em partições inteiras
- Barra de progresso com status em tempo real
- Modo cancelável

### 📦 Software Updater
- Verifica atualizações do **sistema** (`apt list --upgradable`)
- Verifica **pacotes Python** (`pip3 list --outdated`)
- Verifica **Flatpak** e **Snap**
- **Instalação em lote** com um clique
- Destaque para atualizações de segurança

### 📷 Webcam Protection
- Monitora `/dev/video*` com `lsof`
- **Whitelist** de apps confiáveis (Zoom, Teams, Chrome, Firefox, OBS, Discord)
- **Bloqueio físico** via `modprobe -r uvcvideo` ou `chmod 000`
- Alerta em tempo real para acesso não autorizado

### 🌐 DNS-over-HTTPS / DNS-over-TLS
- **4 provedores:** Cloudflare, Quad9, Google, Mullvad
- Testa ping antes de aplicar
- Usa `resolvectl` com DNS-over-TLS se disponível
- Fallback para `/etc/resolv.conf`
- **Suporte a DNSSEC**

### 🧹 System Cleanup
- **14 categorias de limpeza:**
  - APT cache · Kernels antigos · Logs do sistema
  - `~/.cache` · Cache de browsers · npm cache
  - Docker (containers/images parados) · Flatpak (não usados)
  - Pip cache · Thumbnails · Lixeira
  - `/tmp` · Broken symlinks · Diretórios vazios
- **Preview** antes de limpar (mostra tamanho)
- Cálculo de espaço recuperado

### 🔍 Network Inspector
- **ARP Scan** — descobre dispositivos na rede local
- **Router Info** — gateway, IP local, conexões ativas
- Detalhes de cada host (IP, MAC, fabricante)

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
2. **Dependências** — verifica PyQt5, psutil e ferramentas opcionais
3. **Permissões root** — opção de criar atalho com `pkexec`
4. **Instalação** — copia ícones, cria atalhos no menu e na Área de Trabalho
5. **Concluir** — opção de iniciar o DefendR agora

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

Ou use o atalho **DefendR (Root)** criado pelo instalador.

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
├── defendr.py          # Aplicação principal (~3500 linhas)
├── install.py          # Instalador com wizard
├── README.md
└── .gitignore

~/.defendr/             # Configuração e dados
├── installed           # Marca de instalação (com idioma)
├── config.json         # Whitelist e configurações
├── quarantine.json     # Metadados da quarentena
└── scheduler.json      # Scans agendados

~/.local/share/icons/hicolor/*/apps/defendr.png   # Ícones
~/.local/share/applications/defendr.desktop        # Atalho menu
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
