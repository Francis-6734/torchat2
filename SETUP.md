# TorChat2 Setup Guide

End-to-end encrypted messenger over Tor. All traffic is routed through onion services — no clearnet, no metadata leaks.

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Rust | 1.75+ | Install via [rustup.rs](https://rustup.rs) |
| Tor | Any recent | Must be running locally |
| C compiler | gcc / clang / MSVC | Required for native dependencies |
| Git | Any | To clone the repository |

> SQLite, SQLCipher, and OpenSSL are all **bundled** — no system packages needed for those.

---

## Linux Setup

### 1. Install system dependencies

**Debian / Ubuntu:**

```bash
sudo apt update
sudo apt install -y build-essential pkg-config tor git curl
```

**Fedora:**

```bash
sudo dnf install -y gcc gcc-c++ pkgconf-pkg-config tor git curl
```

**Arch Linux:**

```bash
sudo pacman -S base-devel tor git curl
```

### 2. Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

Verify:

```bash
rustc --version   # should be 1.75.0 or newer
cargo --version
```

### 3. Configure and start Tor

Edit `/etc/tor/torrc` and ensure these lines are present:

```
SocksPort 9050
ControlPort 9051
```

Start the service:

```bash
sudo systemctl enable tor
sudo systemctl start tor
```

Verify Tor is running:

```bash
ss -tlnp | grep -E '905[01]'
```

You should see both ports 9050 and 9051 listening.

### 4. Clone and build

```bash
git clone https://github.com/nicholasgasior/torchat2.git
cd torchat2
cargo build --release -p torchat-web
```

Build takes a few minutes on first run (compiles ~200 crates).

### 5. Run

```bash
TORCHAT_BIND=127.0.0.1:3000 ./target/release/torchat-web
```

Open your browser to **http://localhost:3000**

---

## Windows Setup

### 1. Install Rust

Download and run the installer from [https://rustup.rs](https://rustup.rs).

When prompted, install the default toolchain. This also installs the required MSVC build tools if you choose the default host triple.

> If you don't have Visual Studio or Build Tools installed, the Rust installer will guide you to install the **Visual Studio C++ Build Tools**.

Verify in a **new** terminal (cmd or PowerShell):

```powershell
rustc --version
cargo --version
```

### 2. Install Git

Download from [https://git-scm.com/download/win](https://git-scm.com/download/win) and install with default settings.

### 3. Install and configure Tor

**Option A: Tor Expert Bundle (recommended)**

1. Download the Tor Expert Bundle from [https://www.torproject.org/download/tor/](https://www.torproject.org/download/tor/)
2. Extract to a folder, e.g. `C:\tor`
3. Create a config file `C:\tor\torrc` with:

```
SocksPort 9050
ControlPort 9051
DataDirectory C:\tor\data
```

4. Run Tor:

```powershell
C:\tor\tor.exe -f C:\tor\torrc
```

**Option B: Tor Browser (alternative)**

If you already have Tor Browser installed, it runs a SOCKS proxy on port **9150** by default (not 9050). You'd need to either:
- Change Tor Browser's config to also open a ControlPort, or
- Use the Expert Bundle instead (recommended)

### 4. Clone and build

Open a terminal (cmd or PowerShell):

```powershell
git clone https://github.com/nicholasgasior/torchat2.git
cd torchat2
cargo build --release -p torchat-web
```

### 5. Run

```powershell
set TORCHAT_BIND=127.0.0.1:3000
.\target\release\torchat-web.exe
```

Or in PowerShell:

```powershell
$env:TORCHAT_BIND = "127.0.0.1:3000"
.\target\release\torchat-web.exe
```

Open your browser to **http://localhost:3000**

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TORCHAT_BIND` | `0.0.0.0:3000` | Web server bind address. Use `127.0.0.1:3000` for local-only access |
| `TORCHAT_DATA_DIR` | `~/.torchat` | Directory for databases and keys |
| `RUST_LOG` | `info` | Log level (`debug`, `info`, `warn`, `error`) |

---

## First Use

1. Open **http://localhost:3000** in your browser
2. Create an identity by setting a password — this generates your onion address and encryption keys
3. Your onion address (e.g. `abc123...xyz.onion`) is your contact ID — share it with people you want to chat with
4. Add contacts by entering their onion address
5. Send messages — everything is end-to-end encrypted and routed through Tor

---

## CLI Usage (Optional)

The CLI provides direct terminal access to TorChat:

```bash
# Build the CLI
cargo build --release -p torchat-cli

# Show your identity
./target/release/torchat identity

# Start the messaging daemon
./target/release/torchat start --socks-port 9050 --control-port 9051

# Add a contact
./target/release/torchat add <onion-address> --name "Alice"

# Send a message
./target/release/torchat send <onion-address> "Hello!"

# View message history
./target/release/torchat history <onion-address>
```

---

## Troubleshooting

### Tor connection refused

```
Error: Connection refused (os error 111)
```

Tor isn't running or the ports are wrong. Check:

```bash
# Linux
sudo systemctl status tor
ss -tlnp | grep 9050

# Windows
netstat -an | findstr 9050
```

### Build fails with C compiler errors

Make sure you have build tools installed:

- **Linux:** `sudo apt install build-essential` (or equivalent)
- **Windows:** Install Visual Studio C++ Build Tools via the Rust installer prompt

### Permission denied on Tor control port

On Linux, your user may need to be in the `debian-tor` group, or you can set a `CookieAuthentication` / `HashedControlPassword` in `torrc`:

```bash
sudo usermod -aG debian-tor $USER
# Log out and back in for group change to take effect
```

### Port 3000 already in use

Change the bind address:

```bash
TORCHAT_BIND=127.0.0.1:3001 ./target/release/torchat-web
```

### Database locked errors

Only one instance of TorChat can use a data directory at a time. Make sure no other instance is running, or use a separate data directory:

```bash
TORCHAT_DATA_DIR=~/.torchat2 ./target/release/torchat-web
```

---

## Security Notes

- All messages use **Double Ratchet** encryption (like Signal)
- Database files are encrypted with **SQLCipher** (AES-256)
- Encryption keys are derived from your password using **PBKDF2** (100,000 iterations)
- All network traffic goes through **Tor onion services** — your IP is never exposed
- Bind to `127.0.0.1` (not `0.0.0.0`) to prevent LAN access to the web UI
