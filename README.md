# Tundra

DPI-resistant proxy with TLS camouflage, flow morphing, and post-quantum key exchange.

## Architecture

```
┌──────────┐    SOCKS5    ┌──────────────┐    TLS+KEM    ┌──────────────┐    TCP    ┌──────────┐
│  Client   │◄───────────►│ Tundra Proxy │◄─────────────►│ Tundra Server│◄────────►│ Internet │
│ (GUI/CLI) │  localhost   │   (Client)   │  encrypted    │   (Server)   │  upstream │          │
└──────────┘              └──────────────┘              └──────────────┘          └──────────┘
```

**Core features:**
- **Post-quantum KEM** — ML-KEM-768 (Kyber768) key exchange during auth
- **Encrypted tunnel** — ChaCha20-Poly1305 AEAD with BLAKE3 key derivation
- **Flow morphing** — padding and inter-arrival time manipulation to resist DPI fingerprinting
- **Multiplexing** — many SOCKS5 connections over a single TLS session
- **Session churn** — periodic session rotation to avoid long-lived connection detection
- **TLS camouflage** — self-signed certificate mimicking a real website, with fallback for non-Tundra traffic

## Crates

| Crate | Description |
|-------|-------------|
| `tundra-core` | Crypto (ChaCha20-Poly1305, BLAKE3), framing, Kyber768 KEM |
| `tundra-fme` | Flow Morphing Engine — packet padding and IAT scheduling |
| `tundra-server` | TLS terminator, PSK auth, upstream proxy, ACL, fallback |
| `tundra-client` | CLI SOCKS5 frontend with session pool and FME |
| `tundra-gui` (src-tauri) | Tauri 2.x desktop GUI — dark theme, profiles, live stats |

## Quick Start

### Server (VPS)

One-click install from GitHub:

```bash
curl -sL https://raw.githubusercontent.com/Maximus002/tundra/main/install-server.sh | sudo bash
```

Or manually:

```bash
git clone https://github.com/Maximus002/tundra.git /opt/tundra
cd /opt/tundra
cargo build --release --bin tundra-server
```

Create config `/etc/tundra/tundra-server.toml`:

```toml
listen = "0.0.0.0:8443"
psk = "0000000000000000000000000000000000000000000000000000000000000000"
target_domain = "www.microsoft.com"
max_connections = 100
max_per_ip = 10
```

Run:

```bash
/opt/tundra/target/release/tundra-server --config /etc/tundra/tundra-server.toml
```

### Docker

```bash
echo 'psk = "YOUR_64_HEX_PSK"' > tundra-server.toml
docker compose up -d
```

### Client (GUI)

Download `Tundra.app` from [Releases](../../releases) (macOS, Apple Silicon).

Or build from source:

```bash
cargo tauri build
# Output: target/release/bundle/macos/Tundra.app
```

Enter server address, port, and PSK. Click **Connect**. Traffic routes through SOCKS5 on `127.0.0.1:1080`.

System proxy: **Settings → Network → Wi-Fi → Details → Proxies → SOCKS** → `127.0.0.1:1080`

### Client (CLI)

```bash
cargo build --release --bin tundra-client

tundra-client \
  --server-addr 1.2.3.4 \
  --server-port 8443 \
  --socks-port 1080 \
  --psk YOUR_64_HEX_PSK \
  --fme true
```

Test:

```bash
curl -x socks5h://127.0.0.1:1080 https://httpbin.org/ip
```

## Configuration

### Server

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `listen` | string | `0.0.0.0:8443` | Listen address and port |
| `psk` | string | required | 64 hex character pre-shared key |
| `target_domain` | string | required | Domain for TLS certificate (camouflage) |
| `max_connections` | number | 100 | Global connection limit |
| `max_per_ip` | number | 10 | Per-IP connection limit |

### Client (CLI)

| Flag | Default | Description |
|------|---------|-------------|
| `--server-addr` | required | Server IP address |
| `--server-port` | 8443 | Server port |
| `--socks-port` | 1080 | Local SOCKS5 port |
| `--psk` | env `TUNDRA_PSK` | Pre-shared key |
| `--fme` | true | Enable Flow Morphing Engine |
| `--max-session-age-secs` | 600 | Session rotation interval |
| `--max-session-bytes-mb` | 200 | Session rotation by volume |

## Protocol

```
Client                                    Server
  │                                          │
  │──── TCP connect ────────────────────────►│
  │──── TLS handshake ──────────────────────►│
  │                                          │
  │  [magic][Auth: ts+HMAC+KEM_pubkey]      │
  │─────────────────────────────────────────►│
  │  [AuthAck: KEM_ciphertext]               │
  │◄─────────────────────────────────────────│
  │                                          │
  │  shared_secret = KEM_decapsulate(ct)     │
  │  enc_key = BLAKE3(shared_secret, role)   │
  │                                          │
  │  [len:2][encrypted(mux_frame)]           │
  │◄────────────────────────────────────────►│
  │         Multiplexed Data/Close/Ping      │
  └──────────────────────────────────────────┘
```

Wire format per frame (after TLS):
```
[length:2 BE][encrypted([magic:4][cmd:1][stream_id:4][payload_len:2][payload:N])]
```

## Security Notes

- PSK authentication with timestamp-based HMAC (rejects replay within 300s window)
- Kyber768 post-quantum key exchange — shared secret is ephemeral per connection
- Server blocks connections to private IPs (127.x, 10.x, 172.16-31.x, 192.168.x.x, ::1, IPv4-mapped)
- Non-Tundra traffic gets reverse-proxied to `target_domain` (camouflage)
- No logging of traffic content; only connection metadata

## Requirements

**Server:** Linux (x86_64/aarch64), Rust 1.77+, OpenSSL dev headers

**Client GUI:** macOS (Apple Silicon), Tauri 2.x runtime

**Client CLI:** macOS / Linux / Windows, Rust 1.77+

## License

MIT
