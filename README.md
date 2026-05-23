# Tundra

DPI-resistant proxy with TLS camouflage, flow morphing engine, and post-quantum hybrid key exchange.

## Architecture

```
┌──────────┐    SOCKS5    ┌──────────────┐    TLS+KEM    ┌──────────────┐    TCP    ┌──────────┐
│  Client   │◄───────────►│ Tundra Proxy │◄─────────────►│ Tundra Server│◄────────►│ Internet │
│ (GUI/CLI) │  localhost   │   (Client)   │  encrypted    │   (Server)   │  upstream │          │
└──────────┘              └──────────────┘              └──────────────┘          └──────────┘
```

## Features

- **Post-quantum hybrid KEM** — Kyber768 + X25519 key encapsulation; both must succeed, secrets are combined
- **Authenticated encryption** — ChaCha20-Poly1305 AEAD with BLAKE3 key derivation; nonce includes role suffix (client/server) to prevent cross-role nonce reuse
- **Bidirectional key confirmation** — both sides verify each other's key confirm hash with constant-time comparison
- **Flow Morphing Engine (FME)** — GMM-based packet size sampling, Markov chain IAT generation, 6 chaff content types, 5 traffic profiles, adversarial jitter/noise
- **Connection multiplexing** — many SOCKS5 connections over a single encrypted TLS session
- **Session churn** — periodic rotation by time (default 600s) or volume (default 200MB)
- **TLS camouflage** — self-signed certificate for a configurable domain, with reverse-proxy fallback for non-Tundra traffic
- **Probing resistance** — handshake frames padded to 1400 bytes; random padding on data frames
- **ACL** — server blocks connections to private IPs (127.x, 10.x, 172.16-31.x, 192.168.x, ::1, IPv4-mapped)

## Crates

| Crate | Description |
|-------|-------------|
| `tundra-core` | Crypto (ChaCha20-Poly1305, BLAKE3, constant-time ops), framing, hybrid Kyber768+X25519 KEM |
| `tundra-fme` | Flow Morphing Engine — GMM sizes, Markov chain IAT, chaff generation, 5 traffic profiles, adversarial noise |
| `tundra-server` | TLS terminator, PSK auth, Challenge/KeyConfirm handshake, upstream proxy, ACL, fallback |
| `tundra-client` | CLI SOCKS5 frontend with session pool and FME |
| `src-tauri/` | Tauri 2.x desktop GUI — dark theme, live stats, system proxy toggle |

## Quick Start

### Server (VPS)

One-click install:

```bash
curl -sL https://raw.githubusercontent.com/Maximus002/tundra/main/install-server.sh | sudo bash
```

Or build manually:

```bash
git clone https://github.com/Maximus002/tundra.git /opt/tundra
cd /opt/tundra
cargo build --release --bin tundra-server
```

Create `/etc/tundra/tundra-server.toml`:

```toml
listen = "0.0.0.0:8443"
psk = "CHANGE_ME_64_HEX_CHARS_32_BYTES"
target_domain = "www.microsoft.com"
max_connections = 100
max_per_ip = 10
fme_profile = "browser"
```

Run with systemd (recommended) or directly:

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
  --fme true \
  --fme-profile browser
```

Test:

```bash
curl -x socks5h://127.0.0.1:1080 https://ifconfig.me
```

## Configuration

### Server (`tundra-server.toml`)

| Field | Default | Description |
|-------|---------|-------------|
| `listen` | `0.0.0.0:8443` | Listen address:port (parsed as `addr` + `port` if separate) |
| `psk` | required | 64 hex chars (32 bytes) pre-shared key |
| `target_domain` | `www.microsoft.com` | Domain for self-signed TLS cert (camouflage) |
| `max_connections` | 1000 | Global connection limit |
| `max_per_ip` | 10 | Per-IP connection limit |
| `handshake_timeout_secs` | 10 | TLS handshake timeout |
| `fme_profile` | `browser` | FME traffic profile: `browser`, `video`, `chat`, `streaming`, `paranoid` |

### Client (CLI)

| Flag | Default | Description |
|------|---------|-------------|
| `--server-addr` | required | Server IP address |
| `--server-port` | 8443 | Server port |
| `--socks-port` | 1080 | Local SOCKS5 port |
| `--psk` | env `TUNDRA_PSK` | Pre-shared key (64 hex chars) |
| `--fme` | true | Enable Flow Morphing Engine |
| `--fme-profile` | `browser` | Traffic profile: `browser`, `video`, `chat`, `streaming`, `paranoid` |
| `--max-session-age-secs` | 600 | Session rotation interval |
| `--max-session-bytes-mb` | 200 | Session rotation by volume |

## Flow Morphing Engine

FME transforms proxy traffic to resist statistical fingerprinting by DPI systems.

### Traffic Profiles

| Profile | Mimics | Overhead (10KB) | Overhead (100KB) | Packets/100KB |
|---------|--------|-----------------|------------------|---------------|
| `browser` | Chrome TLS browsing | +4.3% | +0.0% | ~192 |
| `video` | Video streaming | +2.0% | +0.2% | ~550 |
| `chat` | Messaging app | +0.7% | +0.0% | ~546 |
| `streaming` | HTTP/2 multiplexed | +13.1% | +0.2% | ~288 |
| `paranoid` | Maximum obfuscation | +10.3% | +0.0% | ~133 |

### FME Components

- **GMM size sampler** — Gaussian Mixture Model with 4-8 components per profile, 128-entry pre-generated cache
- **Markov chain IAT** — 8-state chain (Idle → DNS → Handshake → Request → ResponseBurst → ResponseTrickle → WebSocket → Keepalive), 128-entry cache
- **Chaff generator** — 6 content types (RandomBytes, HttpLikeHeaders, DnsLikeQuery, DummyTlsRecord, Http2Frame, RandomHighEntropy), weighted per profile
- **Adversarial noise** — optional jitter (±8-15%) on IAT and noise (±3-5%) on sizes
- **Random padding** — non-zero random bytes (resists entropy-based detection)

### Throughput

Benchmarked on Apple M1 (release build), 100KB payload:

| Profile | Throughput | Time |
|---------|-----------|------|
| `browser` | ~3.0 GB/s | 32 µs |
| `streaming` | ~2.3 GB/s | 43 µs |
| `video` | ~1.8 GB/s | 56 µs |
| `chat` | ~1.6 GB/s | 64 µs |
| `paranoid` | ~3.2 GB/s | 31 µs |

## Protocol

### Handshake

All handshake frames are padded to 1400 bytes to resist size-based probing.

```
Client                                          Server
  │                                                │
  │──── TCP connect ──────────────────────────────►│
  │──── TLS handshake ────────────────────────────►│
  │                                                │
  │  ◄── Challenge(server_nonce:16) ────────────── │
  │  ── Auth(ts:8 + HMAC:32 + kyber_pk + x25519_pk)►│
  │  ◄── AuthAck(kyber_ct + x25519_ct) ────────── │
  │                                                │
  │    [both sides derive shared secret            │
  │     from hybrid KEM decapsulation]             │
  │    [both sides derive enc keys with role suffix]│
  │                                                │
  │  ◄── KeyConfirm(HASH(s2c_key, "tundra-...")) ─ │
  │  ── KeyConfirm(HASH(c2s_key, "tundra-...")) ──►│
  │    [constant-time verification by both sides]   │
  │                                                │
  │  ════════ Encrypted multiplexed tunnel ════════ │
  │◄───────────────────────────────────────────────►│
  │         Data / NewStream / Close / Ping         │
  └─────────────────────────────────────────────────┘
```

### Wire Format

Frame (after TLS decryption):
```
[magic:4][cmd:1][stream_id:4][payload_len:2][payload:N]
```

Encrypted transport:
```
[length:2 BE][nonce:12][AEAD-encrypted(frame)]
```

## E2E Latency

Real-world test (macOS → NL VPS, HTTPS GET to ifconfig.me):

| Path | Avg latency |
|------|------------|
| Direct | ~250 ms |
| Via Tundra (browser profile) | ~350 ms |
| Via Tundra (paranoid profile) | ~355 ms |

## Security

- **PSK auth** with HMAC-BLAKE3, timestamp-based replay protection (300s window)
- **Hybrid KEM** — Kyber768 + X25519; both must succeed; combined via BLAKE3
- **Key confirmation** — both sides verify peer's key hash; constant-time comparison (`subtle`)
- **Role-separated nonces** — byte 11 = `0x01` (client) / `0x02` (server) prevents cross-role reuse
- **Sensitive data zeroization** — PSK, shared secrets, private keys wiped via `zeroize`
- **ACL** — server blocks connections to RFC 1918 / loopback / link-local addresses
- **Fallback** — non-Tundra TLS traffic reverse-proxied to `target_domain`
- **No traffic logging** — only connection metadata (peer IP, target host:port)

## Requirements

**Server:** Linux (x86_64/aarch64), Rust 1.82+

**Client CLI:** macOS / Linux / Windows, Rust 1.82+

**Client GUI:** macOS (Apple Silicon), Tauri 2.x runtime

## License

MIT
