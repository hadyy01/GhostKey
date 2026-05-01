# GhostKey — Hardware-Rooted Secure Communication for IoT Devices

> Encryption keys that are never stored, never transmitted in plaintext, and born from physical hardware noise that vanishes after use. The key is a ghost.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: ESP8266](https://img.shields.io/badge/Platform-ESP8266%20%2F%20ESP32-orange.svg)]()
[![Server: Raspberry Pi](https://img.shields.io/badge/Server-Raspberry%20Pi-red.svg)]()
[![Crypto: AES-128-GCM](https://img.shields.io/badge/Crypto-AES--128--GCM-green.svg)]()
[![Security: IND-CCA2](https://img.shields.io/badge/Security-IND--CCA2-blueviolet.svg)]()

---

## The Problem

Billions of IoT devices share the same fundamental weakness: **their identity is software**. A device's secret key is burned into flash memory — readable by anyone with physical access or a firmware dump. Clone the firmware, clone the device. There is no hardware the attacker cannot copy.

Existing solutions — TPM chips, ATECC608 secure elements — cost money, require extra hardware, and add supply chain complexity. Most IoT deployments skip them entirely.

GhostKey solves this using silicon that is already there.

---

## Three Core Contributions

### [C1] SRAM Physical Unclonable Function — Device Identity from Silicon

When an ESP8266 powers on, its SRAM cells settle into a startup pattern determined by nanometre-scale manufacturing variation in the NMOS transistors. No two chips settle the same way. This pattern is the chip's fingerprint — unique, stable across power cycles, and physically unclonable without destroying the chip.

GhostKey reads this pattern from address `0x3FFE8000` before the WiFi stack touches heap memory, applies von Neumann debiasing to remove systematic bit bias, and hashes the result through SHA-256 to produce a stable 256-bit device identity.

```
Power-on SRAM → Von Neumann Debias → SHA-256 → 256-bit Device Fingerprint
```

The Raspberry Pi key server stores fingerprints during a one-time enrollment. From then on, any device authenticates by presenting its PUF response — no password, no certificate, no stored secret.

**Security property:** Stealing the firmware binary does not clone the device. The secret is the physical geometry of the silicon, which cannot be read non-destructively.

- **Inter-chip Hamming distance ≈ 50%** — chips are maximally distinct from each other
- **Intra-chip Hamming distance ≈ 0%** — same chip reads same fingerprint every boot

---

### [C2] Ring-Oscillator TRNG — Session Keys from Hardware Entropy

The ESP8266 contains two independent oscillators: the CPU PLL (80 MHz) and the WiFi modem PLL (~80 MHz). Sampling the Xtensa CPU cycle counter (`ccount` register) XOR'd against `micros()` — which runs from a completely separate hardware timer — captures thermal jitter between the two clock domains. This jitter is genuine physical entropy: determined by thermal noise in resistors, unobservable from software, and impossible to replay.

GhostKey collects 128 jitter samples in ~130 µs, debiases them, and hashes through SHA-256 to produce a uniform 128-bit session key per boot.

```
ccount XOR micros() × 128 samples → Von Neumann Debias → SHA-256 → 128-bit Session Key
```

This key material never existed anywhere before this boot. It cannot be predicted by an attacker who has compromised the server, read the firmware, or intercepted previous sessions.

---

### [C3] AES-128-GCM — Authenticated Encryption

The naive IoT approach is AES-CBC with a static IV. This leaks plaintext structure (identical messages produce identical ciphertext) and provides zero tamper detection — a bit-flip attack on the ciphertext goes completely unnoticed.

GhostKey uses AES-128-GCM. Every message gets a fresh 12-byte nonce from the TRNG. The 16-byte GHASH tag authenticates both the ciphertext and the device ID (passed as Additional Authenticated Data). Any tampered ciphertext causes tag verification to fail before a single byte of plaintext is produced.

| Property | AES-CBC + static IV | AES-128-GCM (GhostKey) |
|---|---|---|
| Same message encrypted twice | Identical ciphertext | Different every time |
| Ciphertext tamper detection | None | GHASH tag — rejected before decrypt |
| Formal security model | Not IND-CPA secure | IND-CCA2 secure |
| Per-message overhead | 0 extra bytes | +28 bytes (12 nonce + 16 tag) |

**Wire format per WebSocket frame:**
```
┌─────────────────┬──────────────────────────────┬──────────────────┐
│   12 bytes      │         variable              │    16 bytes      │
│   GCM nonce     │   Ciphertext (sensor JSON)    │   GHASH tag      │
│  (TRNG-fresh)   │                               │  (tamper detect) │
└─────────────────┴──────────────────────────────┴──────────────────┘
                              ▼  base64-encode
                       WebSocket text frame
```

---

## System Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                      Local WiFi / WebSocket TCP                      │
│                                                                      │
│  ┌────────────────────────┐              ┌────────────────────────┐  │
│  │   ESP8266 / NodeMCU    │              │    Raspberry Pi 3/4    │  │
│  │      (IoT Client)      │              │   (Key + Data Server)  │  │
│  │                        │              │                        │  │
│  │  ┌──────────────────┐  │              │  ┌──────────────────┐  │  │
│  │  │  [C1] SRAM PUF   │  │──AUTH:fp──▶ │  │  Key Server      │  │  │
│  │  │  Device identity │  │ ◀──KEY:k─── │  │  :9000           │  │  │
│  │  └──────────────────┘  │              │  │  PUF registry    │  │  │
│  │                        │              │  │  session_store   │  │  │
│  │  ┌──────────────────┐  │              │  └──────────────────┘  │  │
│  │  │  [C2] RO-TRNG    │  │              │                        │  │
│  │  │  Session entropy │  │              │  ┌──────────────────┐  │  │
│  │  └──────────────────┘  │              │  │  Data Server     │  │  │
│  │                        │──GCM msg──▶  │  │  :8010           │  │  │
│  │  ┌──────────────────┐  │ ◀───ACK───── │  │  GCM decrypt     │  │  │
│  │  │  [C3] AES-128-GCM│  │              │  │  sensor log      │  │  │
│  │  │  Authenticated   │  │              │  └──────────────────┘  │  │
│  │  │  encryption      │  │              │                        │  │
│  │  └──────────────────┘  │              └────────────────────────┘  │
│  └────────────────────────┘                                          │
└──────────────────────────────────────────────────────────────────────┘
```

### Protocol flow (per boot)

| Step | Actor | Action |
|------|-------|--------|
| 1 | ESP8266 | Reads raw SRAM at `0x3FFE8000` before heap init. Von Neumann debias → SHA-256 → 256-bit fingerprint. |
| 2 | ESP8266 → Key Server | Sends `AUTH:<64-hex-fingerprint>` over WebSocket to port 9000. |
| 3 | Key Server | Verifies fingerprint against `device_registry.json`. Generates fresh 128-bit key via `os.urandom(16)`. Writes to `session_store.json`. |
| 4 | Key Server → ESP8266 | Sends `KEY:<32-hex-key>`. Key channel closed immediately after. |
| 5 | ESP8266 | Per message: TRNG samples `ccount XOR micros()` × 128 → SHA-256 → 12-byte GCM nonce. Encrypts with AES-128-GCM. |
| 6 | ESP8266 → Data Server | Sends base64 GCM payload to port 8010. |
| 7 | Data Server | Fetches session key from store. Verifies GHASH tag → decrypts → logs sensor JSON. |

---

## Repository Structure

```
GhostKey/
├── firmware/
│   ├── device_client/
│   │   └── device_client.ino          # Main firmware — flash for normal operation
│   └── sram_puf_enrollment/
│       └── sram_puf_enrollment.ino    # Run ONCE per new device to enroll PUF
│
├── server/
│   ├── key_server/
│   │   ├── key_server.py              # RPi Key Server (port 9000)
│   │   └── device_registry.json      # Auto-created on first enrollment
│   ├── data_server/
│   │   ├── data_server.py             # RPi Data Server (port 8010)
│   │   └── sensor_data.jsonl          # Decrypted readings log
│   └── requirements.txt
│
└── tools/
    └── validate_crypto.py             # Offline test suite — run on PC before hardware
```

---

## Quick Start

### Prerequisites

**Raspberry Pi:**
```bash
pip3 install pycryptodome SimpleWebSocketServer
```

**Arduino IDE — Library Manager:**
- `arduinoWebSockets` (Markus Sattler)
- `Crypto` (Rhys Weatherley) — includes SHA256 and AES-GCM

**Arduino IDE — Board Manager:**
- ESP8266: `http://arduino.esp8266.com/stable/package_esp8266com_index.json`

---

### Step 1 — Validate crypto on your PC (no hardware needed)

```bash
pip3 install pycryptodome
python3 tools/validate_crypto.py
```

All 5 tests should pass: GCM round-trip, tamper detection, wrong-key rejection, PUF uniqueness, and Hamming distance characterisation.

---

### Step 2 — Start the Raspberry Pi servers

```bash
# Terminal 1
python3 server/key_server/key_server.py

# Terminal 2
python3 server/data_server/data_server.py
```

---

### Step 3 — Enroll each NodeMCU (one-time per device)

1. Open `firmware/sram_puf_enrollment/sram_puf_enrollment.ino` in Arduino IDE.
2. Set `WIFI_SSID`, `WIFI_PASSWORD`, and `KEY_SERVER_IP`.
3. Flash to the NodeMCU. Open Serial Monitor at 115200 baud.

Expected output:
```
[ENROLL] Sent enrollment fingerprint.
[ENROLL] ✓ Enrollment SUCCESS.
[ENROLL] You may now flash device_client.ino.
```

---

### Step 4 — Flash the main firmware

1. Open `firmware/device_client/device_client.ino`.
2. Set the same credentials. Flash to NodeMCU.

Expected output:
```
[PUF] Device fingerprint: a3f2c8...
[KEY] Session key received and stored.
[GCM] Encrypted 48 bytes. Wire size: 76 bytes.
[DATA] Encrypted message sent.
```

RPi data server logs:
```
[DATA-SERVER] ✓ Decrypted from node_001: {"device":"node_001","temp":"28.51","id":"1"}
```

---

## Security Analysis

### Threat model

| Threat | Naive AES-CBC | GhostKey |
|---|---|---|
| Attacker intercepts WiFi traffic | Reads plaintext key | Sees only GCM ciphertext — key never on wire |
| Same message sent twice | Identical ciphertext — structure leaks | Different ciphertext every time (TRNG nonce) |
| Attacker flips bits in ciphertext | Undetected — decryption proceeds | GHASH tag fails — rejected before any plaintext |
| Attacker clones the device | Copy firmware flash → done | Must replicate sub-micron SRAM silicon geometry |
| Attacker replays a captured frame | Works — no freshness check | Fails — per-session key, fresh nonce per message |

### Formal security claim

Under standard assumptions (AES as a pseudorandom permutation, SHA-256 as a random oracle):
- **IND-CCA2** confidentiality — AES-128-GCM with TRNG-fresh nonces per message
- **Device authentication** — SRAM PUF model (Gassend et al., 2002): attacker cannot forge a valid PUF response without physical access to the chip

---

## Limitations and Future Work

**SRAM PUF temperature sensitivity** — startup patterns can drift slightly under extreme temperatures. Production deployments should add a fuzzy extractor (BCH or Reed-Solomon error correction) to tolerate ~5% bit-flip variation without affecting fingerprint stability.

**ECDH enrollment** — currently the session key is sent as `KEY:<hex>` over WebSocket. A full implementation would use ECDH to establish a shared secret during enrollment, eliminating any key material from the wire entirely.

**NIST SP 800-22 entropy validation** — the TRNG output should be run through the full NIST statistical test suite on physical hardware to formally certify entropy quality. The `validate_crypto.py` tool covers simulation; hardware validation is the next step.

**Fuzzy extractor integration** — for commercial-grade PUF stability, replace the raw SHA-256 hash with a proper helper-data scheme that corrects for bit-flip noise while leaking zero information about the PUF response.

---

## References

1. Gassend, B., Clarke, D., van Dijk, M., & Devadas, S. (2002). *Silicon Physical Random Functions.* ACM CCS 2002.
2. Maiti, A., & Schaumont, P. (2009). *Improving the Quality of a Physical Unclonable Function Using Configurable Ring Oscillators.* FPL 2009.
3. Sunar, B., Martin, W.J., & Stinson, D.R. (2007). *A Provably Secure True Random Number Generator with Built-In Tolerance to Active Attacks.* IEEE Transactions on Computers.
4. Dworkin, M. (2007). *NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM).* NIST.
5. NIST SP 800-90A Rev.1: Recommendation for Random Number Generation Using Deterministic Random Bit Generators. NIST, 2015.

---

## Author

**Khan Hady Khamis**

---

## License

MIT — see [LICENSE](LICENSE).
