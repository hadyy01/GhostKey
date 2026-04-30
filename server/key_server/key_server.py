"""
============================================================
SecIoT — Raspberry Pi Key Server
Contribution: Hardware-Rooted Device Authentication & Session
              Key Distribution

Replaces: original key_Server.py (which used secrets.choice()
          on a software PRNG and sent key+IV in plaintext).

What this server does:
  1. ENROLLMENT (one-time per device):
     • Receives "ENROLL:<hex_puf_fingerprint>" from a device.
     • Stores the fingerprint in a local JSON registry.
     • Replies "ENROLLED:OK".

  2. AUTHENTICATION (every boot):
     • Receives "AUTH:<hex_puf_fingerprint>" from a device.
     • Looks up the fingerprint in the registry.
     • If matched: generates a fresh 128-bit session key and
       sends "KEY:<hex_key>" back.
     • If not found: sends "ERR:DEVICE_NOT_ENROLLED".

  Session key generation uses os.urandom(16) — the OS CSPRNG,
  which on Linux (RPi) reads from /dev/urandom backed by the
  hardware TRNG in the BCM2837/2711 SoC.

Architecture:
  Port 9000 — this key server (auth + key distribution)
  Port 8010 — data_server.py (receives encrypted sensor data)

Author: Khan Hady Khamis
Revamped: 2024 — PUF-based authentication, per-session keys
============================================================
"""

import os
import json
import logging
import hashlib
import secrets
from pathlib import Path
from datetime import datetime
from SimpleWebSocketServer import SimpleWebSocketServer, WebSocket

# ── Logging ──────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [KEY-SERVER] %(levelname)s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("key_server")

# ── Device registry ───────────────────────────────────────────
REGISTRY_PATH = Path(__file__).parent / "device_registry.json"

def load_registry() -> dict:
    """Load the PUF fingerprint registry from disk."""
    if REGISTRY_PATH.exists():
        with open(REGISTRY_PATH) as f:
            return json.load(f)
    return {}

def save_registry(registry: dict) -> None:
    """Persist the registry atomically."""
    tmp = REGISTRY_PATH.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(registry, f, indent=2)
    tmp.replace(REGISTRY_PATH)

registry: dict = load_registry()
log.info("Loaded %d enrolled device(s) from registry.", len(registry))

# ── Session key store ─────────────────────────────────────────
# Maps device fingerprint → current session key (hex)
# The data server reads from this store to decrypt incoming messages.
SESSION_STORE_PATH = Path(__file__).parent / "session_store.json"

def publish_session_key(fingerprint: str, key_hex: str) -> None:
    """Write the active session key to the shared store."""
    store: dict = {}
    if SESSION_STORE_PATH.exists():
        with open(SESSION_STORE_PATH) as f:
            store = json.load(f)
    store[fingerprint] = {
        "key": key_hex,
        "issued_at": datetime.utcnow().isoformat(),
    }
    with open(SESSION_STORE_PATH, "w") as f:
        json.dump(store, f, indent=2)

# ── WebSocket handler ─────────────────────────────────────────

class KeyServer(WebSocket):
    """
    Handles two message types from devices:

    ENROLL:<64-hex-char SHA-256 PUF fingerprint>
        → registers device; replies ENROLLED:OK

    AUTH:<64-hex-char SHA-256 PUF fingerprint>
        → authenticates device; replies KEY:<32-hex-char AES key>
          or ERR:<reason>
    """

    def handleConnected(self):
        log.info("Device connected from %s", self.address)

    def handleClose(self):
        log.info("Device disconnected from %s", self.address)

    def handleMessage(self):
        msg: str = self.data.strip()
        log.debug("Received: %s", msg[:80])

        if msg.startswith("ENROLL:"):
            self._handle_enrollment(msg[7:])

        elif msg.startswith("AUTH:"):
            self._handle_authentication(msg[5:])

        else:
            log.warning("Unknown message from %s: %s", self.address, msg[:40])
            self.sendMessage("ERR:UNKNOWN_COMMAND")

    # ── Enrollment ────────────────────────────────────────────

    def _handle_enrollment(self, fingerprint_hex: str) -> None:
        """Register a new device PUF fingerprint."""
        if not self._valid_fingerprint(fingerprint_hex):
            log.warning("Invalid fingerprint from %s", self.address)
            self.sendMessage("ERR:INVALID_FINGERPRINT")
            return

        if fingerprint_hex in registry:
            log.info("Device already enrolled: %s...", fingerprint_hex[:16])
            self.sendMessage("ENROLLED:OK")  # idempotent
            return

        # Store with metadata
        registry[fingerprint_hex] = {
            "enrolled_at": datetime.utcnow().isoformat(),
            "address":     str(self.address),
        }
        save_registry(registry)

        log.info("✓ New device enrolled. Fingerprint: %s...", fingerprint_hex[:16])
        self.sendMessage("ENROLLED:OK")

    # ── Authentication ────────────────────────────────────────

    def _handle_authentication(self, fingerprint_hex: str) -> None:
        """
        Authenticate a device by its PUF fingerprint and issue
        a fresh session key.

        Session key source: os.urandom(16)
          On RPi (Linux), this reads from the kernel CSPRNG
          (/dev/urandom) which is seeded by hardware entropy
          (BCM SoC TRNG, interrupt timing, etc.).
        """
        if not self._valid_fingerprint(fingerprint_hex):
            self.sendMessage("ERR:INVALID_FINGERPRINT")
            return

        if fingerprint_hex not in registry:
            log.warning("AUTH rejected — unknown device: %s...", fingerprint_hex[:16])
            self.sendMessage("ERR:DEVICE_NOT_ENROLLED")
            return

        # Generate fresh 128-bit session key
        session_key_bytes = os.urandom(16)
        session_key_hex   = session_key_bytes.hex()

        # Publish to shared store so data_server can decrypt
        publish_session_key(fingerprint_hex, session_key_hex)

        log.info(
            "✓ AUTH OK for device %s... | Session key: %s...",
            fingerprint_hex[:16], session_key_hex[:8],
        )
        self.sendMessage(f"KEY:{session_key_hex}")

    # ── Helpers ───────────────────────────────────────────────

    @staticmethod
    def _valid_fingerprint(fp: str) -> bool:
        """SHA-256 hex fingerprint must be exactly 64 lowercase hex chars."""
        if len(fp) != 64:
            return False
        try:
            int(fp, 16)
            return True
        except ValueError:
            return False


# ── Entry point ───────────────────────────────────────────────

if __name__ == "__main__":
    HOST = "0.0.0.0"
    PORT = 9000
    log.info("SecIoT Key Server starting on %s:%d", HOST, PORT)
    log.info("Registry path: %s", REGISTRY_PATH)
    server = SimpleWebSocketServer(HOST, PORT, KeyServer)
    server.serveforever()
