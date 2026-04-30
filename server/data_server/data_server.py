"""
============================================================
SecIoT — Data Server (Raspberry Pi)
Contribution: AES-128-GCM Authenticated Decryption

Replaces: original server.py (AES-CBC with static IV
          'ABCDABCDABCDABCD' — IND-CPA insecure, no authentication).

What this server does:
  • Accepts WebSocket connections from enrolled IoT devices.
  • Receives base64-encoded payloads in wire format:
      [ 12-byte GCM nonce | ciphertext | 16-byte GCM tag ]
  • Looks up the device's current session key from the shared
    session_store.json written by key_server.py.
  • Decrypts and authenticates each message.
  • Any tampered ciphertext raises InvalidTag and is discarded
    before decryption even completes — this is the core
    advantage of GCM over the original CBC implementation.

Port: 8010

Author: Khan Hady Khamis
Revamped: 2024 — GCM decryption with per-session keys
============================================================
"""

import base64
import json
import logging
from pathlib import Path
from datetime import datetime

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from SimpleWebSocketServer import SimpleWebSocketServer, WebSocket

# ── Logging ──────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [DATA-SERVER] %(levelname)s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("data_server")

# ── Session store (written by key_server.py) ─────────────────
SESSION_STORE_PATH = Path(__file__).parent.parent / "key_server" / "session_store.json"

def get_session_key(device_id: str) -> bytes | None:
    """
    Retrieve the active session key for a device.
    Returns raw bytes or None if not found.
    """
    if not SESSION_STORE_PATH.exists():
        return None
    with open(SESSION_STORE_PATH) as f:
        store = json.load(f)
    entry = store.get(device_id)
    if entry is None:
        return None
    return bytes.fromhex(entry["key"])

# ── GCM constants (must match firmware) ───────────────────────
GCM_IV_LEN  = 12   # 96-bit nonce
GCM_TAG_LEN = 16   # 128-bit authentication tag

# ── Decryption ────────────────────────────────────────────────

def decrypt_gcm(session_key: bytes, wire_b64: str, aad: bytes) -> str | None:
    """
    Decrypt an AES-128-GCM payload received from an IoT device.

    Wire format (binary, then base64-encoded):
      [ 12-byte nonce | ciphertext | 16-byte tag ]

    Args:
        session_key:  16-byte AES key from session store
        wire_b64:     base64 string received over WebSocket
        aad:          additional authenticated data (e.g. device ID)

    Returns:
        Decrypted plaintext string, or None if authentication fails.
    """
    try:
        wire = base64.b64decode(wire_b64)
    except Exception as e:
        log.error("Base64 decode error: %s", e)
        return None

    if len(wire) < GCM_IV_LEN + GCM_TAG_LEN + 1:
        log.error("Payload too short: %d bytes", len(wire))
        return None

    nonce      = wire[:GCM_IV_LEN]
    tag        = wire[-GCM_TAG_LEN:]
    ciphertext = wire[GCM_IV_LEN:-GCM_TAG_LEN]

    cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode("utf-8")
    except ValueError:
        # GCM tag mismatch — message was tampered or wrong key
        log.warning("⚠  GCM authentication FAILED — message rejected.")
        return None

# ── WebSocket handler ─────────────────────────────────────────

class DataServer(WebSocket):
    """
    Receives encrypted sensor data from IoT devices and decrypts
    it using the session key issued by key_server.py.

    Message format from device:
      HELLO:<device_id>          — device announces itself
      <base64 GCM payload>       — encrypted sensor reading
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.device_id: str | None = None

    def handleConnected(self):
        log.info("Device connected from %s", self.address)
        self.sendMessage("READY")

    def handleClose(self):
        log.info("Device %s disconnected.", self.device_id or self.address)

    def handleMessage(self):
        msg: str = self.data.strip()

        # ── Device identification ─────────────────────────────
        if msg.startswith("HELLO:"):
            self.device_id = msg[6:].strip()
            log.info("Device identified: %s", self.device_id)
            self.sendMessage("SEND")   # prompt first reading
            return

        # ── Encrypted payload ─────────────────────────────────
        if self.device_id is None:
            log.warning("Message from unidentified device — ignoring.")
            self.sendMessage("ERR:IDENTIFY_FIRST")
            return

        session_key = get_session_key(self.device_id)
        if session_key is None:
            log.warning("No session key for device %s", self.device_id)
            self.sendMessage("ERR:NO_SESSION_KEY")
            return

        aad = self.device_id.encode("utf-8")
        plaintext = decrypt_gcm(session_key, msg, aad)

        if plaintext is not None:
            log.info("✓ Decrypted from %s: %s", self.device_id, plaintext)
            self._store_reading(plaintext)
            self.sendMessage("ACK")
            # Prompt for the next reading
            self.sendMessage("SEND")
        else:
            log.warning("Decryption failed for device %s — dropping message.", self.device_id)
            self.sendMessage("ERR:DECRYPT_FAILED")

    # ── Data storage ──────────────────────────────────────────

    def _store_reading(self, plaintext: str) -> None:
        """
        Append the decrypted sensor reading to a JSONL log file.
        In production, replace with InfluxDB / MQTT / database write.
        """
        data_file = Path(__file__).parent / "sensor_data.jsonl"
        try:
            record = json.loads(plaintext)
            record["received_at"] = datetime.utcnow().isoformat()
            record["source"] = self.device_id
            with open(data_file, "a") as f:
                f.write(json.dumps(record) + "\n")
        except json.JSONDecodeError:
            # plaintext is not JSON — log raw
            with open(data_file, "a") as f:
                f.write(json.dumps({
                    "raw": plaintext,
                    "source": self.device_id,
                    "received_at": datetime.utcnow().isoformat(),
                }) + "\n")


# ── Entry point ───────────────────────────────────────────────

if __name__ == "__main__":
    HOST = "0.0.0.0"
    PORT = 8010
    log.info("SecIoT Data Server starting on %s:%d", HOST, PORT)
    server = SimpleWebSocketServer(HOST, PORT, DataServer)
    server.serveforever()
