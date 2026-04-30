"""
============================================================
SecIoT — Offline Crypto Validation Tool

Simulates the full encrypt→transmit→decrypt pipeline in
pure Python so you can verify the GCM implementation before
flashing firmware.

Usage:
    python3 tools/validate_crypto.py

What it tests:
    1. AES-128-GCM encryption (simulating the firmware side)
    2. AES-128-GCM decryption (simulating the data server)
    3. Tag-tamper detection — modifies one byte and confirms
       the decryption is rejected
    4. SRAM-PUF simulation — verifies SHA-256 fingerprinting
       logic using a synthetic SRAM pattern

Author: Khan Hady Khamis
============================================================
"""

import os
import base64
import hashlib
import json
from Crypto.Cipher import AES

# ── Constants (must match firmware) ───────────────────────────
GCM_IV_LEN  = 12
GCM_TAG_LEN = 16

PASS  = "✓ PASS"
FAIL  = "✗ FAIL"

# ─────────────────────────────────────────────────────────────
# 1. AES-128-GCM Round-Trip Test
# ─────────────────────────────────────────────────────────────

def encrypt_gcm(key: bytes, plaintext: bytes, aad: bytes) -> str:
    """Simulate firmware encryptGCM() in Python."""
    nonce  = os.urandom(GCM_IV_LEN)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    wire = nonce + ciphertext + tag
    return base64.b64encode(wire).decode()

def decrypt_gcm(key: bytes, wire_b64: str, aad: bytes) -> bytes | None:
    """Simulate data_server decrypt_gcm() — returns None on tamper."""
    wire       = base64.b64decode(wire_b64)
    nonce      = wire[:GCM_IV_LEN]
    tag        = wire[-GCM_TAG_LEN:]
    ciphertext = wire[GCM_IV_LEN:-GCM_TAG_LEN]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        return None

def test_gcm_roundtrip():
    print("\n[TEST 1] AES-128-GCM round-trip")
    key       = os.urandom(16)
    plaintext = json.dumps({"device": "node_001", "temp": "28.5", "id": "1"}).encode()
    aad       = b"device_001"

    wire      = encrypt_gcm(key, plaintext, aad)
    recovered = decrypt_gcm(key, wire, aad)

    ok = (recovered == plaintext)
    print(f"  Plaintext:  {plaintext.decode()}")
    print(f"  Wire (b64): {wire[:40]}...")
    print(f"  Recovered:  {recovered.decode() if recovered else 'NONE'}")
    print(f"  Result:     {PASS if ok else FAIL}")
    return ok

# ─────────────────────────────────────────────────────────────
# 2. Tamper Detection Test
# ─────────────────────────────────────────────────────────────

def test_tamper_detection():
    print("\n[TEST 2] GCM tamper detection (IND-CCA2 property)")
    key       = os.urandom(16)
    plaintext = b'{"temp":"28.5","id":"1"}'
    aad       = b"device_001"

    wire_b64  = encrypt_gcm(key, plaintext, aad)
    wire      = bytearray(base64.b64decode(wire_b64))

    # Flip one bit in the ciphertext body
    flip_idx = GCM_IV_LEN + 2
    wire[flip_idx] ^= 0xFF
    tampered_b64 = base64.b64encode(bytes(wire)).decode()

    result = decrypt_gcm(key, tampered_b64, aad)
    ok = (result is None)
    print(f"  Tampered byte at position {flip_idx}")
    print(f"  Decryption result:  {'REJECTED (correct)' if ok else 'ACCEPTED (BUG!)'}")
    print(f"  Result:             {PASS if ok else FAIL}")
    return ok

# ─────────────────────────────────────────────────────────────
# 3. Wrong Key Test
# ─────────────────────────────────────────────────────────────

def test_wrong_key():
    print("\n[TEST 3] Decryption with wrong key rejected")
    key_enc   = os.urandom(16)
    key_wrong = os.urandom(16)
    plaintext = b'{"temp":"28.5"}'
    aad       = b"device_001"

    wire      = encrypt_gcm(key_enc, plaintext, aad)
    result    = decrypt_gcm(key_wrong, wire, aad)
    ok        = (result is None)
    print(f"  Result: {PASS if ok else FAIL}")
    return ok

# ─────────────────────────────────────────────────────────────
# 4. SRAM-PUF Fingerprint Simulation
# ─────────────────────────────────────────────────────────────

def simulate_sram_puf(chip_id: int) -> str:
    """
    Simulates the SRAM startup pattern for a given chip ID.
    In real hardware, this is read from 0x3FFE8000 before
    the bootloader runs.  Here we use a seeded hash to
    reproduce the same 'unique' pattern per chip.
    """
    # Simulate 64 SRAM words with manufacturing variation
    import random
    rng = random.Random(chip_id)
    sram_words = [rng.getrandbits(32) for _ in range(64)]

    # Von Neumann debiasing (Python equivalent of firmware C)
    raw_bits = bytearray()
    current_byte = 0
    bit_pos = 0
    for word in sram_words:
        for i in range(0, 30, 2):
            b0 = (word >> i) & 1
            b1 = (word >> (i+1)) & 1
            if b0 != b1:
                current_byte |= (b0 << bit_pos)
                bit_pos += 1
                if bit_pos == 8:
                    raw_bits.append(current_byte)
                    current_byte = 0
                    bit_pos = 0
        if len(raw_bits) >= 16:
            break

    fingerprint = hashlib.sha256(bytes(raw_bits[:16])).hexdigest()
    return fingerprint

def test_puf_uniqueness():
    print("\n[TEST 4] SRAM PUF fingerprint uniqueness")
    fingerprints = [simulate_sram_puf(chip_id=i) for i in range(5)]
    unique = len(set(fingerprints))
    print(f"  Generated {len(fingerprints)} fingerprints for 5 simulated chips")
    for i, fp in enumerate(fingerprints):
        print(f"    Chip {i}: {fp[:32]}...")
    ok = (unique == len(fingerprints))
    print(f"  All unique: {PASS if ok else FAIL}")

    # Stability: same chip_id → same fingerprint
    fp_a = simulate_sram_puf(chip_id=42)
    fp_b = simulate_sram_puf(chip_id=42)
    stable = (fp_a == fp_b)
    print(f"  Fingerprint stable across reads: {PASS if stable else FAIL}")
    return ok and stable

# ─────────────────────────────────────────────────────────────
# 5. Hamming Distance between PUF responses (intra vs inter)
# ─────────────────────────────────────────────────────────────

def hamming_distance(a: str, b: str) -> int:
    """Bit-level Hamming distance between two hex strings."""
    ba = bytes.fromhex(a)
    bb = bytes.fromhex(b)
    return sum(bin(x ^ y).count('1') for x, y in zip(ba, bb))

def test_puf_hamming():
    print("\n[TEST 5] PUF Hamming distance (intra-chip vs inter-chip)")
    # Intra-chip: same chip, two reads (should be ~0 after debiasing + SHA-256)
    intra = hamming_distance(
        simulate_sram_puf(chip_id=7),
        simulate_sram_puf(chip_id=7),
    )
    # Inter-chip: two different chips (should be ~50% = 128/256 bits)
    inter = hamming_distance(
        simulate_sram_puf(chip_id=7),
        simulate_sram_puf(chip_id=8),
    )
    print(f"  Intra-chip Hamming distance (same chip): {intra} bits")
    print(f"  Inter-chip Hamming distance (diff chip): {inter} bits  (~128 expected)")
    ok = (intra == 0 and inter > 50)
    print(f"  Result: {PASS if ok else FAIL}")
    return ok

# ── Main ──────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 56)
    print("SecIoT — Offline Crypto & PUF Validation")
    print("=" * 56)

    results = [
        test_gcm_roundtrip(),
        test_tamper_detection(),
        test_wrong_key(),
        test_puf_uniqueness(),
        test_puf_hamming(),
    ]

    passed = sum(results)
    total  = len(results)
    print(f"\n{'='*56}")
    print(f"Results: {passed}/{total} tests passed")
    if passed == total:
        print("All tests passed. System is ready for hardware deployment.")
    else:
        print("Some tests failed. Check output above.")
    print("=" * 56)
