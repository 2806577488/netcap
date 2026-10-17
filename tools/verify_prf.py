# Independent verification of one client flight: PRF, key block, and the Finished record.
# Reads _flight.txt (hex) and _keys.txt ("<client_key> <client_iv> <master> <pub>") plus
# the trace values from _t12.err written by NETCAP_TLS12_TRACE=1.
import hashlib
import hmac
import re
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = __import__("os").path.dirname(__import__("os").path.abspath(__file__)) + "/../"


def p_hash(secret, seed, size):
    out = b""
    a = seed
    while len(out) < size:
        a = hmac.new(secret, a, hashlib.sha256).digest()
        out += hmac.new(secret, a + seed, hashlib.sha256).digest()
    return out[:size]


def prf(secret, label, seed, size):
    return p_hash(secret, label + seed, size)


def main():
    flight = bytes.fromhex(open(ROOT + "_flight.txt").read().strip())
    err = open(ROOT + "_t12.err", encoding="utf-8", errors="replace").read()
    ck, civ, master_mine, pub = open(ROOT + "_keys.txt").read().split()
    m = re.search(r"master=([0-9a-f]{96}) pms=([0-9a-f]{64})", err)
    sr = re.search(r"server_random=([0-9a-f]{64})", err).group(1)
    cr = re.search(r"client_random=([0-9a-f]{64})", err).group(1)
    pms = m.group(2)
    print("keys.txt master :", master_mine)
    print("trace master    :", m.group(1))
    master = bytes.fromhex(pms)  # placeholder, replaced below
    master = prf(bytes.fromhex(pms), b"master secret", bytes.fromhex(cr) + bytes.fromhex(sr), 48)
    print("python master   :", master.hex())
    block = prf(master, b"key expansion", bytes.fromhex(sr) + bytes.fromhex(cr), 40)
    print("python client_k :", block[0:16].hex(), "trace:", ck)
    print("python client_i :", block[32:36].hex(), "trace:", civ)
    # Finished record: CKE record 42 bytes, CCS 6 bytes, then 5 byte header + 40 byte body.
    body = flight[53:93]
    nonce_explicit, ct, tag = body[0:8], body[8:24], body[24:40]
    nonce = bytes.fromhex(civ) + nonce_explicit
    aad = (0).to_bytes(8, "big") + bytes([22]) + b"\x03\x03" + len(ct).to_bytes(2, "big")
    try:
        plain = AESGCM(block[0:16]).decrypt(nonce, ct + tag, aad)
        print("finished plain  :", plain.hex())
    except Exception as exc:  # noqa: BLE001
        print("finished decrypt FAILED:", exc)
    # and with the trace key, to rule out a stale file
    try:
        plain = AESGCM(bytes.fromhex(ck)).decrypt(nonce, ct + tag, aad)
        print("with trace key  :", plain.hex())
    except Exception as exc:  # noqa: BLE001
        print("with trace key FAILED:", exc)
    print("pub:", pub, "pms:", pms)


main()

