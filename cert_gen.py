#!/usr/bin/env python3
"""cert_gen: Self-signed X.509 certificate generator (DER/PEM)."""
import hashlib, os, struct, sys, time, binascii

def _int_to_der(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    result = []
    neg = n < 0
    if neg:
        n = -n - 1
    while n > 0:
        result.append(n & 0xFF)
        n >>= 8
    if neg:
        result = [b ^ 0xFF for b in result]
        if result[-1] < 0x80:
            result.append(0xFF)
    else:
        if result[-1] >= 0x80:
            result.append(0)
    return bytes(reversed(result))

def _der_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    enc = _int_to_der(length)
    return bytes([0x80 | len(enc)]) + enc

def _der_tag(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content

def _der_seq(*items) -> bytes:
    content = b"".join(items)
    return _der_tag(0x30, content)

def _der_int(n: int) -> bytes:
    return _der_tag(0x02, _int_to_der(n))

def _der_oid(oid: str) -> bytes:
    parts = [int(x) for x in oid.split(".")]
    result = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        if p < 128:
            result += bytes([p])
        else:
            enc = []
            while p > 0:
                enc.append(p & 0x7F)
                p >>= 7
            enc.reverse()
            for i in range(len(enc) - 1):
                enc[i] |= 0x80
            result += bytes(enc)
    return _der_tag(0x06, result)

def _der_utf8(s: str) -> bytes:
    return _der_tag(0x0C, s.encode("utf-8"))

def _der_bitstring(data: bytes) -> bytes:
    return _der_tag(0x03, b"\x00" + data)

def _der_utctime(t: float) -> bytes:
    import time as _t
    gm = _t.gmtime(t)
    s = _t.strftime("%y%m%d%H%M%SZ", gm)
    return _der_tag(0x17, s.encode())

def generate_rsa_keypair(bits: int = 512):
    """Tiny RSA for demo (NOT secure)."""
    import random
    def is_prime(n, k=10):
        if n < 2: return False
        if n < 4: return True
        if n % 2 == 0: return False
        d, r = n - 1, 0
        while d % 2 == 0:
            d //= 2; r += 1
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            if x == 1 or x == n - 1: continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1: break
            else:
                return False
        return True
    def gen_prime(bits):
        while True:
            p = random.getrandbits(bits) | (1 << (bits - 1)) | 1
            if is_prime(p): return p
    half = bits // 2
    p, q = gen_prime(half), gen_prime(half)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi)
    return {"n": n, "e": e, "d": d, "p": p, "q": q}

def make_self_signed(cn: str = "localhost", days: int = 365, bits: int = 512) -> dict:
    key = generate_rsa_keypair(bits)
    now = time.time()
    not_before = now
    not_after = now + days * 86400
    # Build TBS
    issuer = _der_seq(_der_seq(_der_oid("2.5.4.3"), _der_utf8(cn)))
    name = _der_tag(0x30, _der_seq(_der_oid("2.5.4.3"), _der_utf8(cn)))
    validity = _der_seq(_der_utctime(not_before), _der_utctime(not_after))
    pub_key_der = _der_seq(_der_int(key["n"]), _der_int(key["e"]))
    spki = _der_seq(_der_seq(_der_oid("1.2.840.113549.1.1.1"), _der_tag(0x05, b"")),
                    _der_bitstring(pub_key_der))
    tbs = _der_seq(
        _der_tag(0xA0, _der_int(2)),  # version 3
        _der_int(int.from_bytes(os.urandom(8), "big")),  # serial
        _der_seq(_der_oid("1.2.840.113549.1.1.11"), _der_tag(0x05, b"")),  # sha256WithRSA
        name, validity, name, spki
    )
    # Sign
    digest = hashlib.sha256(tbs).digest()
    sig_int = pow(int.from_bytes(digest, "big"), key["d"], key["n"])
    sig_bytes = sig_int.to_bytes((key["n"].bit_length() + 7) // 8, "big")
    cert_der = _der_seq(
        tbs,
        _der_seq(_der_oid("1.2.840.113549.1.1.11"), _der_tag(0x05, b"")),
        _der_bitstring(sig_bytes)
    )
    return {"der": cert_der, "key": key, "cn": cn}

def to_pem(der: bytes, label: str = "CERTIFICATE") -> str:
    import base64
    b64 = base64.b64encode(der).decode()
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"

def test():
    result = make_self_signed("test.local", days=30, bits=512)
    assert len(result["der"]) > 100
    pem = to_pem(result["der"])
    assert "BEGIN CERTIFICATE" in pem
    assert "END CERTIFICATE" in pem
    assert result["cn"] == "test.local"
    # Key works
    key = result["key"]
    msg = 42
    enc = pow(msg, key["e"], key["n"])
    dec = pow(enc, key["d"], key["n"])
    assert dec == msg
    print("All tests passed!")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        test()
    else:
        print("Usage: cert_gen.py test")
