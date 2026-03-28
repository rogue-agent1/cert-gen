#!/usr/bin/env python3
"""cert_gen - Generate self-signed X.509 certificates (simplified DER)."""
import argparse, hashlib, os, struct, sys, time

def der_len(n):
    if n < 0x80: return bytes([n])
    elif n < 0x100: return bytes([0x81, n])
    else: return bytes([0x82, n >> 8, n & 0xFF])

def der_seq(contents):
    data = b"".join(contents)
    return bytes([0x30]) + der_len(len(data)) + data

def der_int(n):
    if isinstance(n, int):
        h = format(n, "x")
        if len(h) % 2: h = "0" + h
        b = bytes.fromhex(h)
        if b[0] & 0x80: b = b"\x00" + b
    else: b = n
    return bytes([0x02]) + der_len(len(b)) + b

def der_bitstring(data):
    return bytes([0x03]) + der_len(len(data)+1) + b"\x00" + data

def der_utf8(s):
    b = s.encode()
    return bytes([0x0C]) + der_len(len(b)) + b

def der_oid(oid_bytes):
    return bytes([0x06]) + der_len(len(oid_bytes)) + oid_bytes

def der_set(contents):
    data = b"".join(contents)
    return bytes([0x31]) + der_len(len(data)) + data

def make_cn(cn):
    # OID 2.5.4.3 = 55 04 03
    oid = der_oid(bytes([0x55, 0x04, 0x03]))
    val = der_utf8(cn)
    return der_set([der_seq([oid, val])])

def main():
    p = argparse.ArgumentParser(description="Self-signed cert generator")
    p.add_argument("-cn","--common-name", default="localhost")
    p.add_argument("-o","--output", default="cert.der")
    p.add_argument("-d","--days", type=int, default=365)
    a = p.parse_args()
    serial = int.from_bytes(os.urandom(8), "big")
    # Simplified: just the structure, not cryptographically valid
    issuer = der_seq([make_cn(a.common_name)])
    subject = der_seq([make_cn(a.common_name)])
    # Validity (UTCTime)
    now = time.strftime("%y%m%d%H%M%SZ", time.gmtime()).encode()
    later = time.strftime("%y%m%d%H%M%SZ", time.gmtime(time.time() + a.days*86400)).encode()
    validity = der_seq([bytes([0x17]) + der_len(len(now)) + now,
                        bytes([0x17]) + der_len(len(later)) + later])
    # RSA OID 1.2.840.113549.1.1.1
    algo = der_seq([der_oid(bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])), bytes([0x05, 0x00])])
    # Fake public key (demo only)
    fake_key = os.urandom(128)
    pubkey_info = der_seq([algo, der_bitstring(der_seq([der_int(fake_key), der_int(65537)]))])
    tbs = der_seq([
        bytes([0xA0, 0x03, 0x02, 0x01, 0x02]),  # version v3
        der_int(serial), algo, issuer, validity, subject, pubkey_info
    ])
    # SHA-256 with RSA OID
    sig_algo = der_seq([der_oid(bytes([0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0B])), bytes([0x05,0x00])])
    sig = der_bitstring(hashlib.sha256(tbs).digest())
    cert = der_seq([tbs, sig_algo, sig])
    with open(a.output, "wb") as f: f.write(cert)
    print(f"Wrote {a.output} ({len(cert)} bytes)")
    print(f"CN: {a.common_name}")
    print(f"Serial: {serial:016x}")
    print(f"Note: Demo certificate, not cryptographically valid")

if __name__ == "__main__": main()
