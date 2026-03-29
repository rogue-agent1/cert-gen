#!/usr/bin/env python3
"""cert_gen - Self-signed X.509 certificate generator (pure Python, no deps)."""
import hashlib, os, sys, struct, base64, datetime, argparse

def int_to_bytes(n):
    if n == 0: return b"\x00"
    bs = []
    while n > 0:
        bs.append(n & 0xff)
        n >>= 8
    return bytes(reversed(bs))

def der_length(n):
    if n < 0x80: return bytes([n])
    b = int_to_bytes(n)
    return bytes([0x80 | len(b)]) + b

def der_tag(tag, content):
    return bytes([tag]) + der_length(len(content)) + content

def der_int(n):
    b = int_to_bytes(n)
    if b[0] & 0x80: b = b"\x00" + b
    return der_tag(0x02, b)

def der_seq(*items):
    return der_tag(0x30, b"".join(items))

def der_oid(oid_bytes):
    return der_tag(0x06, oid_bytes)

def der_utf8(s):
    return der_tag(0x0c, s.encode())

def der_bitstring(content):
    return der_tag(0x03, b"\x00" + content)

def der_utctime(dt):
    s = dt.strftime("%y%m%d%H%M%SZ").encode()
    return der_tag(0x17, s)

def simple_rsa_keygen(bits=2048):
    """Generate RSA keypair (simplified - uses random primes for demo)."""
    import random
    def is_prime(n, k=10):
        if n < 2: return False
        if n < 4: return True
        if n % 2 == 0: return False
        d, r = n - 1, 0
        while d % 2 == 0: d //= 2; r += 1
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            if x == 1 or x == n - 1: continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1: break
            else: return False
        return True
    def gen_prime(bits):
        while True:
            n = random.getrandbits(bits) | (1 << (bits-1)) | 1
            if is_prime(n): return n
    half = bits // 2
    p, q = gen_prime(half), gen_prime(half)
    n = p * q
    e = 65537
    phi = (p-1)*(q-1)
    d = pow(e, -1, phi)
    return {"n":n,"e":e,"d":d,"p":p,"q":q}

def make_cert(cn="localhost", days=365, bits=2048):
    key = simple_rsa_keygen(bits)
    now = datetime.datetime.utcnow()
    exp = now + datetime.timedelta(days=days)
    sha256_oid = b"\x60\x86\x48\x01\x65\x03\x04\x02\x01"
    rsa_oid = b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"
    rsa_sha256_oid = b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b"
    cn_oid = b"\x55\x04\x03"
    name = der_seq(der_seq(der_tag(0x31, der_seq(der_oid(cn_oid), der_utf8(cn)))))
    pub_key = der_seq(der_int(key["n"]), der_int(key["e"]))
    pub_info = der_seq(der_seq(der_oid(rsa_oid), der_tag(0x05, b"")), der_bitstring(pub_key))
    serial = der_int(int.from_bytes(os.urandom(8), "big"))
    algo = der_seq(der_oid(rsa_sha256_oid), der_tag(0x05, b""))
    validity = der_seq(der_utctime(now), der_utctime(exp))
    tbs = der_seq(der_tag(0xa0, der_int(2)[2:]), serial, algo, name, validity, name, pub_info)
    digest = hashlib.sha256(tbs).digest()
    sig_int = pow(int.from_bytes(digest, "big"), key["d"], key["n"])
    sig = int_to_bytes(sig_int)
    cert = der_seq(tbs, algo, der_bitstring(sig))
    pem_cert = "-----BEGIN CERTIFICATE-----\n"
    b64 = base64.b64encode(cert).decode()
    for i in range(0, len(b64), 64):
        pem_cert += b64[i:i+64] + "\n"
    pem_cert += "-----END CERTIFICATE-----\n"
    priv = der_seq(der_int(0), der_int(key["n"]), der_int(key["e"]), der_int(key["d"]),
                   der_int(key["p"]), der_int(key["q"]),
                   der_int(key["d"]%(key["p"]-1)), der_int(key["d"]%(key["q"]-1)),
                   der_int(pow(key["q"],-1,key["p"])))
    pem_key = "-----BEGIN RSA PRIVATE KEY-----\n"
    b64k = base64.b64encode(priv).decode()
    for i in range(0, len(b64k), 64):
        pem_key += b64k[i:i+64] + "\n"
    pem_key += "-----END RSA PRIVATE KEY-----\n"
    return pem_cert, pem_key

def main():
    p = argparse.ArgumentParser(description="Self-signed certificate generator")
    p.add_argument("--cn", default="localhost", help="Common Name")
    p.add_argument("--days", type=int, default=365)
    p.add_argument("--bits", type=int, default=2048)
    p.add_argument("--out-cert", default="cert.pem")
    p.add_argument("--out-key", default="key.pem")
    args = p.parse_args()
    cert, key = make_cert(args.cn, args.days, args.bits)
    with open(args.out_cert, "w") as f: f.write(cert)
    with open(args.out_key, "w") as f: f.write(key)
    os.chmod(args.out_key, 0o600)
    print(f"Certificate: {args.out_cert}")
    print(f"Private key: {args.out_key}")

if __name__ == "__main__":
    main()
