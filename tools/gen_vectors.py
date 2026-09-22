#!/usr/bin/env python3
"""Generate tests/vectors.h from independent reference implementations.

Oracles: hashlib/hmac (SHA-2, HMAC), the openssl CLI (AES-CTR, ChaCha20
keystream), and small big-integer implementations of Poly1305, X25519 and
Ed25519 written straight from RFC 8439 / 7748 / 8032.
"""
import hashlib, hmac, subprocess, struct, sys, ctypes, ctypes.util

def pat(n, seed=0):
    return bytes((i * 7 + 3 + seed) & 0xff for i in range(n))

def carr(name, b):
    body = ", ".join("0x%02x" % x for x in b) if b else "0"
    return "static const u8 %s[%d] = {%s};\n#define %s_LEN %d\n" % (name, max(len(b), 1), body, name, len(b))

# ---------------- Poly1305 (RFC 8439) ----------------
def poly1305(key, msg):
    r = int.from_bytes(key[:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:32], "little")
    P = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        blk = msg[i:i + 16]
        n = int.from_bytes(blk + b"\x01", "little")
        acc = (acc + n) * r % P
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")

# ---------------- X25519 (RFC 7748) ----------------
P25519 = 2**255 - 19
def x25519(k, u):
    k = bytearray(k); k[0] &= 248; k[31] &= 127; k[31] |= 64
    k = int.from_bytes(k, "little")
    u = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x1, x2, z2, x3, z3, swap = u, 1, 0, u, 1, 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        if swap: x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        A = (x2 + z2) % P25519; AA = A * A % P25519
        B = (x2 - z2) % P25519; BB = B * B % P25519
        E = (AA - BB) % P25519
        C = (x3 + z3) % P25519; D = (x3 - z3) % P25519
        DA = D * A % P25519; CB = C * B % P25519
        x3 = (DA + CB) ** 2 % P25519
        z3 = x1 * (DA - CB) ** 2 % P25519
        x2 = AA * BB % P25519
        z2 = E * (AA + 121665 * E) % P25519
    if swap: x2, x3, z2, z3 = x3, x2, z3, z2
    return (x2 * pow(z2, P25519 - 2, P25519) % P25519).to_bytes(32, "little")

# ---------------- Ed25519 (RFC 8032) ----------------
p = P25519
d = -121665 * pow(121666, p - 2, p) % p
q = 2**252 + 27742317777372353535851937790883648493
I = pow(2, (p - 1) // 4, p)

def sha512(s): return hashlib.sha512(s).digest()
def padd(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % p
    C = 2 * P[3] * Q[3] * d % p
    D = 2 * P[2] * Q[2] % p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % p, G * H % p, F * G % p, E * H % p)
def pmul(s, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1: Q = padd(Q, P)
        P = padd(P, P); s >>= 1
    return Q
def pcompress(P):
    zinv = pow(P[2], p - 2, p)
    x, y = P[0] * zinv % p, P[1] * zinv % p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")
def recover_x(y, sign):
    if y >= p: return None
    x2 = (y * y - 1) * pow(d * y * y + 1, p - 2, p) % p
    if x2 == 0: return None if sign else 0
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p: x = x * I % p
    if (x * x - x2) % p: return None
    if (x & 1) != sign: x = p - x
    return x
def pdecompress(s):
    y = int.from_bytes(s, "little"); sign = y >> 255; y &= (1 << 255) - 1
    x = recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % p)
gy = 4 * pow(5, p - 2, p) % p
G = (recover_x(gy, 0), gy, 1, recover_x(gy, 0) * gy % p)
def expand(seed):
    h = sha512(seed); a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8; a |= 1 << 254
    return a, h[32:]
def ed_pub(seed):
    a, _ = expand(seed); return pcompress(pmul(a, G))
def ed_sign(seed, msg):
    a, prefix = expand(seed); A = pcompress(pmul(a, G))
    r = int.from_bytes(sha512(prefix + msg), "little") % q
    R = pcompress(pmul(r, G))
    h = int.from_bytes(sha512(R + A + msg), "little") % q
    return R + int.to_bytes((r + h * a) % q, 32, "little")
def ed_verify(pub, msg, sig):
    A = pdecompress(pub); R = pdecompress(sig[:32])
    if A is None or R is None: return False
    s = int.from_bytes(sig[32:], "little")
    if s >= q: return False
    h = int.from_bytes(sha512(sig[:32] + pub + msg), "little") % q
    sB, hA = pmul(s, G), pmul(h, A)
    R2 = padd(R, hA)
    return (sB[0] * R2[2] - R2[0] * sB[2]) % p == 0 and (sB[1] * R2[2] - R2[1] * sB[2]) % p == 0

# ---------------- openssl helpers ----------------
def openssl_enc(cipher, key, iv, data, decrypt=False):
    # -provider legacy pulls in ciphers OpenSSL 3.x disabled by default (Blowfish, single DES) --
    # harmless to pass for ciphers that don't need it (AES, ChaCha20), so always included.
    args = ["openssl", "enc", "-" + cipher, "-K", key.hex(), "-iv", iv.hex(), "-nopad",
            "-provider", "legacy", "-provider", "default"]
    if decrypt:
        args.append("-d")
    return subprocess.run(args, input=data, capture_output=True, check=True).stdout

# ---------------- AES-GCM, via OpenSSL's libcrypto directly (ctypes) ----------------
# `openssl enc` has no usable support for AEAD ciphers (no way to get/set the tag), so unlike
# every other cipher here it can't be the oracle through the CLI -- this calls its EVP API instead.
def _libcrypto():
    path = ctypes.util.find_library("crypto") or "/opt/homebrew/lib/libcrypto.dylib"
    lc = ctypes.CDLL(path)
    lc.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
    lc.EVP_CIPHER_CTX_new.argtypes = []
    lc.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
    lc.EVP_get_cipherbyname.restype = ctypes.c_void_p
    lc.EVP_get_cipherbyname.argtypes = [ctypes.c_char_p]
    lc.EVP_EncryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    lc.EVP_EncryptInit_ex.restype = ctypes.c_int
    lc.EVP_CIPHER_CTX_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    lc.EVP_CIPHER_CTX_ctrl.restype = ctypes.c_int
    lc.EVP_EncryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int]
    lc.EVP_EncryptUpdate.restype = ctypes.c_int
    lc.EVP_EncryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]
    lc.EVP_EncryptFinal_ex.restype = ctypes.c_int
    return lc

_EVP_CTRL_GCM_SET_IVLEN = 0x9
_EVP_CTRL_GCM_GET_TAG = 0x10

def aes_gcm_seal(key, iv, aad, plaintext):
    """The (ciphertext, tag) OpenSSL's own AES-GCM produces -- independent of this project's
    core/gcm.c, which was checked against this same oracle during development (see its header
    comment) before a single test vector was committed here."""
    lc = _libcrypto()
    ctx = lc.EVP_CIPHER_CTX_new()
    cname = {16: b"aes-128-gcm", 32: b"aes-256-gcm"}[len(key)]
    cipher = lc.EVP_get_cipherbyname(cname)
    assert cipher, "libcrypto has no %r (unexpected -- OpenSSL 1.1+/3.x always does)" % cname
    assert lc.EVP_EncryptInit_ex(ctx, cipher, None, None, None) == 1
    assert lc.EVP_CIPHER_CTX_ctrl(ctx, _EVP_CTRL_GCM_SET_IVLEN, len(iv), None) == 1
    assert lc.EVP_EncryptInit_ex(ctx, None, None, key, iv) == 1
    outlen = ctypes.c_int(0)
    if aad:
        assert lc.EVP_EncryptUpdate(ctx, None, ctypes.byref(outlen), aad, len(aad)) == 1
    ct = ctypes.create_string_buffer(len(plaintext) + 16)
    assert lc.EVP_EncryptUpdate(ctx, ct, ctypes.byref(outlen), plaintext, len(plaintext)) == 1
    clen = outlen.value
    finlen = ctypes.c_int(0)
    assert lc.EVP_EncryptFinal_ex(ctx, ctypes.cast(ctypes.byref(ct, clen), ctypes.c_char_p), ctypes.byref(finlen)) == 1
    clen += finlen.value
    tag = ctypes.create_string_buffer(16)
    assert lc.EVP_CIPHER_CTX_ctrl(ctx, _EVP_CTRL_GCM_GET_TAG, 16, tag) == 1
    lc.EVP_CIPHER_CTX_free(ctx)
    return ct.raw[:clen], tag.raw

def main():
    out = ["/* GENERATED by tools/gen_vectors.py -- do not edit */\n"]

    # SHA-2 / HMAC
    lens = [0, 1, 3, 55, 56, 63, 64, 65, 111, 112, 119, 127, 128, 129, 200, 1000]
    out.append("#define N_SHA %d\nstatic const int sha_lens[N_SHA] = {%s};\n" % (len(lens), ", ".join(map(str, lens))))
    out.append("static const u8 sha256_exp[N_SHA][32] = {\n%s};\n" % "".join(
        "  {%s},\n" % ", ".join("0x%02x" % x for x in hashlib.sha256(pat(n)).digest()) for n in lens))
    out.append("static const u8 sha512_exp[N_SHA][64] = {\n%s};\n" % "".join(
        "  {%s},\n" % ", ".join("0x%02x" % x for x in hashlib.sha512(pat(n)).digest()) for n in lens))
    out.append("static const u8 sha384_exp[N_SHA][48] = {\n%s};\n" % "".join(
        "  {%s},\n" % ", ".join("0x%02x" % x for x in hashlib.sha384(pat(n)).digest()) for n in lens))
    hm = [(5, 40), (32, 0), (64, 1), (131, 77)]
    out.append("#define N_HMAC %d\nstatic const int hmac_klens[N_HMAC] = {%s};\nstatic const int hmac_mlens[N_HMAC] = {%s};\n" % (
        len(hm), ", ".join(str(k) for k, m in hm), ", ".join(str(m) for k, m in hm)))
    out.append("static const u8 hmac256_exp[N_HMAC][32] = {\n%s};\n" % "".join(
        "  {%s},\n" % ", ".join("0x%02x" % x for x in hmac.new(pat(k, 9), pat(m, 5), hashlib.sha256).digest()) for k, m in hm))
    out.append("static const u8 hmac512_exp[N_HMAC][64] = {\n%s};\n" % "".join(
        "  {%s},\n" % ", ".join("0x%02x" % x for x in hmac.new(pat(k, 9), pat(m, 5), hashlib.sha512).digest()) for k, m in hm))
    out.append("static const u8 hmac_md5_exp[N_HMAC][16] = {\n%s};\n" % "".join(
        "  {%s},\n" % ", ".join("0x%02x" % x for x in hmac.new(pat(k, 9), pat(m, 5), hashlib.md5).digest()) for k, m in hm))

    # AES-CTR (128 & 256, with counter carry)
    iv = bytes(range(0xf0, 0x100)) + b"\xff" * 0  # 16 bytes: f0..ff -> carries through low bytes
    iv = bytes(14 * [0x11]) + b"\xff\xfe"
    plain = pat(157, 2)
    k128, k256 = pat(16, 40), pat(32, 50)
    out.append(carr("aes_iv", iv)); out.append(carr("aes_plain", plain))
    out.append(carr("aes_k128", k128)); out.append(carr("aes_k256", k256))
    out.append(carr("aes128_ctr_exp", openssl_enc("aes-128-ctr", k128, iv, plain)))
    out.append(carr("aes256_ctr_exp", openssl_enc("aes-256-ctr", k256, iv, plain)))

    # Blowfish-CBC (SSH's blowfish-cbc: a 16-byte key; OpenSSL's legacy provider is the independent
    # oracle here, since it -- not this project's own blf_encipher/blf_decipher -- computes these).
    bf_iv = pat(8, 60); bf_key = pat(16, 70); bf_plain = pat(40, 80)     # 5 blocks, a multiple of 8
    out.append(carr("bf_iv", bf_iv)); out.append(carr("bf_key", bf_key)); out.append(carr("bf_plain", bf_plain))
    out.append(carr("bf_cbc_exp", openssl_enc("bf-cbc", bf_key, bf_iv, bf_plain)))

    # 3des-cbc (SSH's "3des-cbc": EDE3 with a 24-byte key, three independent 8-byte DES keys).
    # OpenSSL's legacy provider is the independent oracle -- not this project's own from-scratch
    # DES/EDE3 implementation (core/des.c), which is also checked against the official FIPS 46-3
    # known-answer vector directly in tests/test_crypto.c.
    des3_iv = pat(8, 90); des3_key_bytes = pat(24, 95); des3_plain = pat(40, 100)   # 5 blocks
    out.append(carr("des3_iv", des3_iv)); out.append(carr("des3_key_bytes", des3_key_bytes))
    out.append(carr("des3_plain", des3_plain))
    out.append(carr("des3_cbc_exp", openssl_enc("des-ede3-cbc", des3_key_bytes, des3_iv, des3_plain)))

    # aes128-gcm@openssh.com / aes256-gcm@openssh.com. The GCM spec's own published all-zero
    # example (independent of, and older than, this project) as a sanity check on the oracle
    # wrapper itself, before trusting it to grade core/gcm.c.
    ct0, tag0 = aes_gcm_seal(bytes(16), bytes(12), b"", bytes(16))
    assert ct0.hex() == "0388dace60b6a392f328c2b971b2fe78" and tag0.hex() == "ab6e47d42cec13bdf53a67b21257bddf"
    gcm_lens = [0, 1, 15, 16, 17, 31, 32, 100, 300]
    gcm_plain = pat(300, 180)             # one fixed pattern; each length case uses its first n bytes
    out.append("#define N_GCM %d\nstatic const int gcm_lens[N_GCM] = {%s};\n" % (
        len(gcm_lens), ", ".join(map(str, gcm_lens))))
    out.append(carr("gcm_plain", gcm_plain))
    for tag, keylen in (("128", 16), ("256", 32)):
        key = pat(keylen, 150 if keylen == 16 else 160)
        iv = pat(12, 170)
        out.append(carr("gcm%s_key" % tag, key)); out.append(carr("gcm%s_iv" % tag, iv))
        cts, tags = [], []
        for n in gcm_lens:
            plain = gcm_plain[:n]
            aad = struct.pack(">I", n)          # SSH's AAD is always the cleartext 4-byte length field
            ct, tg = aes_gcm_seal(key, iv, aad, plain)
            cts.append(ct); tags.append(tg)
        out.append("static const u8 gcm%s_ct_exp[N_GCM][300] = {\n%s};\n" % (tag, "".join(
            "  {%s},\n" % ", ".join("0x%02x" % b for b in (c + bytes(300 - len(c)))) for c in cts)))
        out.append("static const u8 gcm%s_tag_exp[N_GCM][16] = {\n%s};\n" % (tag, "".join(
            "  {%s},\n" % ", ".join("0x%02x" % b for b in t) for t in tags)))

    # ChaCha20 (OpenSSH layout: 64-bit counter, 64-bit nonce)
    ck = pat(32, 100); civ = bytes([0, 0, 0, 0, 0, 0, 0x12, 0x34])
    ctr = 1
    ivfull = struct.pack("<Q", ctr) + civ
    ks = openssl_enc("chacha20", ck, ivfull, bytes(300))
    out.append(carr("chacha_key", ck)); out.append(carr("chacha_iv", civ)); out.append(carr("chacha_ks_exp", ks))

    # Poly1305
    rfc_key = bytes.fromhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
    rfc_msg = b"Cryptographic Forum Research Group"
    assert poly1305(rfc_key, rfc_msg).hex() == "a8061dc1305136c6c22b8baf0c0127a9"
    out.append(carr("poly_key", rfc_key)); out.append(carr("poly_msg", rfc_msg))
    out.append(carr("poly_exp", poly1305(rfc_key, rfc_msg)))
    pl = [0, 1, 15, 16, 17, 31, 32, 33, 64, 100, 257]
    pk2 = pat(32, 200)
    out.append("#define N_POLY %d\nstatic const int poly_lens[N_POLY] = {%s};\n" % (len(pl), ", ".join(map(str, pl))))
    out.append(carr("poly_key2", pk2))
    out.append("static const u8 poly_exp2[N_POLY][16] = {\n%s};\n" % "".join(
        "  {%s},\n" % ", ".join("0x%02x" % x for x in poly1305(pk2, pat(n, 3))) for n in pl))

    # chacha20-poly1305@openssh.com packet, built independently
    cpkey = pat(64, 130); seq = 0x01020304
    pt = struct.pack(">I", 29) + pat(29, 60)         # length || payload
    iv8 = struct.pack(">Q", seq)
    polykey = openssl_enc("chacha20", cpkey[:32], struct.pack("<Q", 0) + iv8, bytes(32))
    enc_len = bytes(a ^ b for a, b in zip(pt[:4], openssl_enc("chacha20", cpkey[32:], struct.pack("<Q", 0) + iv8, bytes(4))))
    enc_body = bytes(a ^ b for a, b in zip(pt[4:], openssl_enc("chacha20", cpkey[:32], struct.pack("<Q", 1) + iv8, bytes(29))))
    sealed = enc_len + enc_body
    sealed += poly1305(polykey, sealed)
    out.append("#define CP_SEQ 0x%08xUL\n" % seq)
    out.append(carr("cp_key", cpkey)); out.append(carr("cp_plain", pt)); out.append(carr("cp_sealed", sealed))

    # X25519
    rfc_a = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    rfc_u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
    assert x25519(rfc_a, rfc_u).hex() == "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
    alice = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    bob = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    nine = bytes([9]) + bytes(31)
    assert x25519(alice, nine).hex() == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    shared = x25519(alice, x25519(bob, nine))
    assert shared.hex() == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    out.append(carr("x_a", rfc_a)); out.append(carr("x_u", rfc_u)); out.append(carr("x_exp", x25519(rfc_a, rfc_u)))
    out.append(carr("x_alice", alice)); out.append(carr("x_bob", bob)); out.append(carr("x_shared", shared))
    rs = [(pat(32, 11 * i + 1), pat(32, 13 * i + 5)) for i in range(4)]
    out.append("#define N_X %d\n" % len(rs))
    out.append("static const u8 x_sc[N_X][32] = {\n%s};\n" % "".join("  {%s},\n" % ", ".join("0x%02x" % b for b in s) for s, u in rs))
    out.append("static const u8 x_pt[N_X][32] = {\n%s};\n" % "".join("  {%s},\n" % ", ".join("0x%02x" % b for b in u) for s, u in rs))
    out.append("static const u8 x_out[N_X][32] = {\n%s};\n" % "".join("  {%s},\n" % ", ".join("0x%02x" % b for b in x25519(s, u)) for s, u in rs))

    # Ed25519
    seed1 = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    assert ed_pub(seed1).hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    assert ed_sign(seed1, b"").hex() == ("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
                                         "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    cases = [(seed1, 0), (pat(32, 3), 1), (pat(32, 9), 72), (pat(32, 21), 300)]
    out.append("#define N_ED %d\nstatic const int ed_mlens[N_ED] = {%s};\n" % (len(cases), ", ".join(str(m) for s, m in cases)))
    out.append("static const u8 ed_seed[N_ED][32] = {\n%s};\n" % "".join("  {%s},\n" % ", ".join("0x%02x" % b for b in s) for s, m in cases))
    out.append("static const u8 ed_pub_exp[N_ED][32] = {\n%s};\n" % "".join("  {%s},\n" % ", ".join("0x%02x" % b for b in ed_pub(s)) for s, m in cases))
    out.append("static const u8 ed_sig_exp[N_ED][64] = {\n%s};\n" % "".join("  {%s},\n" % ", ".join("0x%02x" % b for b in ed_sign(s, pat(m, 17))) for s, m in cases))
    for s, m in cases:
        assert ed_verify(ed_pub(s), pat(m, 17), ed_sign(s, pat(m, 17)))


    # SHA-1 / HMAC-SHA1 / hashed known_hosts line
    import base64
    out.append("static const u8 sha1_exp[N_SHA][20] = {\n%s};\n" % "".join(
        "  {%s},\n" % ", ".join("0x%02x" % x for x in hashlib.sha1(pat(n)).digest()) for n in lens))
    out.append("static const u8 hmac1_exp[N_HMAC][20] = {\n%s};\n" % "".join(
        "  {%s},\n" % ", ".join("0x%02x" % x for x in hmac.new(pat(k, 9), pat(m, 5), hashlib.sha1).digest()) for k, m in hm))
    out.append("static const u8 md5_exp[N_SHA][16] = {\n%s};\n" % "".join(
        "  {%s},\n" % ", ".join("0x%02x" % x for x in hashlib.md5(pat(n)).digest()) for n in lens))
    salt = pat(20, 77)
    hh = hmac.new(salt, b"secret.example.org", hashlib.sha1).digest()
    hashed = "|1|%s|%s" % (base64.b64encode(salt).decode(), base64.b64encode(hh).decode())
    out.append('static const char kh_hashed_token[] = "%s";\n' % hashed)

    open("tests/vectors.h", "w").write("\n".join(out))
    print("wrote tests/vectors.h")

main()
