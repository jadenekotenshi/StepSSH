/*
 * gcm.c -- AES-GCM (NIST SP 800-38D) for SSH's aes128-gcm@openssh.com / aes256-gcm@openssh.com.
 *
 * Unlike DES's tables (core/des.c), GHASH's GF(2^128) multiplication is not an arbitrary published
 * constant: it is derived from the "shift and add" algorithm SP 800-38D itself gives (Algorithm 1) --
 * the multiply-by-H tables below are built at init from that definition -- so it belongs with this
 * codebase's other *derived* primitives, not its DES-style exceptions.
 *
 * Verified against an independent oracle -- OpenSSL's own EVP AES-GCM, called directly via ctypes
 * (the `openssl enc` CLI has no usable tag support for AEAD ciphers) -- for many random vectors
 * across both key sizes and a range of AAD/plaintext lengths (tools/gen_vectors.py), and against
 * the Galois/Counter Mode specification's own published all-zero test case as a sanity check
 * while that oracle wrapper was being written.
 */
#include <string.h>
#include "gcm.h"

static void xor16(u8 *a, const u8 *b)
{
    int i;
    for (i = 0; i < 16; i++) a[i] ^= b[i];
}

/* GHASH multiplies by the fixed hash subkey H once per 16 bytes.  NIST SP 800-38D's Algorithm 1
 * does that one bit at a time (128 iterations of a 16-byte XOR and a 16-byte shift per block), which
 * made AES-GCM about 10x slower than AES-CTR.  This is the same multiplication done a nibble at a
 * time ("Shoup's 4-bit tables"): 16 precomputed multiples of H, and 16 precomputed reductions for the
 * four bits shifted out of the bottom on each step.  Both tables are derived here from the spec's own
 * definition -- multiplying by x is "shift right one bit, and XOR R = 11100001 || 0^120 into the top
 * whenever the bit shifted out was 1" -- so nothing below is a hand-typed constant.  A 128-bit value
 * is four big-endian words, v[0] holding the first four bytes. */
static void gf_mulx(u32 v[4])
{
    u32 lsb = v[3] & 1;
    v[3] = (v[2] << 31) | (v[3] >> 1);
    v[2] = (v[1] << 31) | (v[2] >> 1);
    v[1] = (v[0] << 31) | (v[1] >> 1);
    v[0] = (v[0] >> 1) ^ (lsb ? 0xe1000000UL : 0);
}

/* Nibble n's bits, MSB first, are the coefficients of x^0..x^3 (SP 800-38D's bit order), so the
 * entry for the single-bit nibbles 8, 4, 2, 1 is H*x^0, H*x^1, H*x^2, H*x^3 and every other entry
 * is the XOR of those it is made of. */
static void ghash_tables(aes_gcm_ctx *c)
{
    u32 v[4];
    int i, j, k, r;

    for (k = 0; k < 4; k++) { c->ht[0][k] = 0; v[k] = LOAD32_BE(c->H + 4 * k); }
    for (k = 0; k < 4; k++) c->ht[8][k] = v[k];
    for (i = 4; i > 0; i >>= 1) {
        gf_mulx(v);
        for (k = 0; k < 4; k++) c->ht[i][k] = v[k];
    }
    for (i = 2; i <= 8; i <<= 1)
        for (j = 1; j < i; j++)
            for (k = 0; k < 4; k++) c->ht[i + j][k] = c->ht[i][k] ^ c->ht[j][k];

    for (r = 0; r < 16; r++) {                       /* shift the four bits of r out through x^-4 */
        v[0] = v[1] = v[2] = 0;
        v[3] = (u32)r;
        for (i = 0; i < 4; i++) gf_mulx(v);
        c->last4[r] = v[0];
    }
}

/* x = x * H (x is one 16-byte block).  Bytes are consumed last to first, low nibble before high. */
static void gmult(const aes_gcm_ctx *c, u8 x[16])
{
    u32 z0, z1, z2, z3;
    unsigned lo, hi, rem;
    int i;

    lo = x[15] & 0xf;
    z0 = c->ht[lo][0]; z1 = c->ht[lo][1]; z2 = c->ht[lo][2]; z3 = c->ht[lo][3];
    for (i = 15; i >= 0; i--) {
        lo = x[i] & 0xf;
        hi = (unsigned)x[i] >> 4;
        if (i != 15) {
            rem = z3 & 0xf;
            z3 = (z2 << 28) | (z3 >> 4); z2 = (z1 << 28) | (z2 >> 4);
            z1 = (z0 << 28) | (z1 >> 4); z0 = (z0 >> 4) ^ c->last4[rem];
            z0 ^= c->ht[lo][0]; z1 ^= c->ht[lo][1]; z2 ^= c->ht[lo][2]; z3 ^= c->ht[lo][3];
        }
        rem = z3 & 0xf;
        z3 = (z2 << 28) | (z3 >> 4); z2 = (z1 << 28) | (z2 >> 4);
        z1 = (z0 << 28) | (z1 >> 4); z0 = (z0 >> 4) ^ c->last4[rem];
        z0 ^= c->ht[hi][0]; z1 ^= c->ht[hi][1]; z2 ^= c->ht[hi][2]; z3 ^= c->ht[hi][3];
    }
    STORE32_BE(x, z0); STORE32_BE(x + 4, z1); STORE32_BE(x + 8, z2); STORE32_BE(x + 12, z3);
}

/* acc = (acc ^ data) * H over `len` bytes, the last block zero-padded (SP 800-38D s.6.4). */
static void ghash_absorb(const aes_gcm_ctx *c, u8 acc[16], const u8 *data, size_t len)
{
    size_t off, n, i;
    for (off = 0; off < len; off += 16) {
        n = len - off < 16 ? len - off : 16;
        for (i = 0; i < n; i++) acc[i] ^= data[off + i];
        gmult(c, acc);
    }
}

/* GHASH over the associated data, then the ciphertext (each zero-padded out to a 16-byte
 * boundary), then a final block of their two bit-lengths. */
static void ghash(const aes_gcm_ctx *c, const u8 *aad, size_t aad_len, const u8 *ct, size_t c_len, u8 out[16])
{
    u8 acc[16], block[16];
    memset(acc, 0, 16);
    ghash_absorb(c, acc, aad, aad_len);
    ghash_absorb(c, acc, ct, c_len);
    STORE64_BE(block, (u64)aad_len * 8);
    STORE64_BE(block + 8, (u64)c_len * 8);
    ghash_absorb(c, acc, block, 16);
    memcpy(out, acc, 16);
}

void aes_gcm_init(aes_gcm_ctx *c, const u8 *key, int keylen, const u8 iv[GCM_IVLEN])
{
    u8 zero[16];
    memset(zero, 0, 16);
    aes_ctr_init(&c->aesk, key, keylen, zero);   /* round keys only; its ctr/ks/used go unused */
    aes_encrypt_block(&c->aesk, zero, c->H);
    ghash_tables(c);
    memcpy(c->fixed, iv, 4);
    c->invocation = LOAD64_BE(iv + 4);
}

/* J0 = (the 12-byte nonce for this packet) || 0x00000001 (SP 800-38D s.7.1, 96-bit-IV case), and
 * the invocation counter half of the nonce advances once per call, per RFC 5647. */
static void next_j0(aes_gcm_ctx *c, u8 j0[16])
{
    memcpy(j0, c->fixed, 4);
    STORE64_BE(j0 + 4, c->invocation);
    c->invocation++;
    STORE32_BE(j0 + 12, 1);
}

/* GCTR: XOR len bytes with the AES-CTR keystream generated from J0+1, J0+2, ... (SP 800-38D
 * s.6.5) -- the same operation encrypts (in = plaintext) or decrypts (in = ciphertext). Only the
 * low 32 bits of the counter block increment, wrapping mod 2^32 as the spec requires. */
static void gctr(const aes_ctr_ctx *aesk, const u8 j0[16], const u8 *in, u8 *out, size_t len)
{
    u8 ctr[16], ks[16];
    size_t off, i, n;
    memcpy(ctr, j0, 16);
    for (off = 0; off < len; off += 16) {
        n = len - off < 16 ? len - off : 16;
        STORE32_BE(ctr + 12, LOAD32_BE(ctr + 12) + 1);
        aes_encrypt_block(aesk, ctr, ks);
        for (i = 0; i < n; i++) out[off + i] = (u8)(in[off + i] ^ ks[i]);
    }
}

void aes_gcm_seal(aes_gcm_ctx *c, u8 *dst, const u8 *src, size_t len)
{
    u8 j0[16], ek0[16], tag[16];
    if (dst != src) memcpy(dst, src, 4);       /* the length field: authenticated, not encrypted */
    next_j0(c, j0);
    gctr(&c->aesk, j0, src + 4, dst + 4, len);
    ghash(c, dst, 4, dst + 4, len, tag);
    aes_encrypt_block(&c->aesk, j0, ek0);
    xor16(tag, ek0);
    memcpy(dst + 4 + len, tag, GCM_TAGLEN);
}

int aes_gcm_open(aes_gcm_ctx *c, u8 *dst, const u8 *src, size_t len)
{
    u8 j0[16], ek0[16], tag[16];
    next_j0(c, j0);
    ghash(c, src, 4, src + 4, len, tag);
    aes_encrypt_block(&c->aesk, j0, ek0);
    xor16(tag, ek0);
    if (ssh_ct_memcmp(tag, src + 4 + len, GCM_TAGLEN) != 0) return -1;
    if (dst != src) memcpy(dst, src, 4);
    gctr(&c->aesk, j0, src + 4, dst + 4, len);
    return 0;
}
