/*
 * gcm.c -- AES-GCM (NIST SP 800-38D) for SSH's aes128-gcm@openssh.com / aes256-gcm@openssh.com.
 *
 * Unlike DES's tables (core/des.c), GHASH's GF(2^128) multiplication is not an arbitrary published
 * constant: it is directly the "shift and add" algorithm SP 800-38D itself gives (Algorithm 1), so
 * it belongs with this codebase's other *derived* primitives, not its DES-style exceptions.
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

/* GF(2^128) multiply, NIST SP 800-38D Algorithm 1: Z=0, V=X; for each bit of Y from its MSB to its
 * LSB, Z ^= V whenever that bit is 1, then V is shifted right one bit, XORing in the reduction
 * constant R = 11100001 || 0^120 (0xe1 in the top byte) whenever the bit shifted out was 1. */
static void gf_mul(const u8 X[16], const u8 Y[16], u8 out[16])
{
    u8 Z[16], V[16];
    int i, j, k;
    memset(Z, 0, 16);
    memcpy(V, X, 16);
    for (i = 0; i < 16; i++) {
        for (j = 7; j >= 0; j--) {
            int lsb;
            if ((Y[i] >> j) & 1) xor16(Z, V);
            lsb = V[15] & 1;
            for (k = 15; k > 0; k--) V[k] = (u8)((V[k] >> 1) | ((V[k - 1] & 1) << 7));
            V[0] = (u8)(V[0] >> 1);
            if (lsb) V[0] ^= 0xe1;
        }
    }
    memcpy(out, Z, 16);
}

/* GHASH over the associated data, then the ciphertext (each zero-padded out to a 16-byte
 * boundary), then a final block of their two bit-lengths (SP 800-38D s.6.4). */
static void ghash(const u8 H[16], const u8 *aad, size_t aad_len, const u8 *c, size_t c_len, u8 out[16])
{
    u8 acc[16], block[16];
    size_t off, n;
    memset(acc, 0, 16);
    for (off = 0; off < aad_len; off += 16) {
        n = aad_len - off < 16 ? aad_len - off : 16;
        memset(block, 0, 16);
        memcpy(block, aad + off, n);
        xor16(acc, block);
        gf_mul(acc, H, acc);
    }
    for (off = 0; off < c_len; off += 16) {
        n = c_len - off < 16 ? c_len - off : 16;
        memset(block, 0, 16);
        memcpy(block, c + off, n);
        xor16(acc, block);
        gf_mul(acc, H, acc);
    }
    memset(block, 0, 16);
    STORE64_BE(block, (u64)aad_len * 8);
    STORE64_BE(block + 8, (u64)c_len * 8);
    xor16(acc, block);
    gf_mul(acc, H, acc);
    memcpy(out, acc, 16);
}

void aes_gcm_init(aes_gcm_ctx *c, const u8 *key, int keylen, const u8 iv[GCM_IVLEN])
{
    u8 zero[16];
    memset(zero, 0, 16);
    aes_ctr_init(&c->aesk, key, keylen, zero);   /* round keys only; its ctr/ks/used go unused */
    aes_encrypt_block(&c->aesk, zero, c->H);
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
    ghash(c->H, dst, 4, dst + 4, len, tag);
    aes_encrypt_block(&c->aesk, j0, ek0);
    xor16(tag, ek0);
    memcpy(dst + 4 + len, tag, GCM_TAGLEN);
}

int aes_gcm_open(aes_gcm_ctx *c, u8 *dst, const u8 *src, size_t len)
{
    u8 j0[16], ek0[16], tag[16];
    next_j0(c, j0);
    ghash(c->H, src, 4, src + 4, len, tag);
    aes_encrypt_block(&c->aesk, j0, ek0);
    xor16(tag, ek0);
    if (ssh_ct_memcmp(tag, src + 4 + len, GCM_TAGLEN) != 0) return -1;
    if (dst != src) memcpy(dst, src, 4);
    gctr(&c->aesk, j0, src + 4, dst + 4, len);
    return 0;
}
