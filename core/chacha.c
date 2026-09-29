#include <string.h>
#include "chacha.h"

/* ------------------------------ ChaCha20 ------------------------------ */

/* One quarter round.  The four words are loaded into locals, worked on there and stored back, so a
 * compiler can keep them in registers for the twelve operations instead of going through the x[]
 * array in memory for every += ^= and rotate. */
#define QR(x, a, b, c, d) do { \
    u32 qa = x[a], qb = x[b], qc = x[c], qd = x[d]; \
    qa += qb; qd ^= qa; qd = ROL32(qd, 16); \
    qc += qd; qb ^= qc; qb = ROL32(qb, 12); \
    qa += qb; qd ^= qa; qd = ROL32(qd, 8);  \
    qc += qd; qb ^= qc; qb = ROL32(qb, 7);  \
    x[a] = qa; x[b] = qb; x[c] = qc; x[d] = qd; } while (0)

void chacha_keysetup(chacha_ctx *c, const u8 key[32])
{
    static const char sigma[] = "expand 32-byte k";
    int i;
    for (i = 0; i < 4; i++) c->s[i] = LOAD32_LE((const u8 *)sigma + 4 * i);
    for (i = 0; i < 8; i++) c->s[4 + i] = LOAD32_LE(key + 4 * i);
    c->s[12] = c->s[13] = c->s[14] = c->s[15] = 0;
}

void chacha_ivsetup(chacha_ctx *c, const u8 iv[8], u64 counter)
{
    c->s[12] = (u32)(counter & 0xffffffffUL);
    c->s[13] = (u32)(counter >> 32);
    c->s[14] = LOAD32_LE(iv);
    c->s[15] = LOAD32_LE(iv + 4);
}

/* x = the keystream block for c's current state: twenty rounds, then the state added back in. */
static void chacha_core(const chacha_ctx *c, u32 x[16])
{
    int i;
    memcpy(x, c->s, 16 * sizeof(u32));
    for (i = 0; i < 10; i++) {
        QR(x, 0, 4, 8,  12); QR(x, 1, 5, 9,  13); QR(x, 2, 6, 10, 14); QR(x, 3, 7, 11, 15);
        QR(x, 0, 5, 10, 15); QR(x, 1, 6, 11, 12); QR(x, 2, 7, 8,  13); QR(x, 3, 4, 9,  14);
    }
    for (i = 0; i < 16; i++) x[i] += c->s[i];
}

static int little_endian(void)
{
    u32 one = 1;
    return *(u8 *)&one == 1;
}

/* Whole blocks are XORed straight from the block words into the output: as native 32-bit words when
 * this CPU is little-endian (the keystream is little-endian words) and both buffers are 4-byte
 * aligned, otherwise through LOAD32_LE/STORE32_LE.  in and out may be the same buffer. */
void chacha_xor(chacha_ctx *c, const u8 *in, u8 *out, size_t len)
{
    u32 x[16];
    u8 ks[64];
    size_t i, n;
    int fast = little_endian() && (((size_t)in | (size_t)out) & 3) == 0;

    while (len >= 64) {
        chacha_core(c, x);
        if (++c->s[12] == 0) c->s[13]++;
        if (fast) {
            const u32 *a = (const u32 *)in;
            u32 *o = (u32 *)out;
            for (i = 0; i < 16; i++) o[i] = a[i] ^ x[i];
        } else {
            for (i = 0; i < 16; i++) { u32 v = x[i] ^ LOAD32_LE(in + 4 * i); STORE32_LE(out + 4 * i, v); }
        }
        in += 64; out += 64; len -= 64;
    }
    if (len) {                                     /* the last partial block: through a byte buffer */
        chacha_core(c, x);
        if (++c->s[12] == 0) c->s[13]++;
        for (i = 0; i < 16; i++) STORE32_LE(ks + 4 * i, x[i]);
        for (n = 0; n < len; n++) out[n] = (u8)(in[n] ^ ks[n]);
    }
    ssh_wipe(ks, sizeof(ks));
    ssh_wipe(x, sizeof(x));
}

/* ------------------------------ Poly1305 ------------------------------ */
/* Four 32-bit limbs (radix 2^32) plus h4, the few bits above 2^128, in place of poly1305-donna-32's five
 * 26-bit limbs: 16 full 32x32->64 multiplies per block plus four tiny ones (h4 is at most 6), against
 * 25 full ones.  Multiplies are what a 486, a 68040 and above all a SPARC compiled for V7 (no multiply
 * instruction, so every widening multiply is a library call) are slowest at.
 *
 * The clamp makes r1..r3 multiples of 4, so s_j = 5*r_j/4 = r_j + (r_j >> 2) is exact.  A product
 * h_i*r_j with i + j >= 4 sits at weight 2^(128 + 32(i+j-4)), and 2^130 = 5 (mod p = 2^130 - 5), so it
 * equals h_i*s_j at weight 2^(32(i+j-4)): the reduction costs nothing extra.  The one term that cannot
 * use s is h4*r0 (r0 is not a multiple of 4): with V = h4*r0 = 4*(V >> 2) + (V & 3), the first part
 * folds down as 5*(V >> 2) and the last stays at weight 2^128.  Bounds: r_j < 2^28, s_j < 1.25 * 2^28,
 * h_i < 2^32, h4 <= 6, so every sum of four products is below 2^63 and nothing overflows a u64, and
 * h4*s_j and h4*r0 fit a u32.  After each block h4 is folded back to at most 4. */
typedef struct { u32 r[4], s[4], h[5], pad[4]; } poly_ctx;

static void poly_blocks(poly_ctx *p, const u8 *m, size_t bytes, u32 hibit)
{
    u32 r0 = p->r[0], r1 = p->r[1], r2 = p->r[2], r3 = p->r[3];
    u32 s1 = p->s[1], s2 = p->s[2], s3 = p->s[3];
    u32 h0 = p->h[0], h1 = p->h[1], h2 = p->h[2], h3 = p->h[3], h4 = p->h[4];
    u64 d0 = 0, d1 = 0, d2 = 0, d3 = 0, t = 0;     /* always set before read, every pass of the while loop
                                                    * below; m68k's dataflow analysis can't see that across
                                                    * the loop back-edge */
    u32 v, c;

    while (bytes >= 16) {
        t = (u64)h0 + LOAD32_LE(m);                          h0 = (u32)t;     /* h += m, and hibit above it */
        t = (u64)h1 + LOAD32_LE(m + 4) + (t >> 32);          h1 = (u32)t;
        t = (u64)h2 + LOAD32_LE(m + 8) + (t >> 32);          h2 = (u32)t;
        t = (u64)h3 + LOAD32_LE(m + 12) + (t >> 32);         h3 = (u32)t;
        h4 += (u32)(t >> 32) + hibit;

        d0 = (u64)h0 * r0 + (u64)h1 * s3 + (u64)h2 * s2 + (u64)h3 * s1;
        d1 = (u64)h0 * r1 + (u64)h1 * r0 + (u64)h2 * s3 + (u64)h3 * s2;
        d2 = (u64)h0 * r2 + (u64)h1 * r1 + (u64)h2 * r0 + (u64)h3 * s3;
        d3 = (u64)h0 * r3 + (u64)h1 * r2 + (u64)h2 * r1 + (u64)h3 * r0;
        v = h4 * r0;
        d0 += (v >> 2) * 5;
        d1 += h4 * s1;
        d2 += h4 * s2;
        d3 += h4 * s3;

        c = (u32)(d0 >> 32); h0 = (u32)d0;
        d1 += c; c = (u32)(d1 >> 32); h1 = (u32)d1;
        d2 += c; c = (u32)(d2 >> 32); h2 = (u32)d2;
        d3 += c; c = (u32)(d3 >> 32); h3 = (u32)d3;
        h4 = c + (v & 3);

        c = h4 >> 2; h4 &= 3;                                /* fold what is above 2^130 back in, x5 */
        t = (u64)h0 + c * 5;                 h0 = (u32)t;
        t = (u64)h1 + (t >> 32);             h1 = (u32)t;
        t = (u64)h2 + (t >> 32);             h2 = (u32)t;
        t = (u64)h3 + (t >> 32);             h3 = (u32)t;
        h4 += (u32)(t >> 32);

        m += 16; bytes -= 16;
    }
    p->h[0] = h0; p->h[1] = h1; p->h[2] = h2; p->h[3] = h3; p->h[4] = h4;
}

void poly1305_auth(u8 mac[16], const u8 *msg, size_t len, const u8 key[32])
{
    poly_ctx p;
    u32 h0, h1, h2, h3, h4, g0, g1, g2, g3, g4, q, mask;
    u64 t;
    size_t full = len & ~(size_t)15;
    u8 last[16];
    size_t rem = len - full;
    int i;

    p.r[0] = LOAD32_LE(key)      & 0x0fffffff;            /* the clamp */
    p.r[1] = LOAD32_LE(key + 4)  & 0x0ffffffc;
    p.r[2] = LOAD32_LE(key + 8)  & 0x0ffffffc;
    p.r[3] = LOAD32_LE(key + 12) & 0x0ffffffc;
    p.s[0] = 0;
    for (i = 1; i < 4; i++) p.s[i] = p.r[i] + (p.r[i] >> 2);
    for (i = 0; i < 5; i++) p.h[i] = 0;
    for (i = 0; i < 4; i++) p.pad[i] = LOAD32_LE(key + 16 + 4 * i);

    poly_blocks(&p, msg, full, 1);
    if (rem) {
        memset(last, 0, sizeof(last));
        memcpy(last, msg + full, rem);
        last[rem] = 1;
        poly_blocks(&p, last, 16, 0);
    }

    h0 = p.h[0]; h1 = p.h[1]; h2 = p.h[2]; h3 = p.h[3]; h4 = p.h[4];
    for (i = 0; i < 2; i++) {                             /* h < 2^130 (two folds: the first can carry into h4) */
        q = h4 >> 2; h4 &= 3;
        t = (u64)h0 + q * 5;                 h0 = (u32)t;
        t = (u64)h1 + (t >> 32);             h1 = (u32)t;
        t = (u64)h2 + (t >> 32);             h2 = (u32)t;
        t = (u64)h3 + (t >> 32);             h3 = (u32)t;
        h4 += (u32)(t >> 32);
    }
    t = (u64)h0 + 5;                         g0 = (u32)t;  /* g = h + 5: if that reaches 2^130, h >= p, and h - p is g's low 130 bits */
    t = (u64)h1 + (t >> 32);                 g1 = (u32)t;
    t = (u64)h2 + (t >> 32);                 g2 = (u32)t;
    t = (u64)h3 + (t >> 32);                 g3 = (u32)t;
    g4 = h4 + (u32)(t >> 32);
    mask = 0 - ((g4 >> 2) & 1);            /* all ones if h >= p, else zero */
    h0 = (h0 & ~mask) | (g0 & mask); h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask); h3 = (h3 & ~mask) | (g3 & mask);

    t = (u64)h0 + p.pad[0];                                STORE32_LE(mac, (u32)t);        /* tag = (h + s) mod 2^128 */
    t = (u64)h1 + p.pad[1] + (t >> 32);                    STORE32_LE(mac + 4, (u32)t);
    t = (u64)h2 + p.pad[2] + (t >> 32);                    STORE32_LE(mac + 8, (u32)t);
    t = (u64)h3 + p.pad[3] + (t >> 32);                    STORE32_LE(mac + 12, (u32)t);
    ssh_wipe(&p, sizeof(p));
}

/* --------------------- chacha20-poly1305@openssh.com --------------------- */

void chachapoly_init(chachapoly_ctx *c, const u8 key[CHACHAPOLY_KEYLEN])
{
    chacha_keysetup(&c->main, key);
    chacha_keysetup(&c->header, key + 32);
    c->peek_valid = 0;
}

static void seq_iv(u32 seq, u8 iv[8])
{
    iv[0] = iv[1] = iv[2] = iv[3] = 0;
    STORE32_BE(iv + 4, seq);
}

/* The header key's keystream for one packet, applied to its 4 length bytes: served from the cache
 * when this exact packet (sequence number and encrypted bytes) was the last one decrypted. */
static void header_plain(chachapoly_ctx *c, u32 seq, const u8 enc[4], u8 plain[4])
{
    u8 iv[8];
    if (c->peek_valid && c->peek_seq == seq && memcmp(c->peek_enc, enc, 4) == 0) {
        memcpy(plain, c->peek_plain, 4);
        return;
    }
    seq_iv(seq, iv);
    chacha_ivsetup(&c->header, iv, 0);
    chacha_xor(&c->header, enc, plain, 4);
    c->peek_seq = seq;
    memcpy(c->peek_enc, enc, 4);
    memcpy(c->peek_plain, plain, 4);
    c->peek_valid = 1;
}

u32 chachapoly_peek_length(chachapoly_ctx *c, u32 seq, const u8 enc_len[4])
{
    u8 plain[4];
    header_plain(c, seq, enc_len, plain);
    return LOAD32_BE(plain);
}

void chachapoly_seal(chachapoly_ctx *c, u32 seq, u8 *dst, const u8 *src, size_t len)
{
    u8 iv[8], polykey[32];
    seq_iv(seq, iv);
    memset(polykey, 0, 32);
    chacha_ivsetup(&c->main, iv, 0);
    chacha_xor(&c->main, polykey, polykey, 32);

    chacha_ivsetup(&c->header, iv, 0);
    chacha_xor(&c->header, src, dst, CHACHAPOLY_AADLEN);
    chacha_ivsetup(&c->main, iv, 1);
    chacha_xor(&c->main, src + CHACHAPOLY_AADLEN, dst + CHACHAPOLY_AADLEN, len);
    poly1305_auth(dst + CHACHAPOLY_AADLEN + len, dst, CHACHAPOLY_AADLEN + len, polykey);
    ssh_wipe(polykey, sizeof(polykey));
}

int chachapoly_open(chachapoly_ctx *c, u32 seq, u8 *dst, const u8 *src, size_t len)
{
    u8 iv[8], polykey[32], tag[16];
    int bad;
    seq_iv(seq, iv);
    memset(polykey, 0, 32);
    chacha_ivsetup(&c->main, iv, 0);
    chacha_xor(&c->main, polykey, polykey, 32);

    poly1305_auth(tag, src, CHACHAPOLY_AADLEN + len, polykey);
    bad = ssh_ct_memcmp(tag, src + CHACHAPOLY_AADLEN + len, CHACHAPOLY_TAGLEN);
    ssh_wipe(polykey, sizeof(polykey));
    if (bad) return -1;

    {
        u8 hdr[4];
        header_plain(c, seq, src, hdr);              /* a cache hit when the caller peeked this packet */
        c->peek_valid = 0;                           /* one use per packet: the next has a new sequence number */
        memcpy(dst, hdr, CHACHAPOLY_AADLEN);
    }
    chacha_ivsetup(&c->main, iv, 1);
    chacha_xor(&c->main, src + CHACHAPOLY_AADLEN, dst + CHACHAPOLY_AADLEN, len);
    return 0;
}
