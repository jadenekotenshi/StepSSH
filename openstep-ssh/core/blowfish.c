#include "blowfish.h"
#include "blowfish_tab.h"

#define BLF_F(c, x) \
    (((((c)->S[0][(x) >> 24] + (c)->S[1][((x) >> 16) & 0xff]) & 0xffffffffUL) \
      ^ (c)->S[2][((x) >> 8) & 0xff]) + (c)->S[3][(x) & 0xff])

void blf_initstate(blf_ctx *c)
{
    int i, j;
    for (i = 0; i < 18; i++) c->P[i] = BLF_PI[i];
    for (i = 0; i < 4; i++)
        for (j = 0; j < 256; j++) c->S[i][j] = BLF_PI[18 + 256 * i + j];
}

void blf_encipher(const blf_ctx *c, u32 *xl, u32 *xr)
{
    u32 l = *xl, r = *xr;
    int i;
    l ^= c->P[0];
    for (i = 1; i <= 16; i += 2) {
        r ^= (BLF_F(c, l) & 0xffffffffUL) ^ c->P[i];
        l ^= (BLF_F(c, r) & 0xffffffffUL) ^ c->P[i + 1];
    }
    *xl = r ^ c->P[17];
    *xr = l;
}

/* Next big-endian 32-bit word from `data`, wrapping around at its end. */
static u32 stream2word(const u8 *data, size_t len, size_t *pos)
{
    u32 w = 0;
    int i;
    for (i = 0; i < 4; i++) {
        if (*pos >= len) *pos = 0;
        w = (w << 8) | data[*pos];
        (*pos)++;
    }
    return w;
}

void blf_expandstate(blf_ctx *c, const u8 *data, size_t dlen, const u8 *key, size_t klen)
{
    size_t j = 0;
    u32 l = 0, r = 0;
    int i, k;

    for (i = 0; i < 18; i++) c->P[i] ^= stream2word(key, klen, &j);
    j = 0;
    for (i = 0; i < 18; i += 2) {
        l ^= stream2word(data, dlen, &j);
        r ^= stream2word(data, dlen, &j);
        blf_encipher(c, &l, &r);
        c->P[i] = l; c->P[i + 1] = r;
    }
    for (i = 0; i < 4; i++)
        for (k = 0; k < 256; k += 2) {
            l ^= stream2word(data, dlen, &j);
            r ^= stream2word(data, dlen, &j);
            blf_encipher(c, &l, &r);
            c->S[i][k] = l; c->S[i][k + 1] = r;
        }
}

void blf_expand0state(blf_ctx *c, const u8 *key, size_t klen)
{
    size_t j = 0;
    u32 l = 0, r = 0;
    int i, k;

    for (i = 0; i < 18; i++) c->P[i] ^= stream2word(key, klen, &j);
    for (i = 0; i < 18; i += 2) {
        blf_encipher(c, &l, &r);
        c->P[i] = l; c->P[i + 1] = r;
    }
    for (i = 0; i < 4; i++)
        for (k = 0; k < 256; k += 2) {
            blf_encipher(c, &l, &r);
            c->S[i][k] = l; c->S[i][k + 1] = r;
        }
}

void blf_key(blf_ctx *c, const u8 *key, size_t klen)
{
    blf_initstate(c);
    blf_expand0state(c, key, klen);
}
