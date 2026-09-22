#include <string.h>
#include "hmac.h"

void hmac_init(hmac_ctx *h, int kind, const u8 *key, size_t keylen)
{
    u8 k[SHA512_BLOCK], pad[SHA512_BLOCK];
    size_t block = kind == HMAC_SHA512 ? SHA512_BLOCK : SHA256_BLOCK;      /* SHA-1 and SHA-256 both use 64 */
    size_t i;

    h->kind = kind;
    memset(k, 0, sizeof(k));
    if (keylen > block) {
        if (kind == HMAC_SHA512) sha512(key, keylen, k);
        else if (kind == HMAC_SHA1) { sha1_ctx t; sha1_init(&t); sha1_update(&t, key, keylen); sha1_final(&t, k); }
        else sha256(key, keylen, k);
    } else {
        memcpy(k, key, keylen);
    }
    for (i = 0; i < block; i++) pad[i] = (u8)(k[i] ^ 0x36);
    if (kind == HMAC_SHA512) { sha512_init(&h->inner.s512); sha512_update(&h->inner.s512, pad, block); }
    else if (kind == HMAC_SHA1) { sha1_init(&h->inner.s1); sha1_update(&h->inner.s1, pad, block); }
    else { sha256_init(&h->inner.s256); sha256_update(&h->inner.s256, pad, block); }
    for (i = 0; i < block; i++) pad[i] = (u8)(k[i] ^ 0x5c);
    if (kind == HMAC_SHA512) { sha512_init(&h->outer.s512); sha512_update(&h->outer.s512, pad, block); }
    else if (kind == HMAC_SHA1) { sha1_init(&h->outer.s1); sha1_update(&h->outer.s1, pad, block); }
    else { sha256_init(&h->outer.s256); sha256_update(&h->outer.s256, pad, block); }
    ssh_wipe(k, sizeof(k));
    ssh_wipe(pad, sizeof(pad));
}

void hmac_update(hmac_ctx *h, const void *data, size_t len)
{
    if (h->kind == HMAC_SHA512) sha512_update(&h->inner.s512, data, len);
    else if (h->kind == HMAC_SHA1) sha1_update(&h->inner.s1, data, len);
    else sha256_update(&h->inner.s256, data, len);
}

void hmac_final(hmac_ctx *h, u8 *out)
{
    u8 in[SHA512_DIGEST];
    if (h->kind == HMAC_SHA512) {
        sha512_final(&h->inner.s512, in);
        sha512_update(&h->outer.s512, in, SHA512_DIGEST);
        sha512_final(&h->outer.s512, out);
    } else if (h->kind == HMAC_SHA1) {
        sha1_final(&h->inner.s1, in);
        sha1_update(&h->outer.s1, in, 20);
        sha1_final(&h->outer.s1, out);
    } else {
        sha256_final(&h->inner.s256, in);
        sha256_update(&h->outer.s256, in, SHA256_DIGEST);
        sha256_final(&h->outer.s256, out);
    }
    ssh_wipe(in, sizeof(in));
}

void hmac_sha256(const u8 *key, size_t klen, const void *data, size_t len, u8 out[32])
{
    hmac_ctx h;
    hmac_init(&h, HMAC_SHA256, key, klen);
    hmac_update(&h, data, len);
    hmac_final(&h, out);
}
