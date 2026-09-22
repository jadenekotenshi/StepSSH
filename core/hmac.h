#ifndef SSH_HMAC_H
#define SSH_HMAC_H
#include "sha2.h"
#include "sha1.h"

/* HMAC with SHA-256 or SHA-512, incremental so the transport can MAC
 * "seqno || packet" without concatenating. */
#define HMAC_SHA256 0
#define HMAC_SHA512 1
#define HMAC_SHA1   2                          /* legacy: for old servers only */

typedef struct {
    int kind;
    union { sha256_ctx s256; sha512_ctx s512; sha1_ctx s1; } inner, outer;
} hmac_ctx;

void hmac_init(hmac_ctx *h, int kind, const u8 *key, size_t keylen);
void hmac_update(hmac_ctx *h, const void *data, size_t len);
void hmac_final(hmac_ctx *h, u8 *out);        /* 32, 64 or 20 bytes */
void hmac_sha256(const u8 *key, size_t klen, const void *data, size_t len, u8 out[32]);

#endif
