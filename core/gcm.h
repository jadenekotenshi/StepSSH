#ifndef SSH_GCM_H
#define SSH_GCM_H
#include "ssh_types.h"
#include "aes.h"

/* AES-GCM for SSH's aes128-gcm@openssh.com / aes256-gcm@openssh.com (RFC 5647).  Unlike
 * chacha20-poly1305 (whose nonce is the SSH packet sequence number, needing no state of its own),
 * RFC 5647's 12-byte nonce is a fixed field from key derivation concatenated with an 8-byte
 * invocation counter that increments once per packet -- so the context owns and advances it. */
#define GCM_TAGLEN 16
#define GCM_IVLEN  12

typedef struct {
    aes_ctr_ctx aesk;      /* round keys only; its own ctr/ks/used fields are unused here */
    u8  H[16];             /* hash subkey = AES_K(0^128) */
    u8  fixed[4];          /* constant part of the nonce, from key derivation */
    u64 invocation;        /* increments by one every seal/open call */
} aes_gcm_ctx;

void aes_gcm_init(aes_gcm_ctx *c, const u8 *key, int keylen, const u8 iv[GCM_IVLEN]);

/* dst/src = [length(4)][payload(len)]; the length field is authenticated (as GCM's associated
 * data) but not encrypted -- RFC 5647 s.7.3 -- exactly mirroring how ssh.c already treats the
 * length field for encrypt-then-mac.  The 16-byte tag is written to / read from dst+4+len (seal)
 * or src+4+len (open).  open returns 0, or -1 on authentication failure. */
void aes_gcm_seal(aes_gcm_ctx *c, u8 *dst, const u8 *src, size_t len);
int  aes_gcm_open(aes_gcm_ctx *c, u8 *dst, const u8 *src, size_t len);

#endif
