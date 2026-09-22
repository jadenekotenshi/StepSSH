#ifndef SSH_BLOWFISH_H
#define SSH_BLOWFISH_H
#include "ssh_types.h"

/* Blowfish, used only through bcrypt-pbkdf (which unlocks passphrase-protected
 * OpenSSH private keys).  Word order is big-endian, as in Schneier's definition. */
typedef struct { u32 P[18]; u32 S[4][256]; } blf_ctx;

void blf_initstate(blf_ctx *c);
/* bcrypt's "expensive key schedule" steps (OpenBSD blf.c naming): */
void blf_expandstate(blf_ctx *c, const u8 *data, size_t dlen, const u8 *key, size_t klen);
void blf_expand0state(blf_ctx *c, const u8 *key, size_t klen);
void blf_encipher(const blf_ctx *c, u32 *xl, u32 *xr);
void blf_decipher(const blf_ctx *c, u32 *xl, u32 *xr);
/* Standard Blowfish key setup (initstate + expand0state), for the test vectors. */
void blf_key(blf_ctx *c, const u8 *key, size_t klen);

/* CBC mode for the SSH transport's blowfish-cbc: `iv` is updated to the last ciphertext block, so
 * successive calls continue one long chain (SSH chains the IV across packets, RFC 4253 s.6.3). len
 * must be a multiple of 8 (Blowfish's block size); in and out may be the same buffer. */
void blowfish_cbc_encrypt_chain(const blf_ctx *c, u8 iv[8], const u8 *in, u8 *out, size_t len);
void blowfish_cbc_decrypt_chain(const blf_ctx *c, u8 iv[8], const u8 *in, u8 *out, size_t len);

#endif
