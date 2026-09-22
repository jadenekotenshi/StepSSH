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
/* Standard Blowfish key setup (initstate + expand0state), for the test vectors. */
void blf_key(blf_ctx *c, const u8 *key, size_t klen);

#endif
