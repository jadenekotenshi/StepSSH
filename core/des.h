#ifndef SSH_DES_H
#define SSH_DES_H
#include "ssh_types.h"

/* Single DES: exposed only for the FIPS 46-3 known-answer test in tests/test_crypto.c.  SSH
 * itself never negotiates single DES -- only the 3des-cbc cipher below. */
typedef struct { u64 subkeys[16]; } des_ctx;
void des_key(des_ctx *c, const u8 key[8]);
void des_crypt_block(const des_ctx *c, const u8 in[8], u8 out[8], int decrypt);

/* Triple DES, EDE3 (encrypt/decrypt/encrypt with three independent 8-byte keys), for SSH's
 * legacy "3des-cbc" cipher (RFC 4253 s.6.3, keylen 24). */
typedef struct { des_ctx k1, k2, k3; } des3_ctx;
void des3_key(des3_ctx *c, const u8 key[24]);

/* CBC mode, chained across calls exactly like aes_cbc_*_chain / blowfish_cbc_*_chain: `iv` is
 * updated to the last ciphertext block, so successive calls continue one long chain (SSH chains
 * the IV across packets, RFC 4253 s.6.3).  len must be a multiple of 8; in and out may be the
 * same buffer. */
void des3_cbc_encrypt_chain(const des3_ctx *c, u8 iv[8], const u8 *in, u8 *out, size_t len);
void des3_cbc_decrypt_chain(const des3_ctx *c, u8 iv[8], const u8 *in, u8 *out, size_t len);

#endif
