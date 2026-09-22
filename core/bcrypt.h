#ifndef SSH_BCRYPT_H
#define SSH_BCRYPT_H
#include "ssh_types.h"

/* OpenBSD's bcrypt_pbkdf (the key-derivation function of OpenSSH's encrypted
 * private-key format).  Deliberately slow: cost grows linearly with `rounds`.
 * Returns 0 on success, -1 on bad arguments or out of memory. */
int bcrypt_pbkdf(const u8 *pass, size_t passlen, const u8 *salt, size_t saltlen,
                 u8 *key, size_t keylen, unsigned int rounds);

#endif
