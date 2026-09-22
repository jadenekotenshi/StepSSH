#include <stdlib.h>
#include <string.h>
#include "bcrypt.h"
#include "blowfish.h"
#include "sha2.h"

#define BCRYPT_HASHSIZE 32

/* One bcrypt hash of the (already SHA-512'd) password and salt. */
static void bcrypt_hash(const u8 sha2pass[64], const u8 sha2salt[64], u8 out[BCRYPT_HASHSIZE])
{
    static const char ciphertext[] = "OxychromaticBlowfishSwatDynamite";   /* 32 bytes + NUL */
    blf_ctx state;
    u32 cdata[8];
    int i, j;

    blf_initstate(&state);
    blf_expandstate(&state, sha2salt, 64, sha2pass, 64);
    for (i = 0; i < 64; i++) {
        blf_expand0state(&state, sha2salt, 64);
        blf_expand0state(&state, sha2pass, 64);
    }
    for (i = 0; i < 8; i++) cdata[i] = LOAD32_BE((const u8 *)ciphertext + 4 * i);
    for (i = 0; i < 64; i++)
        for (j = 0; j < 8; j += 2) blf_encipher(&state, &cdata[j], &cdata[j + 1]);
    for (i = 0; i < 8; i++) STORE32_LE(out + 4 * i, cdata[i]);   /* bcrypt_pbkdf emits little-endian */
    ssh_wipe(&state, sizeof(state));
    ssh_wipe(cdata, sizeof(cdata));
}

int bcrypt_pbkdf(const u8 *pass, size_t passlen, const u8 *salt, size_t saltlen,
                 u8 *key, size_t keylen, unsigned int rounds)
{
    u8 sha2pass[SHA512_DIGEST], sha2salt[SHA512_DIGEST];
    u8 out[BCRYPT_HASHSIZE], tmpout[BCRYPT_HASHSIZE];
    u8 *countsalt;
    size_t i, j, amt, stride, origkeylen = keylen;
    u32 count;

    if (rounds < 1 || passlen == 0 || saltlen == 0 || saltlen > (1u << 20) ||
        keylen == 0 || keylen > BCRYPT_HASHSIZE * BCRYPT_HASHSIZE) return -1;
    stride = (keylen + BCRYPT_HASHSIZE - 1) / BCRYPT_HASHSIZE;
    amt = (keylen + stride - 1) / stride;
    countsalt = (u8 *)malloc(saltlen + 4);
    if (!countsalt) return -1;
    memcpy(countsalt, salt, saltlen);

    sha512(pass, passlen, sha2pass);
    for (count = 1; keylen > 0; count++) {
        u32 c = count;
        STORE32_BE(countsalt + saltlen, c);
        sha512(countsalt, saltlen + 4, sha2salt);
        bcrypt_hash(sha2pass, sha2salt, tmpout);
        memcpy(out, tmpout, sizeof(out));
        for (i = 1; i < rounds; i++) {
            sha512(tmpout, sizeof(tmpout), sha2salt);
            bcrypt_hash(sha2pass, sha2salt, tmpout);
            for (j = 0; j < sizeof(out); j++) out[j] ^= tmpout[j];
        }
        /* pbkdf2 deviation: scatter the output bytes across the key */
        if (amt > keylen) amt = keylen;
        for (i = 0; i < amt; i++) {
            size_t dest = i * stride + (count - 1);
            if (dest >= origkeylen) break;
            key[dest] = out[i];
        }
        keylen -= i;
    }
    ssh_wipe(countsalt, saltlen + 4);
    free(countsalt);
    ssh_wipe(sha2pass, sizeof(sha2pass)); ssh_wipe(sha2salt, sizeof(sha2salt));
    ssh_wipe(out, sizeof(out)); ssh_wipe(tmpout, sizeof(tmpout));
    return 0;
}
