/*
 * bench -- how long the expensive operations take on THIS machine.
 * Run it from the project root (it reads a few keys from tests/keys/):
 *     build/bench
 * Times are wall-clock, from gettimeofday(); on an old CPU some operations take seconds.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "../core/oscompat.h"
#include "../core/ssh_key.h"
#include "../core/nacl.h"
#include "../core/bcrypt.h"
#include "../core/bignum.h"
#include "../core/chacha.h"
#include "../core/aes.h"
#include "../core/sha2.h"
#include "../core/rng.h"
#include "../core/dh_tab.h"

/* Wall-clock time in milliseconds.  (The units of clock() differ between C libraries and are not
 * all defined on OPENSTEP, so this uses gettimeofday().) */
static double now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec * 1000.0 + (double)tv.tv_usec / 1000.0;
}

static double t0;
static void start(void) { t0 = now_ms(); }
static double elapsed_s(void) { return (now_ms() - t0) / 1000.0; }
static void report(const char *what, int reps)
{
    double ms = (now_ms() - t0) / (double)reps;
    if (ms >= 1000.0) printf("  %-46s %8.2f s\n", what, ms / 1000.0);
    else printf("  %-46s %8.1f ms\n", what, ms);
    fflush(stdout);
}

static int load(const char *name, const char *pass, ssh_key *k)
{
    char path[128], text[8192];
    const char *err;
    FILE *f;
    size_t n;
    strcpy(path, "tests/keys/"); strcat(path, name);
    f = fopen(path, "rb");
    if (!f) { printf("  (cannot read %s; run from the project root)\n", path); return -1; }
    n = fread(text, 1, sizeof(text) - 1, f);
    fclose(f);
    if (ssh_key_parse_private(text, n, pass, k, &err) != 0) { printf("  (%s: %s)\n", name, err); return -1; }
    return 0;
}

static void bench_key(const char *label, const char *file, const char *algo)
{
    ssh_key k;
    sbuf blob, sig;
    u8 msg[32];
    char what[80];
    const char *why;
    int reps = 3, i;
    memset(msg, 7, sizeof(msg));
    if (load(file, NULL, &k) != 0) return;
    sb_init(&blob); sb_init(&sig);
    ssh_key_public_blob(&k, &blob);
    start();
    for (i = 0; i < reps; i++) { sb_clear(&sig); ssh_key_sign(&k, algo, msg, sizeof(msg), &sig); }
    strcpy(what, label); strcat(what, ": sign (login with this key)");
    report(what, reps);
    start();
    for (i = 0; i < reps; i++) ssh_hostkey_verify(blob.p, blob.len, sig.p, sig.len, algo, msg, sizeof(msg), &why);
    strcpy(what, label); strcat(what, ": verify (server's host key)");
    report(what, reps);
    sb_free(&blob); sb_free(&sig); ssh_key_wipe(&k);
}

int main(void)
{
    u8 a[32], b[32], big[65536];
    int i, reps;
    aes_ctr_ctx aes;
    chachapoly_ctx cp;
    u8 key[64], iv[16];
    bn p, g, x, e;

    ssh_rng_seed_system();
    if (!ssh_rng_ready()) ssh_rng_add("bench", 5, 256);
    memset(a, 9, 32); memset(b, 0, 32);
    printf("Cost of the expensive operations on this machine (wall-clock)\n\n");

    printf("Key exchange\n");
    start(); for (i = 0; i < 3; i++) x25519_base(b, a); report("curve25519: one public key / shared secret", 3);
    {
        int ok = 1;
        bn_init(&p); bn_init(&g); bn_init(&x); bn_init(&e);
        ok = bn_from_bytes(&p, DH_P14, sizeof(DH_P14)) == 0 && bn_set_u32(&g, 2) == 0 && bn_from_bytes(&x, key, 32) == 0;
        memset(key, 0xab, 32);
        bn_from_bytes(&x, key, 32);
        if (ok) { start(); bn_modexp(&e, &g, &x, &p); report("DH group14 (2048-bit): one modular exponentiation", 1); }
        bn_free(&p);
        bn_from_bytes(&p, DH_P16, sizeof(DH_P16));
        start(); bn_modexp(&e, &g, &x, &p); report("DH group16 (4096-bit): one modular exponentiation", 1);
        bn_free(&p); bn_free(&g); bn_free(&x); bn_free(&e);
    }
    printf("\nHost keys and login keys\n");
    start(); { u8 sk[64], pk[32], sg[64]; ed25519_keypair(pk, sk, a); ed25519_sign(sg, a, 32, sk); report("ed25519: sign", 1); start(); ed25519_verify(sg, a, 32, pk); report("ed25519: verify", 1); }
    bench_key("ECDSA P-256", "ec256_ssh", "ecdsa-sha2-nistp256");
    bench_key("ECDSA P-384", "ec384_ssh", "ecdsa-sha2-nistp384");
    bench_key("ECDSA P-521", "ec521_ssh", "ecdsa-sha2-nistp521");
    bench_key("RSA 2048", "rsa2048_ssh", "rsa-sha2-256");
    bench_key("RSA 3072", "rsa3072_ssh", "rsa-sha2-256");

    printf("\nUnlocking a passphrase-protected key (bcrypt, 16 rounds -- the ssh-keygen default)\n");
    { u8 material[48]; start(); bcrypt_pbkdf((const u8 *)"passphrase", 10, (const u8 *)"0123456789abcdef", 16, material, 48, 16); report("bcrypt-pbkdf, 16 rounds", 1); }

    printf("\nBulk throughput on an open connection\n");
    memset(big, 1, sizeof(big)); memset(key, 2, sizeof(key)); memset(iv, 3, sizeof(iv));
    reps = 8;
    aes_ctr_init(&aes, key, 32, iv);
    start(); for (i = 0; i < reps; i++) aes_ctr_xor(&aes, big, big, sizeof(big)); 
    { double s = elapsed_s(); printf("  %-46s %8.2f KB/s\n", "AES-256-CTR", s > 0 ? (double)reps * 64.0 / s : 0.0); }
    chachapoly_init(&cp, key);
    start(); for (i = 0; i < reps; i++) chachapoly_seal(&cp, (u32)i, big, big, 32768);
    { double s = elapsed_s(); printf("  %-46s %8.2f KB/s\n", "ChaCha20-Poly1305 (preferred)", s > 0 ? (double)reps * 32.0 / s : 0.0); }
    start(); for (i = 0; i < reps; i++) { u8 d[32]; sha256(big, sizeof(big), d); }
    { double s = elapsed_s(); printf("  %-46s %8.2f KB/s\n", "SHA-256 (HMAC cost)", s > 0 ? (double)reps * 64.0 / s : 0.0); }
    printf("\n(Rows showing 0.0 ms or 0.00 KB/s were faster than the clock can resolve.)\n");
    return 0;
}
