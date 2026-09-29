/*
 * bench_bulk -- per-primitive cost of everything on the bulk-data path, on THIS machine.
 * Run it from the project root:
 *     build/bench_bulk
 * Each row is timed for about half a second (longer only if one call is slower than that), so it
 * finishes quickly on a fast host and still completes on a 68040.  Compare the numbers before and
 * after a change, on the same machine; the packet-sized rows show per-packet overhead (key
 * schedules, MAC set-up, the random padding) that a bulk row hides.
 *
 * Wall-clock time from gettimeofday(); C89 so it builds under gcc 2.7.2 as well.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "../core/ssh_types.h"
#include "../core/chacha.h"
#include "../core/aes.h"
#include "../core/gcm.h"
#include "../core/sha1.h"
#include "../core/sha2.h"
#include "../core/md5.h"
#include "../core/hmac.h"
#include "../core/rng.h"

#define BIG 65536

static double now_s(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
}

/* Seconds per call of fn, measured over enough calls to take at least `budget` seconds. */
static double measure(void (*fn)(void))
{
    const double budget = 0.5;
    double t0, t;
    long n = 1, i;
    for (;;) {
        t0 = now_s();
        for (i = 0; i < n; i++) fn();
        t = now_s() - t0;
        if (t >= budget) return t / (double)n;
        n *= (t < budget / 16.0) ? 16 : 2;
    }
}

static void row_kbs(const char *what, void (*fn)(void), double kbytes)
{
    double s = measure(fn);
    printf("  %-46s %10.1f KB/s\n", what, s > 0 ? kbytes / s : 0.0);
    fflush(stdout);
}

static void row_us(const char *what, void (*fn)(void), double kbytes)
{
    double s = measure(fn);
    printf("  %-46s %10.1f us/op  (%8.1f KB/s)\n", what, s * 1e6, s > 0 ? kbytes / s : 0.0);
    fflush(stdout);
}

static u8 buf[BIG + 128], buf2[BIG + 128], sealed[BIG + 128];
static u8 key64[64], iv16[16], mackey[64], digest[64], mac[64];
static chacha_ctx cc;
static chachapoly_ctx cp;
static aes_ctr_ctx aes128, aes256;
static aes_gcm_ctx gcm128, gcm256;
static u32 seq;
static size_t plen;              /* payload length for the packet-sized rows */
static int hkind;

static void f_chacha(void)       { chacha_xor(&cc, buf, buf, BIG); }
static void f_poly(void)         { poly1305_auth(mac, buf, BIG, key64); }
static void f_cp_seal(void)      { chachapoly_seal(&cp, seq++, buf2, buf, plen); }
static void f_cp_open(void)
{
    (void)chachapoly_peek_length(&cp, 5, sealed);
    (void)chachapoly_open(&cp, 5, buf2, sealed, plen);
}
static void f_aes128_ctr(void)   { aes_ctr_xor(&aes128, buf, buf, BIG); }
static void f_aes256_ctr(void)   { aes_ctr_xor(&aes256, buf, buf, BIG); }
static void f_aes128_cbc_enc(void) { u8 v[16]; memcpy(v, iv16, 16); aes_cbc_encrypt_chain(&aes128, v, buf, buf, 4096); }
static void f_aes128_cbc_dec(void) { u8 v[16]; memcpy(v, iv16, 16); aes_cbc_decrypt_chain(&aes128, v, buf, buf, 4096); }
static void f_gcm128_seal(void)  { aes_gcm_seal(&gcm128, buf2, buf, plen); }
static void f_gcm256_seal(void)  { aes_gcm_seal(&gcm256, buf2, buf, plen); }
static void f_sha1(void)         { sha1_ctx c; sha1_init(&c); sha1_update(&c, buf, BIG); sha1_final(&c, digest); }
static void f_sha256(void)       { sha256(buf, BIG, digest); }
static void f_sha512(void)       { sha512(buf, BIG, digest); }
static void f_md5(void)          { md5_ctx c; md5_init(&c); md5_update(&c, buf, BIG); md5_final(&c, digest); }
static void f_hmac(void)         /* exactly what one transport packet costs: set-up + seq + packet */
{
    hmac_ctx h;
    u8 sb[4];
    sb[0] = sb[1] = sb[2] = 0; sb[3] = (u8)seq++;
    hmac_init(&h, hkind, mackey, hkind == HMAC_SHA512 ? 64 : hkind == HMAC_SHA1 ? 20 : 32);
    hmac_update(&h, sb, 4);
    hmac_update(&h, buf, plen);
    hmac_final(&h, digest);
}
static void f_rng(void)          { u8 pad[12]; ssh_rng_bytes(pad, sizeof(pad)); }
static void f_wipe(void)         { ssh_wipe(buf2, BIG / 2); }
static void f_memmove(void)      { memmove(buf2, buf2 + 4096, BIG / 2); }

int main(void)
{
    int i;
    char what[80];
    static const size_t sizes[3] = { 64, 1400, 32768 };
    static const char *szname[3] = { "64 B", "1400 B", "32 KB" };
    static const int kinds[4] = { HMAC_SHA1, HMAC_SHA256, HMAC_SHA512, HMAC_MD5 };
    static const char *kname[4] = { "HMAC-SHA1", "HMAC-SHA256", "HMAC-SHA512", "HMAC-MD5" };

    ssh_rng_seed_system();
    if (!ssh_rng_ready()) ssh_rng_add("bench", 5, 256);
    for (i = 0; i < 64; i++) { key64[i] = (u8)(i * 7 + 1); mackey[i] = (u8)(i * 13 + 5); }
    for (i = 0; i < 16; i++) iv16[i] = (u8)(i + 3);
    memset(buf, 0x5a, sizeof(buf));

    chacha_keysetup(&cc, key64);
    chacha_ivsetup(&cc, iv16, 0);
    chachapoly_init(&cp, key64);
    aes_ctr_init(&aes128, key64, 16, iv16);
    aes_ctr_init(&aes256, key64, 32, iv16);
    aes_gcm_init(&gcm128, key64, 16, iv16);
    aes_gcm_init(&gcm256, key64, 32, iv16);

    printf("Bulk-path cost on this machine (wall-clock, ~0.5 s per row)\n\n");

    printf("Stream cipher and MAC halves, 64 KB\n");
    row_kbs("ChaCha20 keystream XOR", f_chacha, BIG / 1024.0);
    row_kbs("Poly1305 MAC", f_poly, BIG / 1024.0);

    printf("\nchacha20-poly1305@openssh.com, one packet at a time\n");
    for (i = 0; i < 3; i++) {
        plen = sizes[i];
        sprintf(what, "seal   %s", szname[i]);
        row_us(what, f_cp_seal, (double)plen / 1024.0);
    }
    for (i = 0; i < 3; i++) {
        plen = sizes[i];
        memset(sealed, 0, sizeof(sealed));
        memcpy(sealed, buf, 4 + plen);
        chachapoly_seal(&cp, 5, sealed, sealed, plen);
        sprintf(what, "peek+open %s", szname[i]);
        row_us(what, f_cp_open, (double)plen / 1024.0);
    }

    printf("\nAES, 64 KB (CTR) / 4 KB (CBC)\n");
    row_kbs("AES-128-CTR", f_aes128_ctr, BIG / 1024.0);
    row_kbs("AES-256-CTR", f_aes256_ctr, BIG / 1024.0);
    row_kbs("AES-128-CBC encrypt (legacy)", f_aes128_cbc_enc, 4.0);
    row_kbs("AES-128-CBC decrypt (legacy)", f_aes128_cbc_dec, 4.0);

    printf("\nAES-GCM, one packet at a time\n");
    for (i = 0; i < 3; i++) {
        plen = sizes[i] > 4096 ? 4096 : sizes[i];       /* GCM is slow enough to cap the size */
        sprintf(what, "aes128-gcm seal %lu B", (unsigned long)plen);
        row_us(what, f_gcm128_seal, (double)plen / 1024.0);
    }
    plen = 1400;
    row_us("aes256-gcm seal 1400 B", f_gcm256_seal, 1400 / 1024.0);

    printf("\nHash functions, 64 KB\n");
    row_kbs("SHA-1", f_sha1, BIG / 1024.0);
    row_kbs("SHA-256", f_sha256, BIG / 1024.0);
    row_kbs("SHA-512", f_sha512, BIG / 1024.0);
    row_kbs("MD5", f_md5, BIG / 1024.0);

    printf("\nHMAC as the transport uses it: set-up + sequence number + one packet\n");
    for (i = 0; i < 4; i++) {
        int j;
        hkind = kinds[i];
        for (j = 0; j < 3; j += 2) {                     /* 64 B and 32 KB */
            plen = sizes[j];
            sprintf(what, "%s %s", kname[i], szname[j]);
            row_us(what, f_hmac, (double)plen / 1024.0);
        }
    }

    printf("\nPer-packet overheads\n");
    row_us("ssh_rng_bytes(12): the random padding", f_rng, 0.0);
    row_us("ssh_wipe 32 KB (sb_consume wipes what it frees)", f_wipe, 32.0);
    row_us("memmove 32 KB (sb_consume shifts what is left)", f_memmove, 32.0);
    return 0;
}
