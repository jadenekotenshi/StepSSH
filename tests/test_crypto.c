#include <stdlib.h>
#include "../core/ssh_types.h"
#include "../core/sha2.h"
#include "../core/hmac.h"
#include "../core/aes.h"
#include "../core/chacha.h"
#include "../core/nacl.h"
#include "../core/rng.h"
#include "../core/sha1.h"
#include "../core/md5.h"
#include "../core/knownhosts.h"
#include "../core/wire.h"
#include "../core/blowfish.h"
#include "../core/bcrypt.h"
#include "../core/ssh_key.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "test.h"
#include "vectors.h"

static void pattern(unsigned char *p, int n, int seed)
{
    int i;
    for (i = 0; i < n; i++) p[i] = (unsigned char)((i * 7 + 3 + seed) & 0xff);
}

static void test_sha(void)
{
    int i, j;
    u8 msg[1000], d256[32], d512[64];
    sha256_ctx c256;
    sha512_ctx c512;

    for (i = 0; i < N_SHA; i++) {
        pattern(msg, sha_lens[i], 0);
        sha256(msg, sha_lens[i], d256);
        sha512(msg, sha_lens[i], d512);
        { u8 d384[48]; sha384(msg, (size_t)sha_lens[i], d384); CHECK_MEM(d384, sha384_exp[i], 48, "sha384"); }
        CHECK_MEM(d256, sha256_exp[i], 32, "sha256");
        CHECK_MEM(d512, sha512_exp[i], 64, "sha512");
        /* same message fed in awkward pieces */
        sha256_init(&c256); sha512_init(&c512);
        for (j = 0; j < sha_lens[i]; j += 13) {
            int n = sha_lens[i] - j < 13 ? sha_lens[i] - j : 13;
            sha256_update(&c256, msg + j, n);
            sha512_update(&c512, msg + j, n);
        }
        sha256_final(&c256, d256); sha512_final(&c512, d512);
        CHECK_MEM(d256, sha256_exp[i], 32, "sha256 incremental");
        CHECK_MEM(d512, sha512_exp[i], 64, "sha512 incremental");
    }
}

static void test_hmac(void)
{
    int i;
    u8 k[200], m[200], out[64];
    hmac_ctx h;
    for (i = 0; i < N_HMAC; i++) {
        pattern(k, hmac_klens[i], 9);
        pattern(m, hmac_mlens[i], 5);
        hmac_init(&h, 0, k, hmac_klens[i]);
        hmac_update(&h, m, hmac_mlens[i]);
        hmac_final(&h, out);
        CHECK_MEM(out, hmac256_exp[i], 32, "hmac-sha256");
        hmac_init(&h, 1, k, hmac_klens[i]);
        hmac_update(&h, m, hmac_mlens[i] / 2);
        hmac_update(&h, m + hmac_mlens[i] / 2, hmac_mlens[i] - hmac_mlens[i] / 2);
        hmac_final(&h, out);
        CHECK_MEM(out, hmac512_exp[i], 64, "hmac-sha512");
    }
}

static void test_sha1(void)
{
    int i;
    u8 msg[1000], d[20], k[200], m[200];
    sha1_ctx c;
    md5_ctx mc;
    for (i = 0; i < N_SHA; i++) {
        pattern(msg, sha_lens[i], 0);
        sha1_init(&c); sha1_update(&c, msg, (size_t)sha_lens[i]); sha1_final(&c, d);
        CHECK_MEM(d, sha1_exp[i], 20, "sha1");
        { u8 dm[16]; md5_init(&mc); md5_update(&mc, msg, (size_t)sha_lens[i]); md5_final(&mc, dm); CHECK_MEM(dm, md5_exp[i], 16, "md5"); }
    }
    for (i = 0; i < N_HMAC; i++) {
        hmac_ctx hc;
        pattern(k, hmac_klens[i], 9); pattern(m, hmac_mlens[i], 5);
        hmac_sha1(k, (size_t)hmac_klens[i], m, (size_t)hmac_mlens[i], d);
        CHECK_MEM(d, hmac1_exp[i], 20, "hmac-sha1");
        hmac_init(&hc, HMAC_SHA1, k, (size_t)hmac_klens[i]);                      /* the incremental interface the transport uses */
        hmac_update(&hc, m, (size_t)hmac_mlens[i] / 3);
        hmac_update(&hc, m + hmac_mlens[i] / 3, (size_t)hmac_mlens[i] - (size_t)hmac_mlens[i] / 3);
        hmac_final(&hc, d);
        CHECK_MEM(d, hmac1_exp[i], 20, "hmac-sha1 incremental");
    }
}

static void write_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    fputs(text, f);
    fclose(f);
}

static void test_knownhosts(void)
{
    const char *path = "build/kh_test.tmp";
    u8 blob[51], other[51];
    sbuf b;
    char line[512];
    struct stat st;
    int i;

    /* blob = string "ssh-ed25519" || string pk */
    sb_init(&b);
    sb_put_cstr(&b, "ssh-ed25519"); sb_put_str(&b, ed_pub_exp[1], 32);
    memcpy(blob, b.p, 51);
    sb_clear(&b);
    sb_put_cstr(&b, "ssh-ed25519"); sb_put_str(&b, ed_pub_exp[2], 32);
    memcpy(other, b.p, 51);
    sb_free(&b);

    remove(path);
    CHECK(kh_check(path, "host.example", 22, blob, 51) == KH_UNKNOWN);          /* no file */
    CHECK(kh_add(path, "host.example", 22, blob, 51) == 0);
    CHECK(kh_add(path, "alt.example", 2222, blob, 51) == 0);
    CHECK(stat(path, &st) == 0 && (st.st_mode & 077) == 0);                     /* 0600 */
    CHECK(kh_check(path, "host.example", 22, blob, 51) == KH_MATCH);
    CHECK(kh_check(path, "HOST.Example", 22, blob, 51) == KH_MATCH);            /* case-insensitive */
    CHECK(kh_check(path, "host.example", 22, other, 51) == KH_CHANGED);         /* same host, new key */
    CHECK(kh_check(path, "host.example", 2222, blob, 51) == KH_UNKNOWN);        /* port is part of identity */
    CHECK(kh_check(path, "alt.example", 2222, blob, 51) == KH_MATCH);
    CHECK(kh_check(path, "alt.example", 22, blob, 51) == KH_UNKNOWN);
    CHECK(kh_check(path, "nobody.example", 22, blob, 51) == KH_UNKNOWN);

    /* hand-written lines: wildcards, negation, lists, comments, markers, other key types */
    {
        char b64[100];
        b64_encode(blob, 51, b64, sizeof(b64), 1);
        strcpy(line, "# comment\n\n@cert-authority *.evil ssh-ed25519 ");
        strcat(line, b64);
        strcat(line, "\n*.lab.example,!secret.lab.example,10.0.0.? ssh-ed25519 ");
        strcat(line, b64);
        strcat(line, " trailing comment\nmulti.example ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC\n");
        write_file(path, line);
    }
    CHECK(kh_check(path, "a.lab.example", 22, blob, 51) == KH_MATCH);
    CHECK(kh_check(path, "secret.lab.example", 22, blob, 51) == KH_UNKNOWN);   /* negated */
    CHECK(kh_check(path, "10.0.0.7", 22, blob, 51) == KH_MATCH);
    CHECK(kh_check(path, "10.0.0.77", 22, blob, 51) == KH_UNKNOWN);
    CHECK(kh_check(path, "x.evil", 22, blob, 51) == KH_UNKNOWN);                /* @cert-authority ignored */
    CHECK(kh_check(path, "multi.example", 22, blob, 51) == KH_UNKNOWN);         /* only an RSA entry */

    /* hashed entry as written by OpenSSH with HashKnownHosts */
    {
        char b64[100];
        b64_encode(blob, 51, b64, sizeof(b64), 1);
        strcpy(line, kh_hashed_token);
        strcat(line, " ssh-ed25519 ");
        strcat(line, b64);
        strcat(line, "\n");
        write_file(path, line);
    }
    CHECK(kh_check(path, "secret.example.org", 22, blob, 51) == KH_MATCH);
    CHECK(kh_check(path, "other.example.org", 22, blob, 51) == KH_UNKNOWN);
    CHECK(kh_check(path, "secret.example.org", 22, other, 51) == KH_CHANGED);

    /* junk must not crash */
    write_file(path, "\x01\x02 garbage\n||| |\nhost\nhost ssh-ed25519\nhost ssh-ed25519 !!!!\n");
    for (i = 0; i < 3; i++) CHECK(kh_check(path, "host", 22, blob, 51) == KH_UNKNOWN);
    remove(path);
}

static void unhex(const char *h, u8 *out, int n)
{
    int i;
    for (i = 0; i < n; i++) {
        int a = h[2 * i], b = h[2 * i + 1];
        a = a <= '9' ? a - '0' : (a | 32) - 'a' + 10;
        b = b <= '9' ? b - '0' : (b | 32) - 'a' + 10;
        out[i] = (u8)(a * 16 + b);
    }
}

/* FIPS-197 appendix C known answers, both directions, all three key sizes. */
static void test_aes_blocks(void)
{
    static const struct { int keylen; const char *ct; } v[] = {
        { 16, "69c4e0d86a7b0430d8cdb78070b4c55a" },
        { 24, "dda97ca4864cdfe06eaf70a0ec0d7191" },
        { 32, "8ea2b7ca516745bfeafc49904b496089" },
    };
    u8 key[32], pt[16], ct[16], out[16], zero_iv[16];
    aes_ctr_ctx c;
    int i, j;
    for (j = 0; j < 32; j++) key[j] = (u8)j;
    unhex("00112233445566778899aabbccddeeff", pt, 16);
    memset(zero_iv, 0, 16);
    for (i = 0; i < 3; i++) {
        unhex(v[i].ct, ct, 16);
        aes_ctr_init(&c, key, v[i].keylen, zero_iv);
        aes_encrypt_block(&c, pt, out);
        CHECK_MEM(out, ct, 16, "aes encrypt (FIPS-197)");
        aes_decrypt_block(&c, ct, out);
        CHECK_MEM(out, pt, 16, "aes decrypt (FIPS-197)");
    }
    /* CBC decrypt against a hand-rolled CBC encrypt built from the tested block function */
    {
        u8 plain[64], enc[64], back[64], iv[16], prev[16], blk[16];
        int b, k;
        pattern(plain, 64, 7); pattern(iv, 16, 99); pattern(key, 32, 50);
        aes_ctr_init(&c, key, 32, zero_iv);
        memcpy(prev, iv, 16);
        for (b = 0; b < 64; b += 16) {
            for (k = 0; k < 16; k++) blk[k] = (u8)(plain[b + k] ^ prev[k]);
            aes_encrypt_block(&c, blk, enc + b);
            memcpy(prev, enc + b, 16);
        }
        aes_cbc_decrypt(&c, iv, enc, back, 64);
        CHECK_MEM(back, plain, 64, "aes-cbc decrypt");
        aes_cbc_decrypt(&c, iv, enc, enc, 64);                   /* in place */
        CHECK_MEM(enc, plain, 64, "aes-cbc decrypt in place");
    }
}

/* SSH chains CBC across packets: many small chained calls must equal one big call */
static void test_cbc_chain(void)
{
    aes_ctr_ctx c;
    u8 key[16], iv0[16], iv[16], plain[160], one[160], two[160], back[160], zero[16];
    int off;
    pattern(key, 16, 3); pattern(iv0, 16, 9); pattern(plain, 160, 12); memset(zero, 0, 16);
    aes_ctr_init(&c, key, 16, zero);
    memcpy(iv, iv0, 16);
    aes_cbc_encrypt_chain(&c, iv, plain, one, 160);
    memcpy(iv, iv0, 16);
    for (off = 0; off < 160; off += 32) aes_cbc_encrypt_chain(&c, iv, plain + off, two + off, 32);   /* packets of 2 blocks */
    CHECK_MEM(one, two, 160, "cbc chained encrypt == one-shot");
    CHECK_MEM(iv, one + 144, 16, "iv ends as the last ciphertext block");
    memcpy(iv, iv0, 16);
    for (off = 0; off < 160; off += 48) aes_cbc_decrypt_chain(&c, iv, one + off, back + off, off + 48 <= 160 ? 48 : 16);
    CHECK_MEM(back, plain, 160, "cbc chained decrypt round trip");
    aes_cbc_decrypt(&c, iv0, one, back, 160);
    CHECK_MEM(back, plain, 160, "cbc chained encrypt matches the one-shot decrypt");
    memcpy(iv, iv0, 16);
    aes_cbc_decrypt_chain(&c, iv, one, one, 160);                                                     /* in place */
    CHECK_MEM(one, plain, 160, "cbc chained decrypt in place");
}

static void test_blowfish(void)
{
    blf_ctx c;
    u8 key[8], pt[8], want[8];
    u32 l, r;
    /* Eric Young's Blowfish test vectors */
    memset(key, 0, 8);
    blf_key(&c, key, 8);
    l = 0; r = 0;
    blf_encipher(&c, &l, &r);
    unhex("4ef997456198dd78", want, 8);
    CHECK(l == LOAD32_BE(want) && r == LOAD32_BE(want + 4));
    memset(key, 0xff, 8);
    blf_key(&c, key, 8);
    l = r = 0xffffffffUL;
    blf_encipher(&c, &l, &r);
    unhex("51866fd5b85ecb8a", want, 8);
    CHECK(l == LOAD32_BE(want) && r == LOAD32_BE(want + 4));
    unhex("0123456789abcdef", key, 8); unhex("1111111111111111", pt, 8);
    blf_key(&c, key, 8);
    l = LOAD32_BE(pt); r = LOAD32_BE(pt + 4);
    blf_encipher(&c, &l, &r);
    unhex("61f9c3802281b096", want, 8);
    CHECK(l == LOAD32_BE(want) && r == LOAD32_BE(want + 4));
}

static int read_file(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "rb");
    size_t n;
    if (!f) return -1;
    n = fread(buf, 1, cap - 1, f);
    fclose(f);
    buf[n] = '\0';
    return (int)n;
}

/* The public key that ssh-keygen recorded in "<name>.pub", as a wire-format blob. */
static int pub_blob_from_file(const char *path, u8 *blob, size_t cap)
{
    char text[1024], *sp, *end;
    if (read_file(path, text, sizeof(text)) < 0) return -1;
    sp = strchr(text, ' ');
    if (!sp) return -1;
    sp++;
    end = strchr(sp, ' ');
    if (!end) end = sp + strlen(sp);
    return b64_decode(sp, (size_t)(end - sp), blob, cap);
}

static void test_encrypted_keys(void)
{
    static const char *names[] = { "plain", "enc_ctr256", "enc_ctr128", "enc_ctr192", "enc_cbc256", "enc_cbc128" };
    static char text[8192];
    const char *pass = "correct horse", *err;
    char path[128];
    u8 pubfile[256], msg[32], sig[64];
    ssh_key k;
    sbuf blob;
    int i, n, want_len, rc;

    pattern(msg, 32, 4);
    for (i = 0; i < 6; i++) {
        int encrypted = i > 0;
        strcpy(path, "tests/keys/"); strcat(path, names[i]);
        n = read_file(path, text, sizeof(text));
        if (n < 0) { printf("  FAIL: cannot read %s (run from the project root)\n", path); t_fail++; continue; }
        strcat(path, ".pub");
        want_len = pub_blob_from_file(path, pubfile, sizeof(pubfile));

        rc = ssh_key_parse_private(text, (size_t)n, encrypted ? pass : NULL, &k, &err);
        CHECK(rc == 0);
        if (rc == 0) {
            sb_init(&blob);
            ssh_key_public_blob(&k, &blob);
            CHECK(want_len > 0 && (int)blob.len == want_len && memcmp(blob.p, pubfile, blob.len) == 0);
            sb_free(&blob);
            ed25519_sign(sig, msg, 32, k.sk);                               /* the recovered secret works */
            CHECK(ed25519_verify(sig, msg, 32, k.pk) == 0);
            ssh_key_wipe(&k);
        }
        if (encrypted) {
            CHECK(ssh_key_parse_private(text, (size_t)n, NULL, &k, &err) == -2);            /* needs passphrase */
            CHECK(ssh_key_parse_private(text, (size_t)n, "wrong horse", &k, &err) == -3);  /* wrong one */
            CHECK(strcmp(err, "incorrect passphrase") == 0);
            CHECK(k.type == SSH_KEY_NONE);                                                  /* nothing leaked */
        } else {
            CHECK(ssh_key_parse_private(text, (size_t)n, "irrelevant", &k, &err) == 0);     /* extra passphrase is harmless */
            ssh_key_wipe(&k);
        }
    }

    /* damaged files must fail cleanly, never crash */
    n = read_file("tests/keys/enc_ctr128", text, sizeof(text));
    for (i = 30; i < n; i += 37) {
        char saved = text[i];
        text[i] = (char)(saved == 'A' ? 'B' : 'A');
        rc = ssh_key_parse_private(text, (size_t)n, pass, &k, &err);
        CHECK(rc != 0 || k.type == SSH_KEY_ED25519);      /* a flipped base64 char either fails or (padding) decodes */
        text[i] = saved;
    }
    for (i = 60; i < n; i += 91) {                        /* truncation */
        rc = ssh_key_parse_private(text, (size_t)i, pass, &k, &err);
        CHECK(rc == -1);
    }
}

static void test_keygen(void)
{
    ssh_key a, b, c;
    sbuf f1, f2, line;
    const char *err;
    u8 sig[64], msg[16];
    int i;

    pattern(msg, 16, 8);
    CHECK(ssh_key_generate_ed25519(&a, "unit@test") == 0);
    ed25519_sign(sig, msg, 16, a.sk);
    CHECK(ed25519_verify(sig, msg, 16, a.pk) == 0);                 /* a usable keypair */
    CHECK(ssh_key_generate_ed25519(&b, "other") == 0 && memcmp(a.pk, b.pk, 32) != 0);   /* fresh each time */

    for (i = 0; i < 2; i++) {                                       /* plain, then passphrase-protected */
        const char *pw = i ? "generated pass" : NULL;
        sb_init(&f1); sb_init(&line);
        CHECK(ssh_key_write_private(&a, pw, 6, &f1) == 0);
        CHECK(f1.len > 300 && memcmp(f1.p, "-----BEGIN OPENSSH PRIVATE KEY-----\n", 36) == 0);
        CHECK(memcmp(f1.p + f1.len - 34, "-----END OPENSSH PRIVATE KEY-----\n", 33) == 0);
        CHECK(ssh_key_parse_private((char *)f1.p, f1.len, pw, &c, &err) == 0);            /* round trip */
        CHECK(memcmp(c.pk, a.pk, 32) == 0 && memcmp(c.sk, a.sk, 64) == 0 && strcmp(c.comment, "unit@test") == 0);
        if (i) {
            CHECK(ssh_key_parse_private((char *)f1.p, f1.len, NULL, &c, &err) == -2);
            CHECK(ssh_key_parse_private((char *)f1.p, f1.len, "nope", &c, &err) == -3);
            sb_init(&f2);
            ssh_key_write_private(&a, pw, 6, &f2);                   /* same key twice: salt and check ints differ */
            CHECK(f2.len == f1.len && memcmp(f1.p, f2.p, f1.len) != 0);
            sb_free(&f2);
        }
        CHECK(ssh_key_write_public_line(&a, &line) == 0);
        CHECK(memcmp(line.p, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5", 32) == 0 && line.p[line.len - 1] == '\n');
        CHECK(memcmp(line.p + line.len - 10, "unit@test\n", 10) == 0);
        sb_free(&f1); sb_free(&line);
    }
    /* file lines must be short enough for every tool: <= 70 chars */
    sb_init(&f1);
    ssh_key_write_private(&a, NULL, 6, &f1);
    {
        size_t s = 0, k;
        int longest = 0;
        for (k = 0; k < f1.len; k++) if (f1.p[k] == '\n') { if ((int)(k - s) > longest) longest = (int)(k - s); s = k + 1; }
        CHECK(longest <= 70);
    }
    sb_free(&f1);
    ssh_key_wipe(&a); ssh_key_wipe(&b); ssh_key_wipe(&c);
}

/* Every key type and file format ssh-keygen can produce, parsed, checked against its .pub file,
 * and used to sign and verify with each algorithm the transport can negotiate. */
static void test_key_zoo(void)
{
    static const struct { const char *name; int encrypted; int type; } zoo[] = {
        { "rsa2048_ssh", 0, SSH_KEY_RSA }, { "rsa2048_ssh_enc", 1, SSH_KEY_RSA }, { "rsa3072_ssh", 0, SSH_KEY_RSA },
        { "rsa3072_ssh_enc", 1, SSH_KEY_RSA },
        { "ec256_ssh", 0, SSH_KEY_ECDSA }, { "ec256_ssh_enc", 1, SSH_KEY_ECDSA },
        { "ec384_ssh", 0, SSH_KEY_ECDSA }, { "ec384_ssh_enc", 1, SSH_KEY_ECDSA },
        { "ec521_ssh", 0, SSH_KEY_ECDSA }, { "ec521_ssh_enc", 1, SSH_KEY_ECDSA },
        { "rsa2048_pem", 0, SSH_KEY_RSA }, { "rsa2048_pem_enc", 1, SSH_KEY_RSA },
        { "ec256_pem", 0, SSH_KEY_ECDSA }, { "ec256_pem_enc", 1, SSH_KEY_ECDSA }, { "ec521_pem", 0, SSH_KEY_ECDSA },
        { "ec521_pem_enc", 1, SSH_KEY_ECDSA },
        { "rsa2048_pkcs8", 0, SSH_KEY_RSA }, { "ec384_pkcs8", 0, SSH_KEY_ECDSA },
        { "ec256_pem_named", 0, SSH_KEY_ECDSA }, { "ec384_pkcs8_named", 0, SSH_KEY_ECDSA }, { "ec521_pem_named", 0, SSH_KEY_ECDSA },
        { "plain", 0, SSH_KEY_ED25519 }, { "enc_ctr256", 1, SSH_KEY_ED25519 },
    };
    static char text[8192];
    const char *pass = "correct horse", *err;
    char path[128];
    u8 pubfile[1024], msg[40];
    size_t z;
    int n, want_len, rc;

    pattern(msg, sizeof(msg), 21);
    for (z = 0; z < sizeof(zoo) / sizeof(zoo[0]); z++) {
        static const char *rsa_algs[] = { "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa" };
        ssh_key k;
        sbuf blob, sig;
        const char *algs[3];
        int nalgs = 1, a;

        strcpy(path, "tests/keys/"); strcat(path, zoo[z].name);
        n = read_file(path, text, sizeof(text));
        if (n < 0) { printf("  FAIL: cannot read %s\n", path); t_fail++; continue; }
        strcat(path, ".pub");
        want_len = pub_blob_from_file(path, pubfile, sizeof(pubfile));

        rc = ssh_key_parse_private(text, (size_t)n, zoo[z].encrypted ? pass : NULL, &k, &err);
        if (rc != 0) { printf("  FAIL: %s did not parse: %s\n", zoo[z].name, err); t_fail++; continue; }
        CHECK(k.type == zoo[z].type);
        sb_init(&blob); sb_init(&sig);
        CHECK(ssh_key_public_blob(&k, &blob) == 0 && want_len > 0 && (int)blob.len == want_len && memcmp(blob.p, pubfile, blob.len) == 0);

        if (k.type == SSH_KEY_RSA) { algs[0] = rsa_algs[0]; algs[1] = rsa_algs[1]; algs[2] = rsa_algs[2]; nalgs = 3; }
        else algs[0] = ssh_key_algo_name(&k);
        for (a = 0; a < nalgs; a++) {
            const char *why;
            sb_clear(&sig);
            CHECK(ssh_key_sign(&k, algs[a], msg, sizeof(msg), &sig) == 0);
            CHECK(ssh_hostkey_verify(blob.p, blob.len, sig.p, sig.len, algs[a], msg, sizeof(msg), &why) == 0);
            msg[3] ^= 1;
            CHECK(ssh_hostkey_verify(blob.p, blob.len, sig.p, sig.len, algs[a], msg, sizeof(msg), &why) == -1);
            msg[3] ^= 1;
            if (a + 1 < nalgs)                                               /* signature made with another algorithm */
                CHECK(ssh_hostkey_verify(blob.p, blob.len, sig.p, sig.len, algs[a + 1], msg, sizeof(msg), &why) == -1);
        }
        if (k.type == SSH_KEY_ED25519) CHECK(ssh_key_sign(&k, "rsa-sha2-256", msg, sizeof(msg), &sig) == -1);   /* wrong family */
        /* algorithm selection from the server's advertised list */
        if (k.type == SSH_KEY_RSA) {
            CHECK(strcmp(ssh_key_pick_sigalg(&k, "ssh-ed25519,rsa-sha2-512,rsa-sha2-256"), "rsa-sha2-512") == 0);
            CHECK(strcmp(ssh_key_pick_sigalg(&k, "rsa-sha2-256"), "rsa-sha2-256") == 0);
            CHECK(strcmp(ssh_key_pick_sigalg(&k, NULL), "ssh-rsa") == 0);
            CHECK(strcmp(ssh_key_pick_sigalg(&k, "ssh-ed25519"), "ssh-rsa") == 0);
        } else {
            CHECK(strcmp(ssh_key_pick_sigalg(&k, "rsa-sha2-512"), ssh_key_algo_name(&k)) == 0);
        }
        sb_free(&sig); sb_free(&blob);
        ssh_key_wipe(&k);

        if (zoo[z].encrypted) {
            CHECK(ssh_key_parse_private(text, (size_t)n, NULL, &k, &err) == -2);
            CHECK(ssh_key_parse_private(text, (size_t)n, "wrong horse", &k, &err) == -3);
            CHECK(strcmp(err, "incorrect passphrase") == 0);
            CHECK(k.type == SSH_KEY_NONE && k.rsa == NULL);
        }
    }
    /* a host key check must reject a key of a different family than the algorithm claims */
    {
        ssh_key k;
        sbuf blob, sig;
        const char *why;
        n = read_file("tests/keys/rsa2048_ssh", text, sizeof(text));
        ssh_key_parse_private(text, (size_t)n, NULL, &k, &err);
        sb_init(&blob); sb_init(&sig);
        ssh_key_public_blob(&k, &blob);
        ssh_key_sign(&k, "rsa-sha2-256", msg, sizeof(msg), &sig);
        CHECK(ssh_hostkey_verify(blob.p, blob.len, sig.p, sig.len, "ssh-ed25519", msg, sizeof(msg), &why) == -1);
        CHECK(ssh_hostkey_verify(blob.p, blob.len, sig.p, sig.len, "ecdsa-sha2-nistp256", msg, sizeof(msg), &why) == -1);
        CHECK(ssh_hostkey_verify(blob.p, blob.len, sig.p, sig.len, "rsa-sha2-256", msg, 0, &why) == -1);     /* other message */
        CHECK(ssh_hostkey_verify(blob.p, 5, sig.p, sig.len, "rsa-sha2-256", msg, sizeof(msg), &why) == -1);  /* truncated key */
        CHECK(ssh_hostkey_verify(blob.p, blob.len, sig.p, sig.len - 3, "rsa-sha2-256", msg, sizeof(msg), &why) == -1);
        sb_free(&blob); sb_free(&sig);
        ssh_key_wipe(&k);
    }
    /* encrypted PKCS#8 is refused with advice, not misparsed */
    n = read_file("tests/keys/rsa2048_pkcs8_enc", text, sizeof(text));
    {
        ssh_key k;
        CHECK(ssh_key_parse_private(text, (size_t)n, pass, &k, &err) == -1 && strstr(err, "PKCS#8") != NULL);
    }
    /* hostile input: flipped bytes and truncations of every fixture type must fail cleanly */
    for (z = 0; z < 8; z++) {
        static const char *victims[] = { "rsa2048_ssh", "ec256_ssh", "rsa2048_pem", "ec521_pem", "rsa2048_pkcs8", "ec384_pkcs8", "rsa2048_pem_enc", "ec256_ssh_enc" };
        int i;
        n = read_file(victims[z], text, sizeof(text));
        strcpy(path, "tests/keys/"); strcat(path, victims[z]);
        n = read_file(path, text, sizeof(text));
        for (i = 40; i < n - 40; i += 53) {
            ssh_key k;
            char saved = text[i];
            if (saved == '\n' || saved == '-') continue;
            text[i] = (char)(saved == 'B' ? 'C' : 'B');
            rc = ssh_key_parse_private(text, (size_t)n, pass, &k, &err);
            if (rc == 0) ssh_key_wipe(&k);
            CHECK(rc == 0 || rc == -1 || rc == -3);                          /* never a crash */
            text[i] = saved;
        }
        for (i = 20; i < n; i += 97) {
            ssh_key k;
            rc = ssh_key_parse_private(text, (size_t)i, pass, &k, &err);
            if (rc == 0) ssh_key_wipe(&k);
            CHECK(rc != 0 || i > n - 40);                                    /* a truncated file is not a key */
        }
    }
}

static void test_bcrypt_args(void)
{
    u8 key[48];
    CHECK(bcrypt_pbkdf((const u8 *)"pw", 2, (const u8 *)"salt", 4, key, 48, 0) == -1);      /* zero rounds */
    CHECK(bcrypt_pbkdf((const u8 *)"", 0, (const u8 *)"salt", 4, key, 48, 1) == -1);        /* empty password */
    CHECK(bcrypt_pbkdf((const u8 *)"pw", 2, (const u8 *)"salt", 4, key, 0, 1) == -1);       /* no output */
}

static void test_aes(void)
{
    aes_ctr_ctx c;
    u8 out[157], out2[157];
    int i;

    aes_ctr_init(&c, aes_k128, 16, aes_iv);
    aes_ctr_xor(&c, aes_plain, out, aes_plain_LEN);
    CHECK_MEM(out, aes128_ctr_exp, aes_plain_LEN, "aes-128-ctr");

    aes_ctr_init(&c, aes_k256, 32, aes_iv);
    aes_ctr_xor(&c, aes_plain, out, aes_plain_LEN);
    CHECK_MEM(out, aes256_ctr_exp, aes_plain_LEN, "aes-256-ctr");

    /* the stream must be continuous across differently-sized calls */
    aes_ctr_init(&c, aes_k256, 32, aes_iv);
    for (i = 0; i < aes_plain_LEN; i += 5) {
        int n = aes_plain_LEN - i < 5 ? aes_plain_LEN - i : 5;
        aes_ctr_xor(&c, aes_plain + i, out2 + i, n);
    }
    CHECK_MEM(out2, aes256_ctr_exp, aes_plain_LEN, "aes-256-ctr chunked");
}

static void test_chacha(void)
{
    chacha_ctx c;
    u8 zero[300], ks[300], mac[16], msg[300], sealed[64], opened[64];
    chachapoly_ctx cp;
    int i;

    memset(zero, 0, sizeof(zero));
    chacha_keysetup(&c, chacha_key);
    chacha_ivsetup(&c, chacha_iv, 1);
    chacha_xor(&c, zero, ks, 300);
    CHECK_MEM(ks, chacha_ks_exp, 300, "chacha20 keystream");

    poly1305_auth(mac, poly_msg, poly_msg_LEN, poly_key);
    CHECK_MEM(mac, poly_exp, 16, "poly1305 RFC 8439");
    for (i = 0; i < N_POLY; i++) {
        pattern(msg, poly_lens[i], 3);
        poly1305_auth(mac, msg, poly_lens[i], poly_key2);
        CHECK_MEM(mac, poly_exp2[i], 16, "poly1305");
    }

    chachapoly_init(&cp, cp_key);
    chachapoly_seal(&cp, CP_SEQ, sealed, cp_plain, cp_plain_LEN - 4);
    CHECK_MEM(sealed, cp_sealed, cp_sealed_LEN, "chachapoly seal");
    CHECK(chachapoly_peek_length(&cp, CP_SEQ, sealed) == 29);
    CHECK(chachapoly_open(&cp, CP_SEQ, opened, sealed, 29) == 0);
    CHECK_MEM(opened, cp_plain, cp_plain_LEN, "chachapoly open");
    sealed[10] ^= 1;                                     /* tamper */
    CHECK(chachapoly_open(&cp, CP_SEQ, opened, sealed, 29) == -1);
    sealed[10] ^= 1; sealed[40] ^= 0x80;                 /* tamper with the tag (bytes 33..48) */
    CHECK(chachapoly_open(&cp, CP_SEQ, opened, sealed, 29) == -1);
    sealed[40] ^= 0x80;
    CHECK(chachapoly_open(&cp, CP_SEQ + 1, opened, sealed, 29) == -1);   /* wrong seq */
}

static void test_x25519(void)
{
    u8 out[32], a[32], b[32], s1[32], s2[32];
    int i;

    x25519(out, x_a, x_u);
    CHECK_MEM(out, x_exp, 32, "x25519 RFC 7748");
    x25519_base(a, x_alice);
    x25519_base(b, x_bob);
    x25519(s1, x_alice, b);
    x25519(s2, x_bob, a);
    CHECK_MEM(s1, x_shared, 32, "x25519 shared (alice)");
    CHECK_MEM(s2, x_shared, 32, "x25519 shared (bob)");
    for (i = 0; i < N_X; i++) {
        x25519(out, x_sc[i], x_pt[i]);
        CHECK_MEM(out, x_out[i], 32, "x25519 random");
    }
}

static void test_ed25519(void)
{
    int i;
    u8 pk[32], sk[64], sig[64], msg[300];
    for (i = 0; i < N_ED; i++) {
        pattern(msg, ed_mlens[i], 17);
        ed25519_keypair(pk, sk, ed_seed[i]);
        CHECK_MEM(pk, ed_pub_exp[i], 32, "ed25519 public key");
        ed25519_sign(sig, msg, ed_mlens[i], sk);
        CHECK_MEM(sig, ed_sig_exp[i], 64, "ed25519 signature");
        CHECK(ed25519_verify(ed_sig_exp[i], msg, ed_mlens[i], ed_pub_exp[i]) == 0);
        sig[5] ^= 1;
        CHECK(ed25519_verify(sig, msg, ed_mlens[i], pk) != 0);            /* bad R */
        sig[5] ^= 1; sig[40] ^= 1;
        CHECK(ed25519_verify(sig, msg, ed_mlens[i], pk) != 0);            /* bad S */
        sig[40] ^= 1;
        if (ed_mlens[i]) {
            msg[0] ^= 1;
            CHECK(ed25519_verify(sig, msg, ed_mlens[i], pk) != 0);        /* bad msg */
        }
    }
}

static void test_rng(void)
{
    u8 a[32], b[32];
    /* Not seeded yet: must refuse rather than emit predictable bytes. */
    CHECK(!ssh_rng_ready());
    CHECK(ssh_rng_bytes(a, 32) == -1);
    ssh_rng_add("x", 1, 100);                 /* below threshold */
    CHECK(ssh_rng_bytes(a, 32) == -1);
    if (ssh_rng_seed_system() == 0) {         /* e.g. OPENSTEP: no /dev/urandom */
        printf("  note: no system entropy device here; crediting synthetic entropy for the test\n");
        ssh_rng_add("synthetic", 9, 256);
    }
    CHECK(ssh_rng_ready());
    CHECK(ssh_rng_bytes(a, 32) == 0);
    CHECK(ssh_rng_bytes(b, 32) == 0);
    CHECK(memcmp(a, b, 32) != 0);
    CHECK(ssh_ct_memcmp(a, a, 32) == 0 && ssh_ct_memcmp(a, b, 32) != 0);
}

int main(void)
{
    test_sha(); test_hmac(); test_sha1(); test_knownhosts(); test_aes(); test_aes_blocks(); test_cbc_chain();
    test_blowfish(); test_encrypted_keys(); test_bcrypt_args(); test_key_zoo();
 test_chacha();
    test_x25519(); test_ed25519(); test_rng();
    test_keygen();                       /* after test_rng: that test needs an unseeded pool */
    TEST_DONE("crypto");
}
