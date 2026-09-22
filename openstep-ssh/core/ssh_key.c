#include <stdlib.h>
#include <string.h>
#include "ssh_key.h"
#include "sha2.h"
#include "nacl.h"
#include "aes.h"
#include "bcrypt.h"
#include "md5.h"
#include "rng.h"

static const char BEGIN_LINE[] = "-----BEGIN OPENSSH PRIVATE KEY-----";
static const char END_LINE[]   = "-----END OPENSSH PRIVATE KEY-----";
static const char AUTH_MAGIC[] = "openssh-key-v1";      /* followed by a NUL */

static int name_in_list(const char *list, const char *name)
{
    size_t n = strlen(name);
    const char *p = list;
    while (p && *p) {
        const char *e = strchr(p, ',');
        size_t l = e ? (size_t)(e - p) : strlen(p);
        if (l == n && memcmp(p, name, n) == 0) return 1;
        if (!e) break;
        p = e + 1;
    }
    return 0;
}

void ssh_key_wipe(ssh_key *k)
{
    if (k->rsa) { rsa_priv_free(k->rsa); free(k->rsa); }
    bn_free(&k->ec_d);
    ec_point_free(&k->ec_q);
    ssh_wipe(k, sizeof(*k));
}

static void key_init(ssh_key *k) { memset(k, 0, sizeof(*k)); bn_init(&k->ec_d); ec_point_init(&k->ec_q); }

/* ------------------------------------------------------------------ */
/* names, public blobs, algorithm choice                               */
/* ------------------------------------------------------------------ */

static const char *ec_key_name(int curve)
{
    return curve == EC_P256 ? "ecdsa-sha2-nistp256" : curve == EC_P384 ? "ecdsa-sha2-nistp384" : "ecdsa-sha2-nistp521";
}

const char *ssh_key_algo_name(const ssh_key *k)
{
    switch (k->type) {
    case SSH_KEY_ED25519: return "ssh-ed25519";
    case SSH_KEY_RSA:     return "ssh-rsa";
    case SSH_KEY_ECDSA:   return ec_key_name(k->curve);
    default:              return "";
    }
}

static int put_bn_mpint(sbuf *b, const bn *v)
{
    u8 tmp[2100];
    size_t n = (size_t)(bn_bits(v) + 7) / 8;
    if (n > sizeof(tmp) || bn_to_bytes(v, tmp, n) != 0) return -1;
    return sb_put_mpint(b, tmp, n);
}

int ssh_key_public_blob(const ssh_key *k, sbuf *out)
{
    u8 q[133];
    const ec_curve *c;
    switch (k->type) {
    case SSH_KEY_ED25519:
        sb_put_cstr(out, "ssh-ed25519");
        sb_put_str(out, k->pk, 32);
        break;
    case SSH_KEY_RSA:
        sb_put_cstr(out, "ssh-rsa");
        if (put_bn_mpint(out, &k->rsa->e) < 0 || put_bn_mpint(out, &k->rsa->n) < 0) return -1;
        break;
    case SSH_KEY_ECDSA:
        c = ec_curve_get(k->curve);
        if (!c || ec_encode_point(c, &k->ec_q, q) < 0) return -1;
        sb_put_cstr(out, ec_key_name(k->curve));
        sb_put_cstr(out, c->ssh_name);
        sb_put_str(out, q, (size_t)(1 + 2 * c->nbytes));
        break;
    default:
        return -1;
    }
    return out->oom ? -1 : 0;
}

const char *ssh_key_pick_sigalg(const ssh_key *k, const char *algs)
{
    if (k->type != SSH_KEY_RSA) return ssh_key_algo_name(k);
    if (algs && name_in_list(algs, "rsa-sha2-512")) return "rsa-sha2-512";
    if (algs && name_in_list(algs, "rsa-sha2-256")) return "rsa-sha2-256";
    return "ssh-rsa";
}

static int rsa_hash_for(const char *alg)
{
    if (!strcmp(alg, "rsa-sha2-512")) return RSA_SHA512;
    if (!strcmp(alg, "rsa-sha2-256")) return RSA_SHA256;
    if (!strcmp(alg, "ssh-rsa")) return RSA_SHA1;
    return 0;
}

int ssh_key_sign(const ssh_key *k, const char *sigalg, const u8 *data, size_t len, sbuf *sigblob)
{
    if (!sigalg) sigalg = ssh_key_pick_sigalg(k, NULL);
    if (k->type == SSH_KEY_ED25519) {
        u8 sig[64];
        if (strcmp(sigalg, "ssh-ed25519") != 0) return -1;
        ed25519_sign(sig, data, len, k->sk);
        sb_put_cstr(sigblob, "ssh-ed25519");
        sb_put_str(sigblob, sig, 64);
    } else if (k->type == SSH_KEY_RSA) {
        int hash = rsa_hash_for(sigalg);
        size_t n = (size_t)rsa_size_bytes(&k->rsa->n);
        u8 *sig;
        if (!hash) return -1;
        sig = (u8 *)malloc(n);
        if (!sig) return -1;
        if (rsa_sign(k->rsa, hash, data, len, sig) != 0) { free(sig); return -1; }
        sb_put_cstr(sigblob, sigalg);
        sb_put_str(sigblob, sig, n);
        free(sig);
    } else if (k->type == SSH_KEY_ECDSA) {
        const ec_curve *c = ec_curve_get(k->curve);
        u8 h[64];
        size_t hl;
        bn r, s;
        sbuf inner;
        int rc = -1;
        if (!c || strcmp(sigalg, ec_key_name(k->curve)) != 0) return -1;
        bn_init(&r); bn_init(&s); sb_init(&inner);
        ec_hash(c, data, len, h, &hl);
        if (ecdsa_sign(c, &k->ec_d, h, hl, &r, &s) == 0 && put_bn_mpint(&inner, &r) == 0 && put_bn_mpint(&inner, &s) == 0) {
            sb_put_cstr(sigblob, sigalg);
            sb_put_str(sigblob, inner.p, inner.len);
            rc = 0;
        }
        bn_free(&r); bn_free(&s); sb_free(&inner);
        return rc < 0 ? -1 : (sigblob->oom ? -1 : 0);
    } else {
        return -1;
    }
    return sigblob->oom ? -1 : 0;
}

/* ------------------------------------------------------------------ */
/* verification of a server's host-key signature                       */
/* ------------------------------------------------------------------ */

int ssh_blob_type(const u8 *blob, size_t len, char *out, size_t outsz)
{
    sreader r;
    size_t n;
    const u8 *t;
    sr_init(&r, blob, len);
    t = sr_str(&r, &n);
    if (r.err || n == 0 || n >= outsz) return -1;
    memcpy(out, t, n);
    out[n] = '\0';
    return 0;
}

int ssh_hostkey_verify(const u8 *keyblob, size_t keylen, const u8 *sigblob, size_t siglen,
                       const char *expect_alg, const u8 *msg, size_t msglen, const char **err)
{
    sreader kr, sr;
    const u8 *kt, *sa, *sd;
    size_t ktl, sal, sdl;
    char alg[40];

    *err = "malformed host key or signature";
    sr_init(&kr, keyblob, keylen);
    sr_init(&sr, sigblob, siglen);
    kt = sr_str(&kr, &ktl);
    sa = sr_str(&sr, &sal);
    sd = sr_str(&sr, &sdl);
    if (kr.err || sr.err || sal == 0 || sal >= sizeof(alg)) return -1;
    memcpy(alg, sa, sal); alg[sal] = '\0';
    if (strcmp(alg, expect_alg) != 0) { *err = "host key signature uses a different algorithm than was negotiated"; return -1; }

    if (ktl == 11 && memcmp(kt, "ssh-ed25519", 11) == 0) {
        size_t pkl;
        const u8 *pk = sr_str(&kr, &pkl);
        if (kr.err || pkl != 32 || sdl != 64 || strcmp(alg, "ssh-ed25519") != 0) return -1;
        if (ed25519_verify(sd, msg, msglen, pk) != 0) { *err = "host key signature verification failed (possible man-in-the-middle)"; return -1; }
        return 0;
    }
    if (ktl == 7 && memcmp(kt, "ssh-rsa", 7) == 0) {
        size_t el, nl;
        const u8 *e = sr_str(&kr, &el), *n = sr_str(&kr, &nl);
        rsa_pub pub;
        int hash = rsa_hash_for(alg), rc;
        if (kr.err || !hash) return -1;
        rsa_pub_init(&pub);
        if (bn_from_bytes(&pub.e, e, el) < 0 || bn_from_bytes(&pub.n, n, nl) < 0) { rsa_pub_free(&pub); return -1; }
        rc = rsa_verify(&pub, hash, msg, msglen, sd, sdl);
        rsa_pub_free(&pub);
        if (rc != 0) { *err = "host key signature verification failed (possible man-in-the-middle, or an RSA key that is too small)"; return -1; }
        return 0;
    }
    if (ktl == 19 && memcmp(kt, "ecdsa-sha2-nistp", 16) == 0) {
        int curve = ec_curve_by_name((const char *)kt + 11, ktl - 11);
        const ec_curve *c = curve >= 0 ? ec_curve_get(curve) : NULL;
        size_t cnl, ql;
        const u8 *cn = sr_str(&kr, &cnl), *q = sr_str(&kr, &ql);
        ec_point Q;
        sreader dr;
        const u8 *rb, *sb2;
        size_t rl, sl2;
        bn r, s;
        u8 h[64];
        size_t hl;
        int rc = -1;
        if (!c || kr.err || strcmp(alg, (const char *)ec_key_name(curve)) != 0 || cnl != 8 || memcmp(cn, c->ssh_name, 8) != 0) return -1;
        ec_point_init(&Q); bn_init(&r); bn_init(&s);
        sr_init(&dr, sd, sdl);
        rb = sr_str(&dr, &rl); sb2 = sr_str(&dr, &sl2);
        if (!dr.err && ec_decode_point(c, q, ql, &Q) == 0 && bn_from_bytes(&r, rb, rl) == 0 && bn_from_bytes(&s, sb2, sl2) == 0) {
            ec_hash(c, msg, msglen, h, &hl);
            rc = ecdsa_verify(c, &Q, h, hl, &r, &s);
        }
        ec_point_free(&Q); bn_free(&r); bn_free(&s);
        if (rc != 0) { *err = "host key signature verification failed (possible man-in-the-middle)"; return -1; }
        return 0;
    }
    *err = "unsupported host key type";
    return -1;
}

int ssh_fingerprint_sha256(const u8 *blob, size_t len, char *out, size_t outsz)
{
    u8 d[32];
    char b[48];
    int n;
    sha256(blob, len, d);
    n = b64_encode(d, 32, b, sizeof(b), 0);
    if (n < 0 || outsz < (size_t)n + 8) return -1;
    memcpy(out, "SHA256:", 7);
    memcpy(out + 7, b, (size_t)n + 1);
    return 0;
}

/* ------------------------------------------------------------------ */
/* parsing private keys                                                */
/* ------------------------------------------------------------------ */

/* Locate the base64 body between the OpenSSH BEGIN/END markers. */
static int armor_body(const char *text, size_t len, const char **body, size_t *blen)
{
    const char *b = NULL, *e = NULL, *p;
    size_t i;
    for (i = 0; i + sizeof(BEGIN_LINE) - 1 <= len; i++)
        if (memcmp(text + i, BEGIN_LINE, sizeof(BEGIN_LINE) - 1) == 0) { b = text + i + sizeof(BEGIN_LINE) - 1; break; }
    if (!b) return -1;
    for (p = b; (size_t)(p - text) + sizeof(END_LINE) - 1 <= len; p++)
        if (memcmp(p, END_LINE, sizeof(END_LINE) - 1) == 0) { e = p; break; }
    if (!e) return -1;
    *body = b; *blen = (size_t)(e - b);
    return 0;
}

static int copy_comment(ssh_key *out, const u8 *cm, size_t cl)
{
    if (cl >= sizeof(out->comment)) cl = sizeof(out->comment) - 1;
    memcpy(out->comment, cm, cl);
    out->comment[cl] = '\0';
    return 0;
}

/* Finish an RSA key from big-endian byte strings (ssh mpints or DER integers). */
static int rsa_from_parts(ssh_key *out, const u8 *n, size_t nl, const u8 *e, size_t el, const u8 *d, size_t dl,
                          const u8 *iqmp, size_t il, const u8 *p, size_t pl, const u8 *q, size_t ql, const char **err)
{
    rsa_priv *r = (rsa_priv *)malloc(sizeof(*r));
    if (!r) { *err = "out of memory"; return -1; }
    rsa_priv_init(r);
    if (bn_from_bytes(&r->n, n, nl) < 0 || bn_from_bytes(&r->e, e, el) < 0 || bn_from_bytes(&r->d, d, dl) < 0 ||
        bn_from_bytes(&r->iqmp, iqmp, il) < 0 || bn_from_bytes(&r->p, p, pl) < 0 || bn_from_bytes(&r->q, q, ql) < 0 ||
        rsa_priv_prepare(r) != 0) {
        rsa_priv_free(r); free(r);
        *err = "unusable RSA key (too small, or the numbers are inconsistent)";
        return -1;
    }
    out->rsa = r;
    out->type = SSH_KEY_RSA;
    return 0;
}

static int ecdsa_from_parts(ssh_key *out, int curve, const u8 *q, size_t ql, const u8 *d, size_t dl, const char **err)
{
    const ec_curve *c = ec_curve_get(curve);
    if (!c) { *err = "out of memory"; return -1; }
    out->curve = curve;
    if (bn_from_bytes(&out->ec_d, d, dl) < 0 || bn_is_zero(&out->ec_d) || bn_cmp(&out->ec_d, &c->n) >= 0) {
        *err = "invalid ECDSA private key"; return -1;
    }
    if (q) {
        if (ec_decode_point(c, q, ql, &out->ec_q) != 0) { *err = "invalid ECDSA public point"; return -1; }
    } else if (ec_mul_base(c, &out->ec_q, &out->ec_d) != 0 || out->ec_q.inf) {              /* derive it */
        *err = "cannot derive the ECDSA public key"; return -1;
    }
    out->type = SSH_KEY_ECDSA;
    return 0;
}

/* The decrypted OpenSSH private section, after the two check ints. */
static int parse_openssh_key(sreader *pr, ssh_key *out, const char **err)
{
    size_t kl, n, cl;
    const u8 *kt = sr_str(pr, &kl), *cm;
    if (pr->err) return -1;

    if (kl == 11 && memcmp(kt, "ssh-ed25519", 11) == 0) {
        const u8 *pkd = sr_str(pr, &n), *skd;
        if (pr->err || n != 32) return -1;
        memcpy(out->pk, pkd, 32);
        skd = sr_str(pr, &n);
        if (pr->err || n != 64) return -1;
        memcpy(out->sk, skd, 64);
        cm = sr_str(pr, &cl);
        if (pr->err) return -1;
        copy_comment(out, cm, cl);
        if (memcmp(out->sk + 32, out->pk, 32) != 0) { *err = "corrupt key (public half mismatch)"; return -1; }
        out->type = SSH_KEY_ED25519;
        return 0;
    }
    if (kl == 7 && memcmp(kt, "ssh-rsa", 7) == 0) {
        size_t nl, el, dl, il, pl, ql;
        const u8 *nn = sr_str(pr, &nl), *ee = sr_str(pr, &el), *dd = sr_str(pr, &dl),
                 *ii = sr_str(pr, &il), *pp = sr_str(pr, &pl), *qq = sr_str(pr, &ql);
        if (pr->err) return -1;
        cm = sr_str(pr, &cl);
        if (pr->err) return -1;
        copy_comment(out, cm, cl);
        return rsa_from_parts(out, nn, nl, ee, el, dd, dl, ii, il, pp, pl, qq, ql, err);
    }
    if (kl == 19 && memcmp(kt, "ecdsa-sha2-nistp", 16) == 0) {
        int curve = ec_curve_by_name((const char *)kt + 11, kl - 11);
        size_t cnl, ql, dl;
        const u8 *cn = sr_str(pr, &cnl), *q = sr_str(pr, &ql), *d = sr_str(pr, &dl);
        const ec_curve *c;
        if (pr->err || curve < 0) return -1;
        c = ec_curve_get(curve);
        if (!c || cnl != 8 || memcmp(cn, c->ssh_name, 8) != 0) return -1;
        cm = sr_str(pr, &cl);
        if (pr->err) return -1;
        copy_comment(out, cm, cl);
        return ecdsa_from_parts(out, curve, q, ql, d, dl, err);
    }
    *err = "unsupported key type (supported: ssh-ed25519, ssh-rsa, ecdsa-sha2-nistp256/384/521)";
    return -1;
}

/* Supported private-key ciphers (OpenSSH lists these by name in the key file). */
static const struct { const char *name; int keylen, cbc; } KEY_CIPHERS[] = {
    { "aes256-ctr", 32, 0 }, { "aes192-ctr", 24, 0 }, { "aes128-ctr", 16, 0 },
    { "aes256-cbc", 32, 1 }, { "aes192-cbc", 24, 1 }, { "aes128-cbc", 16, 1 },
};
#define N_KEY_CIPHERS ((int)(sizeof(KEY_CIPHERS) / sizeof(KEY_CIPHERS[0])))
#define MAX_BCRYPT_ROUNDS 4096          /* a hostile key file must not be able to hang us */

static int parse_openssh_format(const char *text, size_t len, const char *passphrase,
                                ssh_key *out, const char **err)
{
    const char *body;
    size_t blen, n, cl, kl, ol;
    u8 *raw = NULL, *dec = NULL;
    int rawlen, rc = -1, i, ci = -1;
    sreader r, pr, kr;
    const u8 *p, *cipher, *kdf, *kdfopts, *pubblob, *priv;
    u32 nkeys, c1, c2;
    int encrypted;

    if (armor_body(text, len, &body, &blen) < 0) return -1;
    raw = (u8 *)malloc(blen / 4 * 3 + 8);
    if (!raw) { *err = "out of memory"; return -1; }
    rawlen = b64_decode(body, blen, raw, blen / 4 * 3 + 8);
    if (rawlen < 0) { *err = "bad base64 in key file"; goto done; }

    sr_init(&r, raw, (size_t)rawlen);
    p = sr_bytes(&r, sizeof(AUTH_MAGIC));
    if (!p || memcmp(p, AUTH_MAGIC, sizeof(AUTH_MAGIC)) != 0) goto done;
    cipher = sr_str(&r, &cl); kdf = sr_str(&r, &kl); kdfopts = sr_str(&r, &ol);
    nkeys = sr_u32(&r);
    if (r.err || nkeys != 1) { *err = "only single-key files are supported"; goto done; }
    pubblob = sr_str(&r, &n); (void)pubblob;
    priv = sr_str(&r, &n);
    if (r.err) { *err = "truncated key file"; goto done; }

    encrypted = !(cl == 4 && memcmp(cipher, "none", 4) == 0 && kl == 4 && memcmp(kdf, "none", 4) == 0);
    dec = (u8 *)malloc(n ? n : 1);
    if (!dec) { *err = "out of memory"; goto done; }
    memcpy(dec, priv, n);

    if (encrypted) {
        const u8 *salt;
        size_t saltlen;
        u32 rounds;
        u8 material[32 + 16];
        aes_ctr_ctx aes;
        int keylen;

        if (!(kl == 6 && memcmp(kdf, "bcrypt", 6) == 0)) { *err = "key uses an unsupported key-derivation function"; goto done; }
        for (i = 0; i < N_KEY_CIPHERS; i++)
            if (strlen(KEY_CIPHERS[i].name) == cl && memcmp(KEY_CIPHERS[i].name, cipher, cl) == 0) { ci = i; break; }
        if (ci < 0) { *err = "key is encrypted with an unsupported cipher (supported: aes-ctr, aes-cbc)"; goto done; }
        if (n == 0 || n % 16 != 0) { *err = "corrupt encrypted key (bad length)"; goto done; }
        if (!passphrase) { *err = "key is passphrase-protected"; rc = -2; goto done; }

        sr_init(&kr, kdfopts, ol);
        salt = sr_str(&kr, &saltlen);
        rounds = sr_u32(&kr);
        if (kr.err || saltlen == 0) { *err = "corrupt key-derivation parameters"; goto done; }
        if (rounds < 1 || rounds > MAX_BCRYPT_ROUNDS) { *err = "key-derivation cost is out of range"; goto done; }

        keylen = KEY_CIPHERS[ci].keylen;
        if (bcrypt_pbkdf((const u8 *)passphrase, strlen(passphrase), salt, saltlen,
                         material, (size_t)keylen + 16, rounds) != 0) {
            *err = "key derivation failed";
            goto done;
        }
        aes_ctr_init(&aes, material, keylen, material + keylen);   /* the IV follows the key */
        if (KEY_CIPHERS[ci].cbc) aes_cbc_decrypt(&aes, material + keylen, dec, dec, n);
        else aes_ctr_xor(&aes, dec, dec, n);
        ssh_wipe(material, sizeof(material));
        ssh_wipe(&aes, sizeof(aes));
    }

    sr_init(&pr, dec, n);
    c1 = sr_u32(&pr); c2 = sr_u32(&pr);
    if (pr.err || c1 != c2) {
        if (encrypted) { *err = "incorrect passphrase"; rc = -3; }
        else *err = "corrupt key (check bytes differ)";
        goto done;
    }
    if (parse_openssh_key(&pr, out, err) != 0) {
        if (!strcmp(*err, "not an OpenSSH private key")) *err = "corrupt or unsupported key";
        goto done;
    }
    *err = "ok";
    rc = 0;
done:
    if (raw) { ssh_wipe(raw, blen / 4 * 3 + 8); free(raw); }
    if (dec) { ssh_wipe(dec, n ? n : 1); free(dec); }
    return rc;
}

/* ---------------- traditional PEM / DER ---------------- */

static int der_read(const u8 **p, const u8 *end, int *tag, const u8 **val, size_t *len)
{
    const u8 *q = *p;
    size_t l;
    if (end - q < 2) return -1;
    *tag = q[0];
    l = q[1];
    q += 2;
    if (l & 0x80) {
        int nb = (int)(l & 0x7f);
        if (nb == 0 || nb > 4 || end - q < nb) return -1;
        l = 0;
        while (nb--) l = (l << 8) | *q++;
    }
    if ((size_t)(end - q) < l) return -1;
    *val = q; *len = l;
    *p = q + l;
    return 0;
}

static int der_expect(const u8 **p, const u8 *end, int want, const u8 **val, size_t *len)
{
    int tag;
    if (der_read(p, end, &tag, val, len) != 0 || tag != want) return -1;
    return 0;
}

/* an INTEGER as a big-endian magnitude (drops the sign-padding zero) */
static int der_int(const u8 **p, const u8 *end, const u8 **val, size_t *len)
{
    if (der_expect(p, end, 0x02, val, len) != 0 || *len == 0) return -1;
    while (*len > 1 && **val == 0) { (*val)++; (*len)--; }
    return 0;
}

static const u8 OID_P256[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
static const u8 OID_P384[] = { 0x2b, 0x81, 0x04, 0x00, 0x22 };
static const u8 OID_P521[] = { 0x2b, 0x81, 0x04, 0x00, 0x23 };
static const u8 OID_RSA[]  = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
static const u8 OID_EC[]   = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };

static int curve_from_oid(const u8 *oid, size_t l)
{
    if (l == sizeof(OID_P256) && !memcmp(oid, OID_P256, l)) return EC_P256;
    if (l == sizeof(OID_P384) && !memcmp(oid, OID_P384, l)) return EC_P384;
    if (l == sizeof(OID_P521) && !memcmp(oid, OID_P521, l)) return EC_P521;
    return -1;
}


/* ECParameters as found in EC keys: a named-curve OID, or (LibreSSL / older tools) the full explicit
 * parameters.  Explicit ones are accepted only if every number equals a curve we know. */
static int curve_from_params(const u8 *p, size_t len)
{
    const u8 *end = p + len, *v, *seq, *fs, *cs;
    size_t vl, sl, fl, cl;
    int tag, id;
    if (len == 0) return -1;
    if (p[0] == 0x06) {                                              /* named curve */
        if (der_expect(&p, end, 0x06, &v, &vl) != 0) return -1;
        return curve_from_oid(v, vl);
    }
    if (der_expect(&p, end, 0x30, &seq, &sl) != 0) return -1;         /* explicit */
    p = seq; end = seq + sl;
    {
        const u8 *ver, *fp, *pp, *op, *ap, *bp, *gp, *np;
        size_t verl, ppl, opl, apl, bpl, gpl, npl;
        int match = -1;
        bn P, A, B, N, gx, gy, cP, cA;
        if (der_int(&p, end, &ver, &verl) != 0 || verl != 1 || ver[0] != 1) return -1;
        if (der_expect(&p, end, 0x30, &fs, &fl) != 0) return -1;      /* fieldID */
        fp = fs;
        if (der_expect(&fp, fs + fl, 0x06, &op, &opl) != 0) return -1;
        if (der_int(&fp, fs + fl, &pp, &ppl) != 0) return -1;
        if (der_expect(&p, end, 0x30, &cs, &cl) != 0) return -1;      /* curve { a, b [, seed] } */
        { const u8 *cp = cs;
          if (der_expect(&cp, cs + cl, 0x04, &ap, &apl) != 0 || der_expect(&cp, cs + cl, 0x04, &bp, &bpl) != 0) return -1; }
        if (der_expect(&p, end, 0x04, &gp, &gpl) != 0) return -1;     /* base point, uncompressed */
        if (der_int(&p, end, &np, &npl) != 0) return -1;
        (void)tag;
        bn_init(&P); bn_init(&A); bn_init(&B); bn_init(&N); bn_init(&gx); bn_init(&gy); bn_init(&cP); bn_init(&cA);
        if (gpl < 3 || gp[0] != 4 || (gpl - 1) % 2) goto out;
        if (bn_from_bytes(&P, pp, ppl) < 0 || bn_from_bytes(&A, ap, apl) < 0 || bn_from_bytes(&B, bp, bpl) < 0 ||
            bn_from_bytes(&N, np, npl) < 0 || bn_from_bytes(&gx, gp + 1, (gpl - 1) / 2) < 0 ||
            bn_from_bytes(&gy, gp + 1 + (gpl - 1) / 2, (gpl - 1) / 2) < 0) goto out;
        for (id = 0; id < EC_NCURVES; id++) {
            const ec_curve *c = ec_curve_get(id);
            if (c && bn_cmp(&P, &c->p) == 0 && bn_cmp(&A, &c->a) == 0 && bn_cmp(&B, &c->b) == 0 &&
                bn_cmp(&N, &c->n) == 0 && bn_cmp(&gx, &c->gx) == 0 && bn_cmp(&gy, &c->gy) == 0) { match = id; break; }
        }
    out:
        bn_free(&P); bn_free(&A); bn_free(&B); bn_free(&N); bn_free(&gx); bn_free(&gy); bn_free(&cP); bn_free(&cA);
        return match;
    }
}

static int parse_pkcs1_rsa(const u8 *der, size_t len, ssh_key *out, const char **err)
{
    const u8 *p = der, *end = der + len, *seq, *v[9];
    size_t sl, vl[9];
    int i;
    if (der_expect(&p, end, 0x30, &seq, &sl) != 0) return -1;
    p = seq; end = seq + sl;
    if (der_int(&p, end, &v[0], &vl[0]) != 0 || vl[0] != 1 || v[0][0] != 0) return -1;          /* version 0 */
    for (i = 1; i < 9; i++) if (der_int(&p, end, &v[i], &vl[i]) != 0) return -1;
    /* order: n e d p q dp dq qinv */
    return rsa_from_parts(out, v[1], vl[1], v[2], vl[2], v[3], vl[3], v[8], vl[8], v[4], vl[4], v[5], vl[5], err);
}

static int parse_sec1_ec(const u8 *der, size_t len, int curve_hint, ssh_key *out, const char **err)
{
    const u8 *p = der, *end = der + len, *seq, *v, *d, *inner, *bits;
    size_t sl, vl, dl, il, bl;
    int curve = curve_hint;
    const u8 *q = NULL;
    size_t ql = 0;
    if (der_expect(&p, end, 0x30, &seq, &sl) != 0) return -1;
    p = seq; end = seq + sl;
    if (der_int(&p, end, &v, &vl) != 0 || vl != 1 || v[0] != 1) return -1;                     /* version 1 */
    if (der_expect(&p, end, 0x04, &d, &dl) != 0) return -1;
    while (p < end) {
        int tag;
        if (der_read(&p, end, &tag, &inner, &il) != 0) return -1;
        if (tag == 0xa0) {
            curve = curve_from_params(inner, il);
        } else if (tag == 0xa1) {
            const u8 *ip = inner;
            if (der_expect(&ip, inner + il, 0x03, &bits, &bl) != 0 || bl < 2 || bits[0] != 0) return -1;
            q = bits + 1; ql = bl - 1;
        }
    }
    if (curve < 0) { *err = "unsupported or missing elliptic curve"; return -1; }
    return ecdsa_from_parts(out, curve, q, ql, d, dl, err);
}

static int parse_pkcs8(const u8 *der, size_t len, ssh_key *out, const char **err)
{
    const u8 *p = der, *end = der + len, *seq, *v, *alg, *oid, *inner, *ip;
    size_t sl, vl, al, ol, il;
    int curve = -1;
    if (der_expect(&p, end, 0x30, &seq, &sl) != 0) return -1;
    p = seq; end = seq + sl;
    if (der_int(&p, end, &v, &vl) != 0) return -1;
    if (der_expect(&p, end, 0x30, &alg, &al) != 0) return -1;
    ip = alg;
    if (der_expect(&ip, alg + al, 0x06, &oid, &ol) != 0) return -1;
    if (der_expect(&p, end, 0x04, &inner, &il) != 0) return -1;
    if (ol == sizeof(OID_RSA) && !memcmp(oid, OID_RSA, ol)) return parse_pkcs1_rsa(inner, il, out, err);
    if (ol == sizeof(OID_EC) && !memcmp(oid, OID_EC, ol)) {
        curve = curve_from_params(ip, (size_t)(alg + al - ip));
        return parse_sec1_ec(inner, il, curve, out, err);
    }
    *err = "unsupported PKCS#8 key algorithm";
    return -1;
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* OpenSSL's EVP_BytesToKey with MD5 and one iteration. */
static void bytes_to_key(const char *pass, const u8 *salt8, u8 *key, size_t keylen)
{
    u8 d[16];
    size_t have = 0, take;
    int first = 1;
    md5_ctx c;
    while (have < keylen) {
        md5_init(&c);
        if (!first) md5_update(&c, d, 16);
        md5_update(&c, pass, strlen(pass));
        md5_update(&c, salt8, 8);
        md5_final(&c, d);
        first = 0;
        take = keylen - have < 16 ? keylen - have : 16;
        memcpy(key + have, d, take);
        have += take;
    }
    ssh_wipe(d, sizeof(d));
}

static int parse_pem_format(const char *text, size_t len, const char *passphrase, ssh_key *out, const char **err)
{
    static const char *kinds[] = { "RSA PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "DSA PRIVATE KEY" };
    const char *p = text, *end = text + len, *body, *endmark, *line;
    char begin[48], finish[48];
    int kind = -1, i, encrypted = 0, keylen = 0, rc = -1;
    u8 iv[16];
    u8 *der = NULL;
    size_t derlen, blen;
    char *b64 = NULL;

    for (i = 0; i < 5; i++) {
        size_t bl;
        strcpy(begin, "-----BEGIN "); strcat(begin, kinds[i]); strcat(begin, "-----");
        bl = strlen(begin);
        for (p = text; p + bl <= end; p++) if (memcmp(p, begin, bl) == 0) { kind = i; break; }
        if (kind == i) { body = p + bl; break; }
    }
    if (kind < 0) return -1;
    if (kind == 3) { *err = "PKCS#8 encrypted keys are not supported; convert with: ssh-keygen -p -m PEM -f KEY"; return -1; }
    if (kind == 4) { *err = "DSA keys are not supported"; return -1; }
    strcpy(finish, "-----END "); strcat(finish, kinds[kind]); strcat(finish, "-----");
    endmark = NULL;
    for (p = body; p + strlen(finish) <= end; p++) if (memcmp(p, finish, strlen(finish)) == 0) { endmark = p; break; }
    if (!endmark) return -1;

    /* optional RFC 1421 headers */
    line = body;
    while (line < endmark && (*line == '\r' || *line == '\n')) line++;
    while (line < endmark) {
        const char *eol = line;
        while (eol < endmark && *eol != '\n') eol++;
        if (!memchr(line, ':', (size_t)(eol - line))) break;                       /* first non-header line: the base64 body */
        if ((size_t)(eol - line) > 10 && memcmp(line, "Proc-Type:", 10) == 0 && strstr(line, "ENCRYPTED") && strstr(line, "ENCRYPTED") < eol)
            encrypted = 1;
        if ((size_t)(eol - line) > 9 && memcmp(line, "DEK-Info:", 9) == 0) {
            const char *c = line + 9;
            int j;
            while (c < eol && *c == ' ') c++;
            if (eol - c > 12 && !memcmp(c, "AES-128-CBC,", 12)) { keylen = 16; c += 12; }
            else if (eol - c > 12 && !memcmp(c, "AES-192-CBC,", 12)) { keylen = 24; c += 12; }
            else if (eol - c > 12 && !memcmp(c, "AES-256-CBC,", 12)) { keylen = 32; c += 12; }
            else { *err = "key is encrypted with an unsupported cipher (supported: AES-CBC; convert 3DES keys with ssh-keygen -p -m PEM)"; return -1; }
            for (j = 0; j < 16; j++) {
                int hi = c + 2 * j + 1 < eol ? hexval(c[2 * j]) : -1, lo = c + 2 * j + 1 < eol ? hexval(c[2 * j + 1]) : -1;
                if (hi < 0 || lo < 0) { *err = "bad DEK-Info IV"; return -1; }
                iv[j] = (u8)(hi * 16 + lo);
            }
        }
        line = eol < endmark ? eol + 1 : eol;
    }
    blen = (size_t)(endmark - line);
    b64 = (char *)malloc(blen + 1);
    der = (u8 *)malloc(blen / 4 * 3 + 8);
    if (!b64 || !der) { *err = "out of memory"; goto done; }
    memcpy(b64, line, blen);
    { int n = b64_decode(b64, blen, der, blen / 4 * 3 + 8); if (n < 0) { *err = "bad base64 in key file"; goto done; } derlen = (size_t)n; }

    if (encrypted) {
        aes_ctr_ctx aes;
        u8 key[32], pad;
        if (keylen == 0) { *err = "encrypted key without DEK-Info"; goto done; }
        if (derlen == 0 || derlen % 16) { *err = "corrupt encrypted key (bad length)"; goto done; }
        if (!passphrase) { *err = "key is passphrase-protected"; rc = -2; goto done; }
        bytes_to_key(passphrase, iv, key, (size_t)keylen);
        aes_ctr_init(&aes, key, keylen, iv);
        aes_cbc_decrypt(&aes, iv, der, der, derlen);
        ssh_wipe(key, sizeof(key)); ssh_wipe(&aes, sizeof(aes));
        pad = der[derlen - 1];
        if (pad < 1 || pad > 16 || pad > derlen) { *err = "incorrect passphrase"; rc = -3; goto done; }
        for (i = 0; i < pad; i++) if (der[derlen - 1 - (size_t)i] != pad) { *err = "incorrect passphrase"; rc = -3; goto done; }
        derlen -= pad;
    }
    if (kind == 0) rc = parse_pkcs1_rsa(der, derlen, out, err);
    else if (kind == 1) rc = parse_sec1_ec(der, derlen, -1, out, err);
    else rc = parse_pkcs8(der, derlen, out, err);
    if (rc != 0) {
        if (encrypted) { *err = "incorrect passphrase"; rc = -3; }
        else if (!strcmp(*err, "not an OpenSSH private key")) { *err = "corrupt or unsupported key"; rc = -1; }
    } else *err = "ok";
done:
    if (der) { ssh_wipe(der, blen / 4 * 3 + 8); free(der); }
    if (b64) { ssh_wipe(b64, blen + 1); free(b64); }
    return rc;
}

int ssh_key_parse_private(const char *text, size_t len, const char *passphrase, ssh_key *out, const char **err)
{
    int rc;
    key_init(out);
    *err = "not an OpenSSH private key";
    rc = parse_openssh_format(text, len, passphrase, out, err);
    if (rc == -1 && !strcmp(*err, "not an OpenSSH private key")) {
        *err = "not a supported private key file";
        rc = parse_pem_format(text, len, passphrase, out, err);
        if (rc == -1 && !strcmp(*err, "not a supported private key file")) *err = "not an OpenSSH or PEM private key";
    }
    if (rc != 0) ssh_key_wipe(out);
    return rc;
}

/* ------------------------------------------------------------------ */
/* generation and export                                               */
/* ------------------------------------------------------------------ */

int ssh_key_generate_ed25519(ssh_key *out, const char *comment)
{
    u8 seed[32];
    size_t n;
    memset(out, 0, sizeof(*out));
    if (ssh_rng_bytes(seed, sizeof(seed)) != 0) return -1;
    ed25519_keypair(out->pk, out->sk, seed);
    ssh_wipe(seed, sizeof(seed));
    out->type = SSH_KEY_ED25519;
    n = comment ? strlen(comment) : 0;
    if (n >= sizeof(out->comment)) n = sizeof(out->comment) - 1;
    if (n) memcpy(out->comment, comment, n);
    return 0;
}

int ssh_key_write_public_line(const ssh_key *k, sbuf *out)
{
    sbuf blob;
    char *b64;
    size_t cap;
    int n, rc = -1;

    sb_init(&blob);
    if (ssh_key_public_blob(k, &blob) < 0) { sb_free(&blob); return -1; }
    cap = (blob.len + 2) / 3 * 4 + 4;
    b64 = (char *)malloc(cap);
    if (b64 && (n = b64_encode(blob.p, blob.len, b64, cap, 1)) >= 0) {
        sb_put(out, ssh_key_algo_name(k), strlen(ssh_key_algo_name(k)));
        sb_put_u8(out, ' ');
        sb_put(out, b64, (size_t)n);
        if (k->comment[0]) { sb_put_u8(out, ' '); sb_put(out, k->comment, strlen(k->comment)); }
        sb_put_u8(out, '\n');
        rc = out->oom ? -1 : 0;
    }
    free(b64);
    sb_free(&blob);
    return rc;
}

int ssh_key_write_private(const ssh_key *k, const char *passphrase, unsigned rounds, sbuf *out)
{
    sbuf pub, priv, ko, file;
    u8 check[4], salt[16], material[48];
    aes_ctr_ctx aes;
    unsigned pad;
    int encrypted = passphrase && passphrase[0], rc = -1, n;
    size_t block = encrypted ? 16 : 8, off, b64cap;
    char *b64 = NULL;

    if (k->type != SSH_KEY_ED25519) return -1;
    sb_init(&pub); sb_init(&priv); sb_init(&ko); sb_init(&file);
    if (ssh_rng_bytes(check, 4) != 0) goto out;
    if (ssh_key_public_blob(k, &pub) < 0) goto out;

    /* the private section: check ints, key, comment, then 1,2,3.. padding */
    sb_put(&priv, check, 4); sb_put(&priv, check, 4);
    sb_put_cstr(&priv, "ssh-ed25519");
    sb_put_str(&priv, k->pk, 32);
    sb_put_str(&priv, k->sk, 64);
    sb_put_cstr(&priv, k->comment);
    for (pad = 1; priv.len % block; pad++) sb_put_u8(&priv, (u8)pad);

    sb_put(&file, "openssh-key-v1", 15);                       /* includes the NUL */
    if (encrypted) {
        if (rounds < 1) rounds = 16;
        if (ssh_rng_bytes(salt, sizeof(salt)) != 0) goto out;
        sb_put_str(&ko, salt, sizeof(salt));
        sb_put_u32(&ko, rounds);
        if (bcrypt_pbkdf((const u8 *)passphrase, strlen(passphrase), salt, sizeof(salt),
                         material, sizeof(material), rounds) != 0) goto out;
        aes_ctr_init(&aes, material, 32, material + 32);
        aes_ctr_xor(&aes, priv.p, priv.p, priv.len);
        ssh_wipe(material, sizeof(material)); ssh_wipe(&aes, sizeof(aes));
        sb_put_cstr(&file, "aes256-ctr"); sb_put_cstr(&file, "bcrypt"); sb_put_str(&file, ko.p, ko.len);
    } else {
        sb_put_cstr(&file, "none"); sb_put_cstr(&file, "none"); sb_put_cstr(&file, "");
    }
    sb_put_u32(&file, 1);
    sb_put_str(&file, pub.p, pub.len);
    sb_put_str(&file, priv.p, priv.len);
    if (pub.oom || priv.oom || ko.oom || file.oom) goto out;

    /* Encode the whole file once (padding only at the very end), then wrap at 70 columns. */
    b64cap = (file.len + 2) / 3 * 4 + 4;
    b64 = (char *)malloc(b64cap);
    if (!b64) goto out;
    n = b64_encode(file.p, file.len, b64, b64cap, 1);
    if (n < 0) goto out;
    sb_put(out, BEGIN_LINE, sizeof(BEGIN_LINE) - 1);
    sb_put_u8(out, '\n');
    for (off = 0; off < (size_t)n; off += 70) {
        size_t chunk = (size_t)n - off < 70 ? (size_t)n - off : 70;
        sb_put(out, b64 + off, chunk);
        sb_put_u8(out, '\n');
    }
    sb_put(out, END_LINE, sizeof(END_LINE) - 1);
    sb_put_u8(out, '\n');
    rc = out->oom ? -1 : 0;
out:
    free(b64);
    sb_free(&pub); sb_free(&priv); sb_free(&ko); sb_free(&file);
    return rc;
}
