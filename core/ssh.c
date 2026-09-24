/*
 * ssh.c -- SSH-2 transport: identification, packet layer, key exchange, events.
 * (Authentication is in ssh_auth.c, channels in ssh_chan.c.)
 *
 * Implements RFC 4253 with curve25519-sha256 (RFC 8731), the OpenSSH
 * chacha20-poly1305 and encrypt-then-MAC extensions, ext-info (RFC 8308) and
 * OpenSSH "strict KEX" (Terrapin mitigation).
 */
#include <stdlib.h>
#include <string.h>
#include "ssh_priv.h"
#include "sha2.h"
#include "hmac.h"
#include "nacl.h"
#include "rng.h"
#include "bignum.h"
#include "ecc.h"
#include "dh_tab.h"

#define CLIENT_VERSION "SSH-2.0-StepSSH_1.1"

/* Key exchange methods, in the order we prefer them.  Modern first; the SHA-1 group is a last resort
 * for old servers.  (diffie-hellman-group1-sha1, 1024 bits, is deliberately not offered.) */
enum { H_SHA1 = 1, H_SHA256, H_SHA384, H_SHA512 };
enum { KX_C25519 = 1, KX_ECDH, KX_DH, KX_DHGEX };
static const struct { const char *name; int type, hash, param; } KEXES[] = {
    { "curve25519-sha256",                    KX_C25519, H_SHA256, 0 },
    { "curve25519-sha256@libssh.org",         KX_C25519, H_SHA256, 0 },
    { "ecdh-sha2-nistp256",                   KX_ECDH,   H_SHA256, EC_P256 },
    { "ecdh-sha2-nistp384",                   KX_ECDH,   H_SHA384, EC_P384 },
    { "ecdh-sha2-nistp521",                   KX_ECDH,   H_SHA512, EC_P521 },
    { "diffie-hellman-group-exchange-sha256", KX_DHGEX,  H_SHA256, 0 },
    { "diffie-hellman-group16-sha512",        KX_DH,     H_SHA512, 16 },
    { "diffie-hellman-group14-sha256",        KX_DH,     H_SHA256, 14 },
    { "diffie-hellman-group14-sha1",          KX_DH,     H_SHA1,   14 },
};
#define N_KEXES ((int)(sizeof(KEXES) / sizeof(KEXES[0])))
static const char DEF_KEX[] =
    "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
    "diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256,"
    "diffie-hellman-group14-sha1";
static const char DEF_HOSTKEY[] =
    "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,ssh-rsa";
static const char DEF_CIPHERS[] =
    "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,"
    "aes256-ctr,aes192-ctr,aes128-ctr,"
    "aes256-cbc,aes192-cbc,aes128-cbc,blowfish-cbc,3des-cbc";
static const char DEF_MACS[] =
    "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,"
    "hmac-sha2-256,hmac-sha2-512,hmac-sha1,"
    "hmac-sha1-96-etm@openssh.com,hmac-md5-etm@openssh.com,hmac-md5-96-etm@openssh.com,"
    "hmac-sha1-96,hmac-md5,hmac-md5-96";
/* Group-exchange bounds (RFC 8270 requires at least 2048 bits; 4096 keeps a slow CPU usable). */
#define GEX_MIN  2048
#define GEX_BITS 3072
#define GEX_MAX  4096
/* Private exponent size for the fixed groups: 256 bits gives ~128-bit security for MODP >= 2048. */
#define DH_XBITS 256
static const struct { const char *name; int id; int keylen, ivlen; } CIPHERS[] = {
    { "chacha20-poly1305@openssh.com", CIPHER_CHACHAPOLY, 64, 0  },
    { "aes256-gcm@openssh.com",        CIPHER_AES256GCM,  32, 12 },
    { "aes128-gcm@openssh.com",        CIPHER_AES128GCM,  16, 12 },
    { "aes256-ctr",                    CIPHER_AES256CTR,  32, 16 },
    { "aes192-ctr",                    CIPHER_AES192CTR,  24, 16 },
    { "aes128-ctr",                    CIPHER_AES128CTR,  16, 16 },
    { "aes256-cbc",                    CIPHER_AES256CBC,  32, 16 },    /* legacy: last resort */
    { "aes192-cbc",                    CIPHER_AES192CBC,  24, 16 },    /* legacy: last resort */
    { "aes128-cbc",                    CIPHER_AES128CBC,  16, 16 },    /* legacy: last resort */
    { "blowfish-cbc",                  CIPHER_BLOWFISHCBC, 16, 8  },   /* legacy: last resort */
    { "3des-cbc",                      CIPHER_3DESCBC,     24, 8  },   /* legacy: last resort */
};
#define N_CIPHERS ((int)(sizeof(CIPHERS) / sizeof(CIPHERS[0])))

/* AEAD ciphers (chacha20-poly1305, AES-GCM) authenticate the packet themselves: no separate MAC is
 * negotiated or applied, and (unlike every block cipher above) their length field is cleartext. */
static int cipher_is_aead(int id)
{
    return id == CIPHER_CHACHAPOLY || id == CIPHER_AES256GCM || id == CIPHER_AES128GCM;
}
static int cipher_is_gcm(int id)
{
    return id == CIPHER_AES256GCM || id == CIPHER_AES128GCM;
}

/* len is the MAC tag appended to each packet; keylen is the HMAC key length, always the underlying
 * hash's natural output size even where len is shorter (the "-96" variants: RFC 4253's hmac-sha1-96
 * and hmac-md5-96 truncate only the tag, not the key derived for it -- getting this wrong is exactly
 * the kind of thing that would silently interoperate with nothing, since both ends must derive and
 * use the identical, untruncated key before either one agrees to only compare 96 bits of the result). */
static const struct { const char *name; int kind, etm, len, keylen; } MACS[] = {
    { "hmac-sha2-256-etm@openssh.com", HMAC_SHA256, 1, 32, 32 },
    { "hmac-sha2-512-etm@openssh.com", HMAC_SHA512, 1, 64, 64 },
    { "hmac-sha1-etm@openssh.com",     HMAC_SHA1,   1, 20, 20 },    /* legacy */
    { "hmac-sha1-96-etm@openssh.com",  HMAC_SHA1,   1, 12, 20 },    /* legacy */
    { "hmac-md5-etm@openssh.com",      HMAC_MD5,    1, 16, 16 },    /* legacy */
    { "hmac-md5-96-etm@openssh.com",   HMAC_MD5,    1, 12, 16 },    /* legacy */
    { "hmac-sha2-256",                 HMAC_SHA256, 0, 32, 32 },
    { "hmac-sha2-512",                 HMAC_SHA512, 0, 64, 64 },
    { "hmac-sha1",                     HMAC_SHA1,   0, 20, 20 },    /* legacy */
    { "hmac-sha1-96",                  HMAC_SHA1,   0, 12, 20 },    /* legacy */
    { "hmac-md5",                      HMAC_MD5,    0, 16, 16 },    /* legacy */
    { "hmac-md5-96",                   HMAC_MD5,    0, 12, 16 },    /* legacy */
};
#define N_MACS ((int)(sizeof(MACS) / sizeof(MACS[0])))

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

static char *xstrdup(const char *s)
{
    size_t n = strlen(s) + 1;
    char *p = (char *)malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

static void cat(char *dst, size_t sz, const char *s)
{
    size_t n = strlen(dst), m = strlen(s);
    if (n + 1 >= sz) return;
    if (m > sz - n - 1) m = sz - n - 1;
    memcpy(dst + n, s, m);
    dst[n + m] = '\0';
}

static int namelist_has(const u8 *list, size_t len, const char *tok, size_t toklen)
{
    size_t i = 0, start;
    while (i <= len) {
        start = i;
        while (i < len && list[i] != ',') i++;
        if (i - start == toklen && memcmp(list + start, tok, toklen) == 0) return 1;
        i++;
    }
    return 0;
}

/* Client preference order wins (RFC 4253 7.1). */
static int negotiate(const char *client, const u8 *server, size_t slen, char *out, size_t outsz)
{
    const char *c = client;
    size_t n;
    while (*c) {
        const char *e = strchr(c, ',');
        n = e ? (size_t)(e - c) : strlen(c);
        if (n < outsz && namelist_has(server, slen, c, n)) {
            memcpy(out, c, n);
            out[n] = '\0';
            return 0;
        }
        c += n;
        if (*c == ',') c++;
    }
    return -1;
}

static int find_cipher(const char *name)
{
    int i;
    for (i = 0; i < N_CIPHERS; i++) if (strcmp(CIPHERS[i].name, name) == 0) return i;
    return -1;
}

static int find_mac(const char *name)
{
    int i;
    for (i = 0; i < N_MACS; i++) if (strcmp(MACS[i].name, name) == 0) return i;
    return -1;
}

/* ------------------------------------------------------------------ */
/* events                                                              */
/* ------------------------------------------------------------------ */

static void free_evnode(ssh_evnode *n)
{
    if (!n) return;
    if (n->data) { ssh_wipe(n->data, n->ev.len); free(n->data); }
    free(n->text);
    free(n->text2);
    free(n);
}

void ssh_push_event(ssh_session *s, int type, int chan, const u8 *data, size_t len,
                    int ext, int code, const char *text, const char *text2)
{
    ssh_evnode *n = (ssh_evnode *)calloc(1, sizeof(*n));
    if (!n) return;
    n->ev.type = type; n->ev.channel = chan; n->ev.len = len;
    n->ev.ext = ext; n->ev.code = code;
    if (data && len) {
        n->data = (u8 *)malloc(len);
        if (!n->data) { free(n); return; }
        memcpy(n->data, data, len);
    }
    if (text) n->text = xstrdup(text);
    if (text2) n->text2 = xstrdup(text2);
    n->ev.data = n->data;
    n->ev.text = n->text ? n->text : "";
    n->ev.text2 = n->text2 ? n->text2 : "";
    if (s->ev_tail) s->ev_tail->next = n; else s->ev_head = n;
    s->ev_tail = n;
}

int ssh_next_event(ssh_session *s, ssh_event *ev)
{
    ssh_evnode *n;
    if (s->ev_cur) { free_evnode(s->ev_cur); s->ev_cur = NULL; }
    n = s->ev_head;
    if (!n) return 0;
    s->ev_head = n->next;
    if (!s->ev_head) s->ev_tail = NULL;
    s->ev_cur = n;
    *ev = n->ev;
    return 1;
}

/* ------------------------------------------------------------------ */
/* lifecycle                                                           */
/* ------------------------------------------------------------------ */

ssh_session *ssh_new(const char *username)
{
    ssh_session *s = (ssh_session *)calloc(1, sizeof(*s));
    if (!s) return NULL;
    sb_init(&s->in); sb_init(&s->out); sb_init(&s->deferred);
    sb_init(&s->kexinit_c); sb_init(&s->kexinit_s); sb_init(&s->hostkey_blob);
    s->user = xstrdup(username ? username : "");
    strcpy(s->client_ver, CLIENT_VERSION);
    return s;
}

void ssh_set_kex_prefs(ssh_session *s, const char *kex)
{
    free(s->pref_kex);
    s->pref_kex = kex ? xstrdup(kex) : NULL;
}

void ssh_set_prefs(ssh_session *s, const char *ciphers, const char *macs)
{
    free(s->pref_ciphers); free(s->pref_macs);
    s->pref_ciphers = ciphers ? xstrdup(ciphers) : NULL;
    s->pref_macs = macs ? xstrdup(macs) : NULL;
}

void ssh_free(ssh_session *s)
{
    int i;
    ssh_evnode *n, *nx;
    if (!s) return;
    for (i = 0; i < SSH_MAX_CHANNELS; i++) sb_free(&s->chan[i].out);
    for (n = s->ev_head; n; n = nx) { nx = n->next; free_evnode(n); }
    free_evnode(s->ev_cur);
    ssh_auth_free(s);
    sb_free(&s->in); sb_free(&s->out); sb_free(&s->deferred);
    sb_free(&s->kexinit_c); sb_free(&s->kexinit_s); sb_free(&s->hostkey_blob);
    bn_free(&s->kex_x); bn_free(&s->gex_p); bn_free(&s->gex_g);
    free(s->user); free(s->pref_ciphers); free(s->pref_macs); free(s->pref_kex); free(s->server_sig_algs);
    ssh_wipe(s, sizeof(*s));
    free(s);
}

int ssh_is_closed(const ssh_session *s) { return s->closed; }
int ssh_is_authenticated(const ssh_session *s) { return s->auth_ok; }
const char *ssh_server_version(const ssh_session *s) { return s->server_ver; }
const char *ssh_cipher_name(const ssh_session *s)
{
    return s->first_kex_done ? CIPHERS[s->cipher_c2s].name : "none";
}
const char *ssh_kex_name(const ssh_session *s)
{
    return (s->first_kex_done && s->kex_idx >= 0) ? KEXES[s->kex_idx].name : "none";
}
const char *ssh_mac_name(const ssh_session *s)
{
    if (!s->first_kex_done) return "none";
    if (cipher_is_aead(CIPHERS[s->cipher_c2s].id)) return "(implicit)";
    return MACS[s->mac_c2s].name;
}

void ssh_output_done(ssh_session *s, size_t n) { sb_consume(&s->out, n); }
const u8 *ssh_output(ssh_session *s, size_t *len)
{
    *len = s->out.len;
    return s->out.p;
}

/* ------------------------------------------------------------------ */
/* packet layer                                                        */
/* ------------------------------------------------------------------ */

/* Block-cipher encrypt/decrypt in place: AES-CTR keeps a running keystream, AES-CBC,
 * Blowfish-CBC and 3DES-CBC chain their IV across packets (RFC 4253 section 6.3). */
static void blk_enc(ssh_dir *d, u8 *p, size_t n)
{
    if (d->cipher == CIPHER_BLOWFISHCBC) blowfish_cbc_encrypt_chain(&d->bf, d->cbcv, p, p, n);
    else if (d->cipher == CIPHER_3DESCBC) des3_cbc_encrypt_chain(&d->des3, d->cbcv, p, p, n);
    else if (d->cbc) aes_cbc_encrypt_chain(&d->aes, d->cbcv, p, p, n);
    else aes_ctr_xor(&d->aes, p, p, n);
}

static void blk_dec(ssh_dir *d, u8 *p, size_t n)
{
    if (d->cipher == CIPHER_BLOWFISHCBC) blowfish_cbc_decrypt_chain(&d->bf, d->cbcv, p, p, n);
    else if (d->cipher == CIPHER_3DESCBC) des3_cbc_decrypt_chain(&d->des3, d->cbcv, p, p, n);
    else if (d->cbc) aes_cbc_decrypt_chain(&d->aes, d->cbcv, p, p, n);
    else aes_ctr_xor(&d->aes, p, p, n);
}

static void mac_calc(const ssh_dir *d, u32 seq, const u8 *data, size_t n, u8 *out)
{
    hmac_ctx h;
    u8 sb[4], full[64];      /* the full, untruncated digest: HMAC always uses the full key and produces
                               * the full tag internally, even for a "-96" MAC that only appends 12 bytes
                               * of it to the packet -- writing straight into `out` would overrun it for
                               * those, since callers size that space from d->maclen, not the real digest */
    STORE32_BE(sb, seq);
    hmac_init(&h, d->mackind, d->mackey, (size_t)d->mackeylen);
    hmac_update(&h, sb, 4);
    hmac_update(&h, data, n);
    hmac_final(&h, full);
    memcpy(out, full, (size_t)d->maclen);
}

static int send_packet_now(ssh_session *s, const u8 *payload, size_t plen)
{
    ssh_dir *d = &s->tx;
    int aead_chacha = d->cipher == CIPHER_CHACHAPOLY;
    int aead_gcm = cipher_is_gcm(d->cipher);
    int aead = aead_chacha || aead_gcm;
    /* chacha20-poly1305 always aligns to 8 regardless of d->block (unused/0 for it); AES-GCM
     * aligns to the AES block size like any other AES mode, via d->block (set to 16). */
    size_t block = (d->cipher == CIPHER_NONE || aead_chacha) ? 8 : (size_t)d->block;
    int excl = aead || d->etm;              /* length field not covered by alignment */
    size_t body = 1 + plen, pad, pktlen, total;
    u8 *pkt;

    pad = block - ((body + (excl ? 0 : 4)) % block);
    if (pad < 4) pad += block;
    pktlen = body + pad;
    if (pktlen > SSH_MAX_PACKET) { ssh_fail(s, "outgoing packet too large"); return -1; }
    total = 4 + pktlen + (aead_chacha ? CHACHAPOLY_TAGLEN : aead_gcm ? GCM_TAGLEN : (size_t)d->maclen);
    if (sb_reserve(&s->out, total) < 0) { ssh_fail(s, "out of memory"); return -1; }

    pkt = s->out.p + s->out.len;
    STORE32_BE(pkt, (u32)pktlen);
    pkt[4] = (u8)pad;
    memcpy(pkt + 5, payload, plen);
    if (ssh_rng_bytes(pkt + 5 + plen, pad) < 0) memset(pkt + 5 + plen, 0, pad);

    if (aead_chacha) {
        chachapoly_seal(&d->cp, s->tx_seq, pkt, pkt, pktlen);
    } else if (aead_gcm) {
        aes_gcm_seal(&d->gcm, pkt, pkt, pktlen);
    } else if (d->cipher != CIPHER_NONE && d->etm) {
        blk_enc(d, pkt + 4, pktlen);
        mac_calc(d, s->tx_seq, pkt, 4 + pktlen, pkt + 4 + pktlen);
    } else if (d->cipher != CIPHER_NONE) {
        mac_calc(d, s->tx_seq, pkt, 4 + pktlen, pkt + 4 + pktlen);
        blk_enc(d, pkt, 4 + pktlen);
    }
    s->out.len += total;
    s->tx_seq++;
    return 0;
}

int ssh_kex_locked(const ssh_session *s)
{
    return s->kex_sent_kexinit && !s->kex_sent_newkeys;
}

/* While a key exchange is in flight only transport messages may be sent;
 * anything else (auth, channels) waits in `deferred` until NEWKEYS is out. */
int ssh_send_packet(ssh_session *s, const u8 *payload, size_t len)
{
    if (s->closed) return -1;
    if (ssh_kex_locked(s) && payload[0] >= 50) {
        sb_put_u32(&s->deferred, (u32)len);
        sb_put(&s->deferred, payload, len);
        return s->deferred.oom ? -1 : 0;
    }
    return send_packet_now(s, payload, len);
}

static void flush_deferred(ssh_session *s)
{
    size_t pos = 0;
    while (pos + 4 <= s->deferred.len) {
        u32 n = LOAD32_BE(s->deferred.p + pos);
        pos += 4;
        if (pos + n > s->deferred.len) break;
        if (send_packet_now(s, s->deferred.p + pos, n) < 0) break;
        pos += n;
    }
    sb_clear(&s->deferred);
}

void ssh_fail(ssh_session *s, const char *msg)
{
    sbuf b;
    if (s->closed) return;
    ssh_push_event(s, SSH_EV_ERROR, -1, NULL, 0, 0, 0, msg, NULL);
    if (s->have_version) {                     /* tell the peer, best effort */
        sb_init(&b);
        sb_put_u8(&b, M_DISCONNECT);
        sb_put_u32(&b, 2);                     /* protocol error */
        sb_put_cstr(&b, msg);
        sb_put_cstr(&b, "");
        if (!b.oom) send_packet_now(s, b.p, b.len);
        sb_free(&b);
    }
    s->closed = 1;
    s->fatal = 1;
}

void ssh_disconnect(ssh_session *s, const char *msg)
{
    sbuf b;
    if (s->closed) return;
    sb_init(&b);
    sb_put_u8(&b, M_DISCONNECT);
    sb_put_u32(&b, 11);                        /* by application */
    sb_put_cstr(&b, msg ? msg : "disconnected by user");
    sb_put_cstr(&b, "");
    if (!b.oom) send_packet_now(s, b.p, b.len);
    sb_free(&b);
    s->closed = 1;
}

void ssh_send_ignore(ssh_session *s)
{
    u8 p[5];
    p[0] = M_IGNORE; STORE32_BE(p + 1, 0);
    ssh_send_packet(s, p, 5);
}

void ssh_set_verbose(ssh_session *s, int on)
{
    s->verbose = on ? 1 : 0;
}

/* Returns 1 with *payload set, 0 if more input is needed, -1 on a protocol error. */
static int read_packet(ssh_session *s, const u8 **payload, size_t *plen)
{
    ssh_dir *d = &s->rx;
    u8 *p = s->in.p;
    size_t avail = s->in.len, total, pktlen, n;
    u8 padlen;

    if (d->cipher == CIPHER_NONE) {
        if (avail < 4) return 0;
        pktlen = LOAD32_BE(p);
        if (pktlen < 5 || pktlen > SSH_MAX_PACKET) { ssh_fail(s, "bad packet length"); return -1; }
        total = 4 + pktlen;
        if (avail < total) return 0;
    } else if (d->cipher == CIPHER_CHACHAPOLY) {
        if (avail < 4) return 0;
        pktlen = chachapoly_peek_length(&d->cp, s->rx_seq, p);
        if (pktlen < 8 || pktlen > SSH_MAX_PACKET || (pktlen % 8)) { ssh_fail(s, "bad packet length"); return -1; }
        total = 4 + pktlen + CHACHAPOLY_TAGLEN;
        if (avail < total) return 0;
        if (chachapoly_open(&d->cp, s->rx_seq, p, p, pktlen) != 0) { ssh_fail(s, "message authentication failed"); return -1; }
    } else if (cipher_is_gcm(d->cipher)) {
        /* AES-GCM's length field is cleartext (RFC 5647 s.7.3, like etm below) and used directly
         * as GCM's associated data -- no separate decrypt-to-peek step the way chacha needs. Same
         * per-cipher minimum reasoning as the etm branch below: the true floor is d->block (16 for
         * AES), not a fixed constant. */
        if (avail < 4) return 0;
        pktlen = LOAD32_BE(p);
        if (pktlen < (size_t)d->block || pktlen > SSH_MAX_PACKET || (pktlen % (size_t)d->block)) { ssh_fail(s, "bad packet length"); return -1; }
        total = 4 + pktlen + GCM_TAGLEN;
        if (avail < total) return 0;
        if (aes_gcm_open(&d->gcm, p, p, pktlen) != 0) { ssh_fail(s, "message authentication failed"); return -1; }
    } else if (d->etm) {
        u8 mac[64];
        if (avail < 4) return 0;
        pktlen = LOAD32_BE(p);
        /* Unlike the non-etm framing below, etm's 4-byte length field is cleartext and outside the
         * cipher's alignment (send_packet_now's `excl`), so the smallest legal pktlen is exactly one
         * block: 1 (padding_length) + 1 (a message's minimum payload) rounds up to `block` once the
         * >=4-bytes-of-padding rule is applied, for every block size this codebase uses (8 or 16) --
         * there is no cipher-independent constant here the way non-etm's "total size >= 16" is.
         * A hardcoded 16 (this file's former check) silently over-rejects real, minimal packets from
         * an 8-byte-block cipher (3des-cbc/blowfish-cbc): e.g. OpenSSH's own 1-byte-payload
         * USERAUTH_SUCCESS is pktlen=8 under 3des-cbc-etm, found via real interop testing. */
        if (pktlen < (size_t)d->block || pktlen > SSH_MAX_PACKET || (pktlen % (size_t)d->block)) { ssh_fail(s, "bad packet length"); return -1; }
        total = 4 + pktlen + (size_t)d->maclen;
        if (avail < total) return 0;
        mac_calc(d, s->rx_seq, p, 4 + pktlen, mac);
        if (ssh_ct_memcmp(mac, p + 4 + pktlen, (size_t)d->maclen) != 0) { ssh_fail(s, "message authentication failed"); return -1; }
        blk_dec(d, p + 4, pktlen);
    } else {
        u8 mac[64];
        size_t blk = (size_t)d->block;             /* need only the first block to learn the length */
        if (!s->rx_hdr_done) {
            if (avail < blk) return 0;
            blk_dec(d, p, blk);
            s->rx_pktlen = LOAD32_BE(p);
            s->rx_hdr_done = 1;
        }
        pktlen = s->rx_pktlen;
        if (pktlen < 12 || pktlen > SSH_MAX_PACKET || ((pktlen + 4) % blk)) { ssh_fail(s, "bad packet length"); return -1; }
        total = 4 + pktlen + (size_t)d->maclen;
        if (avail < total) return 0;
        if (4 + pktlen > blk) blk_dec(d, p + blk, 4 + pktlen - blk);
        s->rx_hdr_done = 0;
        mac_calc(d, s->rx_seq, p, 4 + pktlen, mac);
        if (ssh_ct_memcmp(mac, p + 4 + pktlen, (size_t)d->maclen) != 0) { ssh_fail(s, "message authentication failed"); return -1; }
    }

    padlen = p[4];
    if (padlen < 4 || (size_t)padlen + 1 >= pktlen) { ssh_fail(s, "bad padding length"); return -1; }
    n = pktlen - padlen - 1;
    *payload = p + 5;
    *plen = n;
    s->rx_total = total;
    s->cur_rx_seq = s->rx_seq;
    s->rx_seq++;
    return 1;
}

/* ------------------------------------------------------------------ */
/* identification exchange                                             */
/* ------------------------------------------------------------------ */

/* 1 = got it, 0 = need more, -1 = error */
static int read_version(ssh_session *s)
{
    size_t i, start = 0, n;
    for (;;) {
        for (i = start; i < s->in.len && s->in.p[i] != '\n'; i++) ;
        if (i >= s->in.len) {
            if (s->in.len > 65536) { ssh_fail(s, "server sent too much text before its version"); return -1; }
            return 0;
        }
        n = i - start;                                    /* line without the LF */
        if (n && s->in.p[start + n - 1] == '\r') n--;
        if (n >= 4 && memcmp(s->in.p + start, "SSH-", 4) == 0) {
            if (n > 255) { ssh_fail(s, "server version string too long"); return -1; }
            memcpy(s->server_ver, s->in.p + start, n);
            s->server_ver[n] = '\0';
            sb_consume(&s->in, i + 1);
            if (strncmp(s->server_ver, "SSH-2.0-", 8) != 0 && strncmp(s->server_ver, "SSH-1.99-", 9) != 0) {
                ssh_fail(s, "server does not speak SSH protocol 2");
                return -1;
            }
            s->have_version = 1;
            return 1;
        }
        start = i + 1;                                    /* pre-banner line: skip */
        if (start >= s->in.len) { sb_consume(&s->in, start); start = 0; return 0; }
    }
}

/* ------------------------------------------------------------------ */
/* key exchange                                                        */
/* ------------------------------------------------------------------ */

static int send_kexinit(ssh_session *s)
{
    sbuf b;
    u8 cookie[16];
    int first = !s->first_kex_done;
    const char *ciphers = s->pref_ciphers ? s->pref_ciphers : DEF_CIPHERS;
    const char *macs = s->pref_macs ? s->pref_macs : DEF_MACS;
    char kex[512];

    if (ssh_rng_bytes(cookie, 16) < 0) { ssh_fail(s, "random number generator not seeded"); return -1; }
    strcpy(kex, s->pref_kex ? s->pref_kex : DEF_KEX);
    if (first) cat(kex, sizeof(kex), ",ext-info-c,kex-strict-c-v00@openssh.com");

    sb_init(&b);
    sb_put_u8(&b, M_KEXINIT);
    sb_put(&b, cookie, 16);
    sb_put_cstr(&b, kex);
    sb_put_cstr(&b, DEF_HOSTKEY);
    sb_put_cstr(&b, ciphers); sb_put_cstr(&b, ciphers);
    sb_put_cstr(&b, macs);    sb_put_cstr(&b, macs);
    sb_put_cstr(&b, "none");  sb_put_cstr(&b, "none");
    sb_put_cstr(&b, "");      sb_put_cstr(&b, "");
    sb_put_u8(&b, 0);
    sb_put_u32(&b, 0);
    if (b.oom) { sb_free(&b); ssh_fail(s, "out of memory"); return -1; }

    sb_clear(&s->kexinit_c);
    sb_put(&s->kexinit_c, b.p, b.len);
    s->kex_sent_newkeys = 0;
    s->kex_got_newkeys = 0;
    if (send_packet_now(s, b.p, b.len) < 0) { sb_free(&b); return -1; }
    s->kex_sent_kexinit = 1;
    s->kex_state = KEX_SENT_INIT;
    sb_free(&b);
    return 0;
}

int ssh_start(ssh_session *s)
{
    if (s->started) return 0;
    if (!ssh_rng_ready()) {
        ssh_fail(s, "not enough entropy to start a secure session");
        return -1;
    }
    s->started = 1;
    sb_put(&s->out, s->client_ver, strlen(s->client_ver));
    sb_put(&s->out, "\r\n", 2);
    return send_kexinit(s);
}

/* ---------------------------------------------------------------- */
/* hashing for the exchange hash and key derivation                  */
/* ---------------------------------------------------------------- */

typedef struct {
    int alg;
    union { sha1_ctx s1; sha256_ctx s256; sha512_ctx s512; } u;
} hctx;

static int h_len(int alg)
{
    return alg == H_SHA1 ? 20 : alg == H_SHA256 ? 32 : alg == H_SHA384 ? 48 : 64;
}

static void h_init(hctx *h, int alg)
{
    h->alg = alg;
    if (alg == H_SHA1) sha1_init(&h->u.s1);
    else if (alg == H_SHA256) sha256_init(&h->u.s256);
    else if (alg == H_SHA384) sha384_init(&h->u.s512);
    else sha512_init(&h->u.s512);
}

static void h_update(hctx *h, const void *d, size_t n)
{
    if (h->alg == H_SHA1) sha1_update(&h->u.s1, d, n);
    else if (h->alg == H_SHA256) sha256_update(&h->u.s256, d, n);
    else sha512_update(&h->u.s512, d, n);          /* SHA-384 shares SHA-512's update */
}

static void h_final(hctx *h, u8 *out)               /* writes h_len(alg) bytes */
{
    u8 full[64];
    if (h->alg == H_SHA1) sha1_final(&h->u.s1, full);
    else if (h->alg == H_SHA256) sha256_final(&h->u.s256, full);
    else if (h->alg == H_SHA384) { sha384_final(&h->u.s512, full); }
    else sha512_final(&h->u.s512, full);
    memcpy(out, full, (size_t)h_len(h->alg));
    ssh_wipe(full, sizeof(full));
}

static void h_string(hctx *h, const void *d, size_t n)
{
    u8 l[4];
    STORE32_BE(l, (u32)n);
    h_update(h, l, 4);
    h_update(h, d, n);
}

static void h_u32(hctx *h, u32 v)
{
    u8 l[4];
    STORE32_BE(l, v);
    h_update(h, l, 4);
}

static void h_mpint(hctx *h, const u8 *be, size_t n)
{
    sbuf b;
    sb_init(&b);
    sb_put_mpint(&b, be, n);
    if (!b.oom) h_update(h, b.p, b.len);
    sb_free(&b);
}

/* ---------------------------------------------------------------- */
/* Diffie-Hellman helpers                                            */
/* ---------------------------------------------------------------- */

static int dh_load_group(int which, bn *p)
{
    return which == 14 ? bn_from_bytes(p, DH_P14, sizeof(DH_P14)) : bn_from_bytes(p, DH_P16, sizeof(DH_P16));
}

/* Pick x, compute e = g^x mod p; x is kept in s->kex_x, e (big-endian) in s->kex_e. */
static int dh_generate(ssh_session *s, const bn *g, const bn *p)
{
    u8 xb[DH_XBITS / 8];
    bn e;
    size_t elen;
    int rc = -1;
    if (ssh_rng_bytes(xb, sizeof(xb)) != 0) return -1;
    xb[0] |= 0x80;                                    /* full-length exponent */
    bn_init(&e);
    if (bn_from_bytes(&s->kex_x, xb, sizeof(xb)) < 0 || bn_modexp(&e, g, &s->kex_x, p) < 0) goto out;
    elen = (size_t)(bn_bits(&e) + 7) / 8;
    if (elen == 0 || elen > sizeof(s->kex_e) || bn_to_bytes(&e, s->kex_e, elen) != 0) goto out;
    s->kex_elen = elen;
    rc = 0;
out:
    ssh_wipe(xb, sizeof(xb));
    bn_free(&e);
    return rc;
}

/* A DH public value from the peer must lie strictly between 1 and p-1. */
static int dh_public_ok(const bn *f, const bn *p)
{
    bn one, pm1;
    int ok;
    bn_init(&one); bn_init(&pm1);
    if (bn_set_u32(&one, 1) < 0 || bn_sub(&pm1, p, &one) < 0) { bn_free(&one); bn_free(&pm1); return 0; }
    ok = bn_cmp(f, &one) > 0 && bn_cmp(f, &pm1) < 0;
    bn_free(&one); bn_free(&pm1);
    return ok;
}

/* ---------------------------------------------------------------- */
/* starting a key exchange                                           */
/* ---------------------------------------------------------------- */

static int kex_send_init(ssh_session *s)
{
    sbuf b;
    int rc = -1;
    const int type = KEXES[s->kex_idx].type, param = KEXES[s->kex_idx].param;

    sb_init(&b);
    if (type == KX_C25519) {
        if (ssh_rng_bytes(s->eph_priv, 32) < 0) { ssh_fail(s, "random number generator not seeded"); goto out; }
        x25519_base(s->kex_e, s->eph_priv);
        s->kex_elen = 32;
        sb_put_u8(&b, M_KEX_ECDH_INIT);
        sb_put_str(&b, s->kex_e, 32);
    } else if (type == KX_ECDH) {
        const ec_curve *c = ec_curve_get(param);
        ec_point Q;
        int ok;
        if (!c) { ssh_fail(s, "out of memory"); goto out; }
        ec_point_init(&Q);
        ok = ec_random_scalar(c, &s->kex_x) == 0 && ec_mul_base(c, &Q, &s->kex_x) == 0 &&
             ec_encode_point(c, &Q, s->kex_e) == 0;
        ec_point_free(&Q);
        if (!ok) { ssh_fail(s, "random number generator not seeded"); goto out; }
        s->kex_elen = (size_t)(1 + 2 * c->nbytes);
        sb_put_u8(&b, M_KEX_ECDH_INIT);
        sb_put_str(&b, s->kex_e, s->kex_elen);
    } else if (type == KX_DH) {
        bn p, g;
        int ok;
        bn_init(&p); bn_init(&g);
        ok = dh_load_group(param, &p) == 0 && bn_set_u32(&g, 2) == 0 && dh_generate(s, &g, &p) == 0;
        bn_free(&p); bn_free(&g);
        if (!ok) { ssh_fail(s, "cannot start Diffie-Hellman key exchange"); goto out; }
        sb_put_u8(&b, M_KEX_ECDH_INIT);                          /* SSH_MSG_KEXDH_INIT = 30 */
        sb_put_mpint(&b, s->kex_e, s->kex_elen);
    } else {                                                      /* group exchange: ask for a group first */
        sb_put_u8(&b, M_KEX_DH_GEX_REQUEST);
        sb_put_u32(&b, GEX_MIN); sb_put_u32(&b, GEX_BITS); sb_put_u32(&b, GEX_MAX);
    }
    if (b.oom) { ssh_fail(s, "out of memory"); goto out; }
    if (ssh_send_packet(s, b.p, b.len) < 0) goto out;
    s->kex_state = type == KX_DHGEX ? KEX_WAIT_GROUP : KEX_WAIT_REPLY;
    rc = 0;
out:
    sb_free(&b);
    return rc;
}

static int handle_kexinit(ssh_session *s, const u8 *pl, size_t len)
{
    sreader r;
    const u8 *lst[10];
    size_t ll[10];
    int i, first_follows;
    char name[96], errmsg[300], kexname[64];
    int ci = 0, mi = 0;
    const char *ciphers = s->pref_ciphers ? s->pref_ciphers : DEF_CIPHERS;
    const char *macs = s->pref_macs ? s->pref_macs : DEF_MACS;
    const char *kexlist = s->pref_kex ? s->pref_kex : DEF_KEX;

    if (s->kex_state == KEX_IDLE) {                       /* server-initiated rekey */
        if (send_kexinit(s) < 0) return -1;
    } else if (s->kex_state != KEX_SENT_INIT) {
        ssh_fail(s, "unexpected KEXINIT");
        return -1;
    }
    sb_clear(&s->kexinit_s);
    sb_put(&s->kexinit_s, pl, len);

    sr_init(&r, pl, len);
    sr_u8(&r);
    sr_bytes(&r, 16);
    for (i = 0; i < 10; i++) lst[i] = sr_str(&r, &ll[i]);
    first_follows = sr_u8(&r);
    sr_u32(&r);
    if (r.err) { ssh_fail(s, "malformed KEXINIT"); return -1; }

    if (!s->first_kex_done) {
        static const char strict_s[] = "kex-strict-s-v00@openssh.com";
        s->strict_kex = namelist_has(lst[0], ll[0], strict_s, sizeof(strict_s) - 1);
    }

    errmsg[0] = '\0';
    s->kex_idx = -1;
    if (negotiate(kexlist, lst[0], ll[0], kexname, sizeof(kexname)) < 0) {
        strcpy(errmsg, "no matching key exchange method (server offers only algorithms this client does not implement)");
    } else {
        for (i = 0; i < N_KEXES; i++) if (strcmp(KEXES[i].name, kexname) == 0) { s->kex_idx = i; break; }
        if (s->kex_idx < 0) strcpy(errmsg, "no matching key exchange method");
    }
    if (errmsg[0]) {
        /* fall through to the error report below */
    } else if (negotiate(DEF_HOSTKEY, lst[1], ll[1], s->hostkey_alg, sizeof(s->hostkey_alg)) < 0) {
        strcpy(errmsg, "no matching host key type (this client supports ssh-ed25519, ecdsa-sha2-nistp256/384/521 and RSA; the server offers none of them)");
    } else if (negotiate(ciphers, lst[2], ll[2], name, sizeof(name)) < 0 || (ci = find_cipher(name)) < 0) {
        strcpy(errmsg, "no matching cipher (client->server)");
    } else {
        s->cipher_c2s = ci;
        if (negotiate(ciphers, lst[3], ll[3], name, sizeof(name)) < 0 || (ci = find_cipher(name)) < 0) {
            strcpy(errmsg, "no matching cipher (server->client)");
        } else {
            s->cipher_s2c = ci;
        }
    }
    if (!errmsg[0]) {
        if (!cipher_is_aead(CIPHERS[s->cipher_c2s].id)) {
            if (negotiate(macs, lst[4], ll[4], name, sizeof(name)) < 0 || (mi = find_mac(name)) < 0)
                strcpy(errmsg, "no matching MAC (client->server)");
            else s->mac_c2s = mi;
        }
        if (!errmsg[0] && !cipher_is_aead(CIPHERS[s->cipher_s2c].id)) {
            if (negotiate(macs, lst[5], ll[5], name, sizeof(name)) < 0 || (mi = find_mac(name)) < 0)
                strcpy(errmsg, "no matching MAC (server->client)");
            else s->mac_s2c = mi;
        }
    }
    if (!errmsg[0] && negotiate("none", lst[6], ll[6], name, sizeof(name)) < 0)
        strcpy(errmsg, "server requires compression, which this client does not support");
    if (errmsg[0]) { ssh_fail(s, errmsg); return -1; }

    if (first_follows) {
        /* Its guess is right only if its first-listed kex and host key algorithms are the ones
         * we settled on; otherwise the follow-up packet must be dropped. */
        size_t kl = strlen(kexname), hl = strlen(s->hostkey_alg);
        int kex_ok = ll[0] >= kl && memcmp(lst[0], kexname, kl) == 0 && (ll[0] == kl || lst[0][kl] == ',');
        int key_ok = ll[1] >= hl && memcmp(lst[1], s->hostkey_alg, hl) == 0 && (ll[1] == hl || lst[1][hl] == ',');
        if (!kex_ok || !key_ok) s->ignore_next_packet = 1;
    }

    return kex_send_init(s);
}

/* Group exchange, step 2: the server picked a group (p, g); check it and send our public value. */
static int handle_gex_group(ssh_session *s, const u8 *pl, size_t len)
{
    sreader r;
    size_t pn, gn;
    const u8 *pp, *gg;
    bn p, g;
    sbuf b;
    int bits, rc = -1;

    sr_init(&r, pl, len);
    sr_u8(&r);
    pp = sr_str(&r, &pn); gg = sr_str(&r, &gn);
    if (r.err) { ssh_fail(s, "malformed group exchange reply"); return -1; }
    bn_init(&p); bn_init(&g); sb_init(&b);
    if (bn_from_bytes(&p, pp, pn) < 0 || bn_from_bytes(&g, gg, gn) < 0) { ssh_fail(s, "out of memory"); goto out; }
    bits = bn_bits(&p);
    if (bits < GEX_MIN || bits > GEX_MAX || !bn_is_odd(&p)) {
        ssh_fail(s, "server proposed a Diffie-Hellman group of unacceptable size");
        goto out;
    }
    if (!dh_public_ok(&g, &p)) { ssh_fail(s, "server proposed an invalid Diffie-Hellman generator"); goto out; }
    if (bn_copy(&s->gex_p, &p) < 0 || bn_copy(&s->gex_g, &g) < 0 || dh_generate(s, &g, &p) != 0) {
        ssh_fail(s, "cannot start group-exchange key exchange");
        goto out;
    }
    sb_put_u8(&b, M_KEX_DH_GEX_INIT);
    sb_put_mpint(&b, s->kex_e, s->kex_elen);
    if (b.oom || ssh_send_packet(s, b.p, b.len) < 0) goto out;
    s->kex_state = KEX_WAIT_REPLY;
    rc = 0;
out:
    bn_free(&p); bn_free(&g); sb_free(&b);
    return rc;
}

static void derive_key(int halg, const sbuf *kmp, const u8 *H, int hl, u8 letter,
                       const u8 *sid, int sidl, u8 *out, size_t need)
{
    u8 blk[64];
    hctx c;
    size_t have, n;

    h_init(&c, halg);
    h_update(&c, kmp->p, kmp->len);
    h_update(&c, H, (size_t)hl);
    h_update(&c, &letter, 1);
    h_update(&c, sid, (size_t)sidl);
    h_final(&c, blk);
    n = need < (size_t)hl ? need : (size_t)hl;
    memcpy(out, blk, n);
    have = n;
    while (have < need) {                                          /* K2 = HASH(K || H || K1), and so on */
        h_init(&c, halg);
        h_update(&c, kmp->p, kmp->len);
        h_update(&c, H, (size_t)hl);
        h_update(&c, out, have);
        h_final(&c, blk);
        n = need - have < (size_t)hl ? need - have : (size_t)hl;
        memcpy(out + have, blk, n);
        have += n;
    }
    ssh_wipe(blk, sizeof(blk));
}

/* Build one direction from the negotiated algorithm and derived material. */
static void setup_dir(ssh_dir *d, int cidx, int midx, const u8 *iv, const u8 *key, const u8 *mackey)
{
    memset(d, 0, sizeof(*d));
    d->cipher = CIPHERS[cidx].id;
    if (d->cipher == CIPHER_CHACHAPOLY) {
        chachapoly_init(&d->cp, key);
        return;                                    /* AEAD: no separate MAC to set up */
    }
    if (cipher_is_gcm(d->cipher)) {
        aes_gcm_init(&d->gcm, key, CIPHERS[cidx].keylen, iv);
        d->block = 16;
        return;                                    /* AEAD: no separate MAC to set up */
    }
    if (d->cipher == CIPHER_BLOWFISHCBC) {
        blf_key(&d->bf, key, (size_t)CIPHERS[cidx].keylen);
        d->cbc = 1;
        d->block = 8;
        memcpy(d->cbcv, iv, 8);
    } else if (d->cipher == CIPHER_3DESCBC) {
        des3_key(&d->des3, key);
        d->cbc = 1;
        d->block = 8;
        memcpy(d->cbcv, iv, 8);
    } else {
        aes_ctr_init(&d->aes, key, CIPHERS[cidx].keylen, iv);        /* the round keys serve CTR and CBC alike */
        d->block = 16;
        if (d->cipher == CIPHER_AES256CBC || d->cipher == CIPHER_AES192CBC || d->cipher == CIPHER_AES128CBC) {
            d->cbc = 1;
            memcpy(d->cbcv, iv, 16);
        }
    }
    d->mackind = MACS[midx].kind;
    d->etm = MACS[midx].etm;
    d->maclen = MACS[midx].len;
    d->mackeylen = MACS[midx].keylen;
    memcpy(d->mackey, mackey, (size_t)d->mackeylen);
}

/* The server's reply to our KEX init: type 31 (ECDH / DH reply) or 33 (group-exchange reply). */
static int handle_kex_reply(ssh_session *s, u8 type, const u8 *pl, size_t len)
{
    const int kt = KEXES[s->kex_idx].type, halg = KEXES[s->kex_idx].hash, hl = h_len(halg);
    sreader r;
    const u8 *ks, *v, *sig;
    size_t ksl, vl, sigl, i;
    u8 shared[520], H[64], zero = 0;
    size_t sharedlen = 0;
    sbuf kmp;
    hctx c;
    int first = !s->first_kex_done;
    u8 iv_c[64], iv_s[64], k_c[64], k_s[64], m_c[64], m_s[64];
    char fp[64], ktype[40];
    bn f, K, p, g;
    int rc = -1;

    if (s->kex_state != KEX_WAIT_REPLY) { ssh_fail(s, "unexpected key exchange reply"); return -1; }
    if ((kt == KX_DHGEX) != (type == M_KEX_DH_GEX_REPLY)) { ssh_fail(s, "unexpected key exchange reply type"); return -1; }
    sr_init(&r, pl, len);
    sr_u8(&r);
    ks = sr_str(&r, &ksl); v = sr_str(&r, &vl); sig = sr_str(&r, &sigl);
    if (r.err) { ssh_fail(s, "malformed key exchange reply"); return -1; }

    bn_init(&f); bn_init(&K); bn_init(&p); bn_init(&g);
    sb_init(&kmp);

    /* 1. the shared secret */
    if (kt == KX_C25519) {
        if (vl != 32) { ssh_fail(s, "malformed key exchange reply"); goto out; }
        x25519(shared, s->eph_priv, v);
        sharedlen = 32;
        for (i = 0; i < 32; i++) zero |= shared[i];
        if (zero == 0) { ssh_fail(s, "server sent a degenerate public key"); goto out; }
    } else if (kt == KX_ECDH) {
        const ec_curve *ec = ec_curve_get(KEXES[s->kex_idx].param);
        ec_point peer;
        int ok;
        if (!ec) { ssh_fail(s, "out of memory"); goto out; }
        ec_point_init(&peer);
        ok = ec_decode_point(ec, v, vl, &peer) == 0 && ecdh_shared(ec, &s->kex_x, &peer, shared) == 0;
        ec_point_free(&peer);
        if (!ok) { ssh_fail(s, "server sent an invalid elliptic-curve public key"); goto out; }
        sharedlen = (size_t)ec->nbytes;
    } else {                                                       /* DH or group exchange */
        if (kt == KX_DH) {
            if (dh_load_group(KEXES[s->kex_idx].param, &p) < 0 || bn_set_u32(&g, 2) < 0) { ssh_fail(s, "out of memory"); goto out; }
        } else if (bn_copy(&p, &s->gex_p) < 0 || bn_copy(&g, &s->gex_g) < 0) { ssh_fail(s, "out of memory"); goto out; }
        if (bn_from_bytes(&f, v, vl) < 0) { ssh_fail(s, "out of memory"); goto out; }
        if (!dh_public_ok(&f, &p)) { ssh_fail(s, "server sent an invalid Diffie-Hellman public value"); goto out; }
        sharedlen = (size_t)(bn_bits(&p) + 7) / 8;
        if (sharedlen > sizeof(shared) || bn_modexp(&K, &f, &s->kex_x, &p) < 0 || bn_to_bytes(&K, shared, sharedlen) != 0) {
            ssh_fail(s, "Diffie-Hellman computation failed");
            goto out;
        }
    }
    /* RFC 8731 / 5656 / 4253: K is encoded as an mpint of the big-endian shared secret. */
    sb_put_mpint(&kmp, shared, sharedlen);

    /* 2. the exchange hash */
    h_init(&c, halg);
    h_string(&c, s->client_ver, strlen(s->client_ver));
    h_string(&c, s->server_ver, strlen(s->server_ver));
    h_string(&c, s->kexinit_c.p, s->kexinit_c.len);
    h_string(&c, s->kexinit_s.p, s->kexinit_s.len);
    h_string(&c, ks, ksl);
    if (kt == KX_C25519 || kt == KX_ECDH) {
        h_string(&c, s->kex_e, s->kex_elen);                      /* Q_C */
        h_string(&c, v, vl);                                      /* Q_S */
    } else {
        u8 pb[520], gb[520];
        if (kt == KX_DHGEX) {
            size_t pn = (size_t)(bn_bits(&p) + 7) / 8, gn = (size_t)(bn_bits(&g) + 7) / 8;
            if (pn > sizeof(pb) || gn > sizeof(gb) || bn_to_bytes(&p, pb, pn) != 0 || bn_to_bytes(&g, gb, gn) != 0) {
                ssh_fail(s, "out of memory"); goto out;
            }
            h_u32(&c, GEX_MIN); h_u32(&c, GEX_BITS); h_u32(&c, GEX_MAX);
            h_mpint(&c, pb, pn);
            h_mpint(&c, gb, gn);
        }
        h_mpint(&c, s->kex_e, s->kex_elen);                       /* e */
        h_mpint(&c, v, vl);                                       /* f */
    }
    h_update(&c, kmp.p, kmp.len);
    h_final(&c, H);

    /* 3. the host key must have signed it */
    {
        const char *herr;
        if (ssh_hostkey_verify(ks, ksl, sig, sigl, s->hostkey_alg, H, (size_t)hl, &herr) != 0) {
            ssh_fail(s, herr);
            goto out;
        }
    }

    if (first) {
        memcpy(s->session_id, H, (size_t)hl);
        s->session_id_len = hl;
        sb_put(&s->hostkey_blob, ks, ksl);
        if (ssh_fingerprint_sha256(ks, ksl, fp, sizeof(fp)) == 0 && ssh_blob_type(ks, ksl, ktype, sizeof(ktype)) == 0)
            ssh_push_event(s, SSH_EV_HOSTKEY, -1, ks, ksl, 0, 0, fp, ktype);
    } else if (s->hostkey_blob.len != ksl || memcmp(s->hostkey_blob.p, ks, ksl) != 0) {
        ssh_fail(s, "server host key changed during re-keying");
        goto out;
    }

    derive_key(halg, &kmp, H, hl, 'A', s->session_id, s->session_id_len, iv_c, 64);
    derive_key(halg, &kmp, H, hl, 'B', s->session_id, s->session_id_len, iv_s, 64);
    derive_key(halg, &kmp, H, hl, 'C', s->session_id, s->session_id_len, k_c, 64);
    derive_key(halg, &kmp, H, hl, 'D', s->session_id, s->session_id_len, k_s, 64);
    derive_key(halg, &kmp, H, hl, 'E', s->session_id, s->session_id_len, m_c, 64);
    derive_key(halg, &kmp, H, hl, 'F', s->session_id, s->session_id_len, m_s, 64);
    setup_dir(&s->tx_next, s->cipher_c2s, s->mac_c2s, iv_c, k_c, m_c);
    setup_dir(&s->rx_next, s->cipher_s2c, s->mac_s2c, iv_s, k_s, m_s);
    ssh_wipe(iv_c, 64); ssh_wipe(iv_s, 64); ssh_wipe(k_c, 64);
    ssh_wipe(k_s, 64);  ssh_wipe(m_c, 64);  ssh_wipe(m_s, 64);

    /* NEWKEYS goes out under the old keys; everything after uses the new ones. */
    {
        u8 nk = M_NEWKEYS;
        if (send_packet_now(s, &nk, 1) < 0) goto out;
    }
    s->tx = s->tx_next;
    ssh_wipe(&s->tx_next, sizeof(s->tx_next));
    if (s->strict_kex) s->tx_seq = 0;
    s->kex_sent_newkeys = 1;
    s->kex_state = KEX_WAIT_NEWKEYS;
    flush_deferred(s);
    rc = 0;
out:
    ssh_wipe(shared, sizeof(shared));
    ssh_wipe(s->eph_priv, 32);
    bn_free(&s->kex_x); bn_free(&s->gex_p); bn_free(&s->gex_g);      /* secrets from this exchange are done with */
    bn_free(&f); bn_free(&K); bn_free(&p); bn_free(&g);
    sb_free(&kmp);
    return rc;
}

static void kex_finished(ssh_session *s)
{
    int first = !s->first_kex_done;
    s->kex_state = KEX_IDLE;
    s->kex_sent_kexinit = 0;
    s->kex_sent_newkeys = 0;
    s->first_kex_done = 1;
    if (first) {
        if (s->hostkey_decided) {
            if (s->hostkey_ok) ssh_auth_begin(s);
        } else {
            s->auth_state = AUTH_WAIT_HOSTKEY;
        }
    }
}

static int handle_newkeys(ssh_session *s)
{
    if (s->kex_state != KEX_WAIT_NEWKEYS) { ssh_fail(s, "unexpected NEWKEYS"); return -1; }
    s->rx = s->rx_next;
    ssh_wipe(&s->rx_next, sizeof(s->rx_next));
    s->rx_hdr_done = 0;
    if (s->strict_kex) s->rx_seq = 0;
    kex_finished(s);
    return 0;
}

void ssh_hostkey_accept(ssh_session *s, int accept)
{
    if (s->hostkey_decided) return;
    s->hostkey_decided = 1;
    s->hostkey_ok = accept ? 1 : 0;
    if (!accept) {
        ssh_disconnect(s, "host key rejected by user");
        ssh_push_event(s, SSH_EV_ERROR, -1, NULL, 0, 0, 0, "host key rejected", NULL);
        return;
    }
    if (s->first_kex_done && s->auth_state == AUTH_WAIT_HOSTKEY) ssh_auth_begin(s);
}

/* ------------------------------------------------------------------ */
/* dispatch                                                            */
/* ------------------------------------------------------------------ */

static int handle_packet(ssh_session *s, const u8 *pl, size_t len)
{
    sreader r;
    u8 type = pl[0];
    sbuf b;

    if (s->cur_rx_seq == 0 && !s->first_kex_done && type != M_KEXINIT) {
        ssh_fail(s, "server's first packet was not KEXINIT");
        return -1;
    }
    if (s->strict_kex && !s->first_kex_done &&
        type != M_KEXINIT && type != M_KEX_ECDH_REPLY && type != M_KEX_DH_GEX_REPLY && type != M_NEWKEYS) {
        ssh_fail(s, "unexpected packet during strict key exchange");
        return -1;
    }
    if (s->ignore_next_packet) { s->ignore_next_packet = 0; return 0; }

    sr_init(&r, pl, len);
    sr_u8(&r);
    switch (type) {
    case M_DISCONNECT: {
        u32 code = sr_u32(&r);
        size_t n;
        const u8 *msg = sr_str(&r, &n);
        char *t = (char *)malloc(n + 1);
        if (t) { if (msg) memcpy(t, msg, n); t[n] = '\0'; }
        ssh_push_event(s, SSH_EV_DISCONNECT, -1, NULL, 0, 0, (int)code, t ? t : "", NULL);
        free(t);
        s->closed = 1;
        return 0;
    }
    case M_IGNORE:
        return 0;
    case M_DEBUG: {
        size_t n;
        const u8 *msg;
        if (!s->verbose) return 0;
        sr_u8(&r);                                 /* always_display: shown either way when verbose */
        msg = sr_str(&r, &n);
        if (!r.err) {
            char *t = (char *)malloc(n + 1);
            if (t) {
                if (msg) memcpy(t, msg, n);
                t[n] = '\0';
                ssh_push_event(s, SSH_EV_TRACE, -1, NULL, 0, 0, 0, t, NULL);
                free(t);
            }
        }
        return 0;
    }
    case M_UNIMPLEMENTED:
        return 0;
    case M_EXT_INFO: {
        u32 n = sr_u32(&r), i;
        for (i = 0; i < n && !r.err; i++) {
            size_t nl, vl;
            const u8 *name = sr_str(&r, &nl), *val = sr_str(&r, &vl);
            if (!r.err && nl == 15 && memcmp(name, "server-sig-algs", 15) == 0) {
                free(s->server_sig_algs);
                s->server_sig_algs = (char *)malloc(vl + 1);
                if (s->server_sig_algs) { memcpy(s->server_sig_algs, val, vl); s->server_sig_algs[vl] = '\0'; }
            }
        }
        return 0;
    }
    case M_KEXINIT:
        return handle_kexinit(s, pl, len);
    case M_KEX_ECDH_REPLY:
        if (s->kex_state == KEX_WAIT_GROUP) return handle_gex_group(s, pl, len);
        return handle_kex_reply(s, type, pl, len);
    case M_KEX_DH_GEX_REPLY:
        return handle_kex_reply(s, type, pl, len);
    case M_NEWKEYS:
        return handle_newkeys(s);
    case M_SERVICE_ACCEPT:
    case M_USERAUTH_FAILURE:
    case M_USERAUTH_SUCCESS:
    case M_USERAUTH_BANNER:
    case M_USERAUTH_INFO:
        return ssh_auth_dispatch(s, type, &r);
    default:
        if (type >= 80 && type <= 100) return ssh_chan_dispatch(s, type, &r);
        sb_init(&b);
        sb_put_u8(&b, M_UNIMPLEMENTED);
        sb_put_u32(&b, s->cur_rx_seq);
        if (!b.oom) ssh_send_packet(s, b.p, b.len);
        sb_free(&b);
        return 0;
    }
}

int ssh_input(ssh_session *s, const u8 *data, size_t len)
{
    const u8 *pl;
    size_t plen;
    int rc;

    if (s->closed) return s->fatal ? -1 : 0;
    if (sb_put(&s->in, data, len) < 0) { ssh_fail(s, "out of memory"); return -1; }
    while (!s->closed) {
        if (!s->have_version) {
            rc = read_version(s);
            if (rc < 0) break;
            if (rc == 0) break;
            continue;
        }
        rc = read_packet(s, &pl, &plen);
        if (rc <= 0) break;
        rc = handle_packet(s, pl, plen);
        sb_consume(&s->in, s->rx_total);
        if (rc < 0) break;
    }
    if (!s->closed) ssh_chan_flush_all(s);
    return s->fatal ? -1 : 0;
}
