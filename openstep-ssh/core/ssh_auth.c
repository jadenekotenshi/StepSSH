/* ssh_auth.c -- RFC 4252 user authentication: none, password, publickey, keyboard-interactive. */
#include <stdlib.h>
#include <string.h>
#include "ssh_priv.h"

static char *dupn(const u8 *p, size_t n)
{
    char *s = (char *)malloc(n + 1);
    if (!s) return NULL;
    if (n) memcpy(s, p, n);
    s[n] = '\0';
    return s;
}

static void kbd_clear(ssh_session *s)
{
    int i;
    for (i = 0; i < s->kbd_n; i++) free(s->kbd_prompts[i]);
    free(s->kbd_prompts); free(s->kbd_echo); free(s->kbd_name); free(s->kbd_instr);
    s->kbd_prompts = NULL; s->kbd_echo = NULL; s->kbd_name = s->kbd_instr = NULL;
    s->kbd_n = 0;
}

void ssh_auth_free(ssh_session *s) { kbd_clear(s); }

void ssh_auth_begin(ssh_session *s)
{
    sbuf b;
    sb_init(&b);
    sb_put_u8(&b, M_SERVICE_REQUEST);
    sb_put_cstr(&b, "ssh-userauth");
    if (!b.oom) ssh_send_packet(s, b.p, b.len);
    sb_free(&b);
    s->auth_state = AUTH_SERVICE_SENT;
}

/* Common prefix of every USERAUTH_REQUEST. */
static void req_head(ssh_session *s, sbuf *b, const char *method)
{
    sb_put_u8(b, M_USERAUTH_REQUEST);
    sb_put_cstr(b, s->user);
    sb_put_cstr(b, "ssh-connection");
    sb_put_cstr(b, method);
}

static int send_request(ssh_session *s, sbuf *b, const char *method)
{
    int rc;
    if (b->oom) { sb_free(b); ssh_fail(s, "out of memory"); return -1; }
    rc = ssh_send_packet(s, b->p, b->len);
    sb_free(b);
    strncpy(s->auth_pending, method, sizeof(s->auth_pending) - 1);
    s->auth_pending[sizeof(s->auth_pending) - 1] = '\0';
    return rc;
}

static int can_auth(const ssh_session *s)
{
    return !s->closed && s->auth_state == AUTH_IN_PROGRESS && s->auth_pending[0] == '\0' && !s->auth_ok;
}

int ssh_auth_password(ssh_session *s, const char *password)
{
    sbuf b;
    if (!can_auth(s)) return -1;
    sb_init(&b);
    req_head(s, &b, "password");
    sb_put_u8(&b, 0);
    sb_put_cstr(&b, password);
    return send_request(s, &b, "password");
}

int ssh_auth_publickey(ssh_session *s, const ssh_key *key)
{
    sbuf b, blob, sd, sig;
    /* the signature algorithm (e.g. rsa-sha2-512), chosen from what the server advertised */
    const char *algo = ssh_key_pick_sigalg(key, s->server_sig_algs);
    int rc = -1;
    if (!can_auth(s)) return -1;
    sb_init(&b); sb_init(&blob); sb_init(&sd); sb_init(&sig);
    if (ssh_key_public_blob(key, &blob) < 0) goto out;

    /* The signed data binds the session id, the user and the key (RFC 4252 s.7). */
    sb_put_str(&sd, s->session_id, (size_t)s->session_id_len);
    req_head(s, &sd, "publickey");
    sb_put_u8(&sd, 1);
    sb_put_cstr(&sd, algo);
    sb_put_str(&sd, blob.p, blob.len);
    if (sd.oom || ssh_key_sign(key, algo, sd.p, sd.len, &sig) < 0) goto out;

    req_head(s, &b, "publickey");
    sb_put_u8(&b, 1);
    sb_put_cstr(&b, algo);
    sb_put_str(&b, blob.p, blob.len);
    sb_put_str(&b, sig.p, sig.len);
    rc = send_request(s, &b, "publickey");
out:
    sb_free(&b); sb_free(&blob); sb_free(&sd); sb_free(&sig);
    return rc;
}

int ssh_auth_kbdint_start(ssh_session *s)
{
    sbuf b;
    if (!can_auth(s)) return -1;
    sb_init(&b);
    req_head(s, &b, "keyboard-interactive");
    sb_put_cstr(&b, "");                                  /* language tag */
    sb_put_cstr(&b, "");                                  /* submethods */
    return send_request(s, &b, "keyboard-interactive");
}

int ssh_kbdint_count(const ssh_session *s) { return s->kbd_n; }
const char *ssh_kbdint_name(const ssh_session *s) { return s->kbd_name ? s->kbd_name : ""; }
const char *ssh_kbdint_instruction(const ssh_session *s) { return s->kbd_instr ? s->kbd_instr : ""; }

const char *ssh_kbdint_prompt(const ssh_session *s, int i, int *echo)
{
    if (i < 0 || i >= s->kbd_n) return NULL;
    if (echo) *echo = s->kbd_echo[i];
    return s->kbd_prompts[i];
}

int ssh_auth_kbdint_respond(ssh_session *s, const char **answers, int n)
{
    sbuf b;
    int i;
    if (s->closed || strcmp(s->auth_pending, "keyboard-interactive") != 0) return -1;
    sb_init(&b);
    sb_put_u8(&b, M_USERAUTH_INFO_RESPONSE);
    sb_put_u32(&b, (u32)n);
    for (i = 0; i < n; i++) sb_put_cstr(&b, answers[i]);
    if (b.oom) { sb_free(&b); ssh_fail(s, "out of memory"); return -1; }
    i = ssh_send_packet(s, b.p, b.len);
    sb_free(&b);
    kbd_clear(s);
    return i;
}

int ssh_auth_dispatch(ssh_session *s, u8 type, sreader *r)
{
    switch (type) {
    case M_SERVICE_ACCEPT: {
        sbuf b;
        if (s->auth_state != AUTH_SERVICE_SENT) return 0;
        s->auth_state = AUTH_IN_PROGRESS;
        sb_init(&b);
        req_head(s, &b, "none");                          /* asks the server which methods it allows */
        return send_request(s, &b, "none");
    }
    case M_USERAUTH_BANNER: {
        size_t n;
        const u8 *msg = sr_str(r, &n);
        char *t;
        if (r->err) return 0;
        t = dupn(msg, n);
        if (t) { ssh_push_event(s, SSH_EV_BANNER, -1, NULL, 0, 0, 0, t, NULL); free(t); }
        return 0;
    }
    case M_USERAUTH_FAILURE: {
        size_t n;
        const u8 *m = sr_str(r, &n);
        int partial = sr_u8(r);
        char *t;
        int was_none = strcmp(s->auth_pending, "none") == 0;
        if (r->err) { ssh_fail(s, "malformed USERAUTH_FAILURE"); return -1; }
        t = dupn(m, n);
        s->auth_pending[0] = '\0';
        kbd_clear(s);
        if (t) {
            ssh_push_event(s, was_none ? SSH_EV_AUTH_NEEDED : SSH_EV_AUTH_FAILED, -1, NULL, 0, 0, partial, t, NULL);
            free(t);
        }
        return 0;
    }
    case M_USERAUTH_SUCCESS:
        s->auth_pending[0] = '\0';
        s->auth_ok = 1;
        s->auth_state = AUTH_DONE;
        ssh_push_event(s, SSH_EV_AUTH_OK, -1, NULL, 0, 0, 0, NULL, NULL);
        return 0;
    case M_USERAUTH_INFO:
        if (strcmp(s->auth_pending, "keyboard-interactive") == 0) {
            size_t nl, il, ll, pl;
            const u8 *name = sr_str(r, &nl), *instr = sr_str(r, &il);
            u32 count, i;
            sr_str(r, &ll);
            count = sr_u32(r);
            if (r->err || count > 32) { ssh_fail(s, "malformed keyboard-interactive request"); return -1; }
            kbd_clear(s);
            s->kbd_name = dupn(name, nl);
            s->kbd_instr = dupn(instr, il);
            s->kbd_prompts = (char **)calloc(count ? count : 1, sizeof(char *));
            s->kbd_echo = (int *)calloc(count ? count : 1, sizeof(int));
            if (!s->kbd_prompts || !s->kbd_echo) { ssh_fail(s, "out of memory"); return -1; }
            for (i = 0; i < count; i++) {
                const u8 *pr = sr_str(r, &pl);
                s->kbd_echo[i] = sr_u8(r);
                if (r->err) { ssh_fail(s, "malformed keyboard-interactive prompt"); return -1; }
                s->kbd_prompts[i] = dupn(pr, pl);
                s->kbd_n = (int)i + 1;
            }
            ssh_push_event(s, SSH_EV_KBDINT, -1, NULL, 0, 0, (int)count, s->kbd_name, s->kbd_instr);
        } else if (strcmp(s->auth_pending, "password") == 0) {
            /* SSH_MSG_USERAUTH_PASSWD_CHANGEREQ: the server wants a new password. */
            size_t n;
            const u8 *m = sr_str(r, &n);
            char *t = r->err ? NULL : dupn(m, n);
            s->auth_pending[0] = '\0';
            ssh_push_event(s, SSH_EV_AUTH_FAILED, -1, NULL, 0, 0, 2,
                           t ? t : "password expired; change it on the server", NULL);
            free(t);
        }
        return 0;
    }
    return 0;
}
