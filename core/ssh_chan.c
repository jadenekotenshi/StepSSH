/* ssh_chan.c -- RFC 4254 connection protocol: channels and flow control. */
#include <stdlib.h>
#include <string.h>
#include "ssh_priv.h"
#include "rng.h"

void ssh_chan_reset(ssh_chan *c)
{
    sb_free(&c->out);
    sb_free(&c->x11_pending);
    memset(c, 0, sizeof(*c));
}

static ssh_chan *get_chan(ssh_session *s, int id)
{
    if (id < 0 || id >= SSH_MAX_CHANNELS || s->chan[id].state == CH_FREE) return NULL;
    return &s->chan[id];
}

/* First CH_FREE slot, or -1 if every one is in use -- shared by our own client-initiated opens
 * (open_begin) and the server-initiated "x11" accept path in ssh_chan_dispatch. */
static int find_free_chan(ssh_session *s)
{
    int i;
    for (i = 0; i < SSH_MAX_CHANNELS && s->chan[i].state != CH_FREE; i++) ;
    return i == SSH_MAX_CHANNELS ? -1 : i;
}

static void send_simple(ssh_session *s, u8 type, u32 remote_id)
{
    sbuf b;
    sb_init(&b);
    sb_put_u8(&b, type);
    sb_put_u32(&b, remote_id);
    if (!b.oom) ssh_send_packet(s, b.p, b.len);
    sb_free(&b);
}

static void release(ssh_session *s, int id)
{
    ssh_push_event(s, SSH_EV_CHAN_CLOSE, id, NULL, 0, 0, 0, NULL, NULL);
    ssh_chan_reset(&s->chan[id]);
}

static void chan_flush(ssh_session *s, int id)
{
    ssh_chan *c = &s->chan[id];
    sbuf b;
    size_t n;

    if (c->state != CH_OPEN || c->close_sent || ssh_kex_locked(s) || s->closed) return;
    while (c->out.len && c->remote_window) {
        n = c->out.len;
        if (n > c->remote_window) n = c->remote_window;
        if (n > c->remote_maxpkt) n = c->remote_maxpkt;
        if (n > 16384) n = 16384;                          /* keep packets modest for slow CPUs */
        sb_init(&b);
        sb_put_u8(&b, M_CHAN_DATA);
        sb_put_u32(&b, c->remote_id);
        sb_put_str(&b, c->out.p, n);
        if (b.oom || ssh_send_packet(s, b.p, b.len) < 0) { sb_free(&b); return; }
        sb_free(&b);
        c->remote_window -= (u32)n;
        sb_consume(&c->out, n);
    }
    if (c->out.len == 0) {
        if (c->want_eof && !c->eof_sent) { send_simple(s, M_CHAN_EOF, c->remote_id); c->eof_sent = 1; }
        if (c->want_close && !c->close_sent) {
            send_simple(s, M_CHAN_CLOSE, c->remote_id);
            c->close_sent = 1;
            if (c->close_recv) release(s, id);
        }
    }
}

void ssh_chan_flush_all(ssh_session *s)
{
    int i;
    for (i = 0; i < SSH_MAX_CHANNELS; i++)
        if (s->chan[i].state == CH_OPEN) chan_flush(s, i);
}

int ssh_chan_dispatch(ssh_session *s, u8 type, sreader *r)
{
    ssh_chan *c;
    u32 id, v;
    sbuf b;

    switch (type) {
    case M_GLOBAL_REQUEST: {
        size_t n;
        int want;
        sr_str(r, &n);
        want = sr_u8(r);
        if (r->err) return 0;
        if (want) {                                        /* we support none of them */
            u8 f = M_REQUEST_FAILURE;
            ssh_send_packet(s, &f, 1);
        }
        return 0;
    }
    /* server-initiated: refused, except for "x11" once ssh_channel_request_x11() has been called
     * (RFC 4254 s.6.3.2) -- every other type, and "x11" when never requested, is refused exactly
     * as before. */
    case M_CHAN_OPEN: {
        size_t tn, an;
        const u8 *ctype, *addr;
        u32 sender, rwindow, rmaxpkt, aport;
        int free_i;
        char *addrtext;

        ctype = sr_str(r, &tn);
        sender = sr_u32(r);
        rwindow = sr_u32(r);
        rmaxpkt = sr_u32(r);
        if (r->err) return 0;

        if (s->x11_active && tn == 3 && memcmp(ctype, "x11", 3) == 0) {
            addr = sr_str(r, &an);
            aport = sr_u32(r);
            (void)aport;                                   /* cosmetic only; nothing here uses it */
            if (!r->err) {
                free_i = find_free_chan(s);
                if (free_i < 0) {
                    sb_init(&b);
                    sb_put_u8(&b, M_CHAN_OPEN_FAIL);
                    sb_put_u32(&b, sender);
                    sb_put_u32(&b, 4);                     /* SSH_OPEN_RESOURCE_SHORTAGE */
                    sb_put_cstr(&b, "");
                    sb_put_cstr(&b, "");
                    if (!b.oom) ssh_send_packet(s, b.p, b.len);
                    sb_free(&b);
                    return 0;
                }
                /* We are the one confirming this open, not the one waiting for confirmation --
                 * straight to CH_OPEN, no CH_OPENING round trip. */
                memset(&s->chan[free_i], 0, sizeof(s->chan[free_i]));
                s->chan[free_i].state = CH_OPEN;
                s->chan[free_i].remote_id = sender;
                s->chan[free_i].remote_window = rwindow;
                s->chan[free_i].remote_maxpkt = rmaxpkt;
                s->chan[free_i].local_window = SSH_LOCAL_WINDOW;
                s->chan[free_i].is_x11 = 1;
                sb_init(&s->chan[free_i].out);
                sb_init(&s->chan[free_i].x11_pending);

                sb_init(&b);
                sb_put_u8(&b, M_CHAN_OPEN_CONFIRM);
                sb_put_u32(&b, sender);
                sb_put_u32(&b, (u32)free_i);
                sb_put_u32(&b, SSH_LOCAL_WINDOW);
                sb_put_u32(&b, SSH_LOCAL_MAXPKT);
                if (!b.oom) ssh_send_packet(s, b.p, b.len);
                sb_free(&b);

                addrtext = (char *)malloc(an + 1);
                if (addrtext) { if (an) memcpy(addrtext, addr, an); addrtext[an] = '\0'; }
                ssh_push_event(s, SSH_EV_X11_OPEN, free_i, NULL, 0, 0, 0, addrtext ? addrtext : "", NULL);
                free(addrtext);
                return 0;
            }
            /* malformed x11-specific fields: fall through to the ordinary refusal below */
        }

        sb_init(&b);
        sb_put_u8(&b, M_CHAN_OPEN_FAIL);
        sb_put_u32(&b, sender);
        sb_put_u32(&b, 1);                                 /* administratively prohibited */
        sb_put_cstr(&b, "");
        sb_put_cstr(&b, "");
        if (!b.oom) ssh_send_packet(s, b.p, b.len);
        sb_free(&b);
        return 0;
    }
    default:
        break;
    }

    id = sr_u32(r);
    if (r->err) { ssh_fail(s, "malformed channel message"); return -1; }
    c = get_chan(s, (int)id);
    if (!c) {                                              /* stale id (e.g. after our close): ignore */
        return 0;
    }

    switch (type) {
    case M_CHAN_OPEN_CONFIRM:
        c->remote_id = sr_u32(r);
        c->remote_window = sr_u32(r);
        c->remote_maxpkt = sr_u32(r);
        if (r->err || c->state != CH_OPENING) { ssh_fail(s, "malformed channel confirmation"); return -1; }
        c->state = CH_OPEN;
        ssh_push_event(s, SSH_EV_CHAN_OPEN, (int)id, NULL, 0, 0, 0, NULL, NULL);
        if (c->want_close) chan_flush(s, (int)id);
        return 0;
    case M_CHAN_OPEN_FAIL: {
        size_t n;
        u32 reason = sr_u32(r);
        const u8 *d = sr_str(r, &n);
        char *t = (char *)malloc(n + 1);
        if (t) { if (d && n) memcpy(t, d, n); t[n] = '\0'; }
        ssh_push_event(s, SSH_EV_CHAN_OPEN_FAILED, (int)id, NULL, 0, 0, (int)reason, t ? t : "", NULL);
        free(t);
        ssh_chan_reset(c);
        return 0;
    }
    case M_CHAN_WINDOW_ADJ:
        v = sr_u32(r);
        if (r->err) return 0;
        c->remote_window = (c->remote_window + v < c->remote_window) ? 0xffffffffUL : c->remote_window + v;
        chan_flush(s, (int)id);
        return 0;
    case M_CHAN_DATA:
    case M_CHAN_EXT_DATA: {
        size_t n;
        u32 ext = 0;
        const u8 *d;
        if (type == M_CHAN_EXT_DATA) ext = sr_u32(r);
        d = sr_str(r, &n);
        if (r->err) { ssh_fail(s, "malformed channel data"); return -1; }
        if (n > c->local_window) { ssh_fail(s, "server overran the channel window"); return -1; }
        c->local_window -= (u32)n;
        if (n && c->is_x11 && !c->x11_setup_done) {
            /* The X11 protocol's own ConnectionSetup request appears exactly once, at the start
             * of a fresh x11 channel -- accumulate until it's whole, rewrite its cookie, and only
             * then emit it (plus anything pipelined right after it in the same buffer) as ordinary
             * channel data. Never surface the fake cookie to the app, not even partially. */
            sbuf rewritten;
            size_t consumed;
            int rc;
            if (sb_put(&c->x11_pending, d, n) < 0) { ssh_fail(s, "out of memory"); return -1; }
            rc = x11_rewrite_setup(c->x11_pending.p, c->x11_pending.len, s->x11_fake_cookie,
                                   s->x11_real_cookie_len ? s->x11_real_cookie : NULL,
                                   s->x11_real_cookie_len, &rewritten, &consumed);
            if (rc == X11_OK) {
                c->x11_setup_done = 1;
                ssh_push_event(s, SSH_EV_CHAN_DATA, (int)id, rewritten.p, rewritten.len, (int)ext, 0, NULL, NULL);
                if (c->x11_pending.len > consumed)
                    ssh_push_event(s, SSH_EV_CHAN_DATA, (int)id, c->x11_pending.p + consumed,
                                   c->x11_pending.len - consumed, (int)ext, 0, NULL, NULL);
                sb_free(&rewritten);
                sb_free(&c->x11_pending);
                sb_init(&c->x11_pending);
            } else if (rc == X11_BAD) {
                /* This channel's "connection" was never legitimately triggered by our own
                 * x11-req -- close just this one channel, never the whole session. */
                c->x11_setup_done = 1;                     /* stop re-inspecting; it is closing */
                if (s->verbose)
                    ssh_push_event(s, SSH_EV_TRACE, -1, NULL, 0, 0, 0,
                                   "x11 channel closed: ConnectionSetup did not match what was advertised", NULL);
                ssh_channel_close(s, (int)id);
            }
            /* X11_NEED_MORE: nothing to emit yet -- keep buffering in c->x11_pending. */
        } else if (n) {
            ssh_push_event(s, SSH_EV_CHAN_DATA, (int)id, d, n, (int)ext, 0, NULL, NULL);
        }
        if (c->local_window < SSH_LOCAL_WINDOW / 2 && !c->close_sent) {
            sb_init(&b);
            sb_put_u8(&b, M_CHAN_WINDOW_ADJ);
            sb_put_u32(&b, c->remote_id);
            sb_put_u32(&b, SSH_LOCAL_WINDOW - c->local_window);
            if (!b.oom) ssh_send_packet(s, b.p, b.len);
            sb_free(&b);
            c->local_window = SSH_LOCAL_WINDOW;
        }
        return 0;
    }
    case M_CHAN_EOF:
        c->eof_recv = 1;
        ssh_push_event(s, SSH_EV_CHAN_EOF, (int)id, NULL, 0, 0, 0, NULL, NULL);
        return 0;
    case M_CHAN_CLOSE:
        c->close_recv = 1;
        if (!c->close_sent) {
            send_simple(s, M_CHAN_CLOSE, c->remote_id);
            c->close_sent = 1;
        }
        release(s, (int)id);
        return 0;
    case M_CHAN_SUCCESS:
        ssh_push_event(s, SSH_EV_CHAN_SUCCESS, (int)id, NULL, 0, 0, 0, NULL, NULL);
        return 0;
    case M_CHAN_FAILURE:
        ssh_push_event(s, SSH_EV_CHAN_FAILURE, (int)id, NULL, 0, 0, 0, NULL, NULL);
        return 0;
    case M_CHAN_REQUEST: {
        size_t n;
        const u8 *rt = sr_str(r, &n);
        int want = sr_u8(r);
        if (r->err) return 0;
        if (n == 11 && memcmp(rt, "exit-status", 11) == 0) {
            u32 st = sr_u32(r);
            if (!r->err) ssh_push_event(s, SSH_EV_CHAN_EXIT, (int)id, NULL, 0, 0, (int)st, NULL, NULL);
        } else if (n == 11 && memcmp(rt, "exit-signal", 11) == 0) {
            size_t sl;
            const u8 *sn = sr_str(r, &sl);
            char *t = (char *)malloc(sl + 1);
            if (t && !r->err) {
                memcpy(t, sn, sl); t[sl] = '\0';
                ssh_push_event(s, SSH_EV_CHAN_EXIT, (int)id, NULL, 0, 0, 128, t, NULL);
            }
            free(t);
        }
        if (want) send_simple(s, M_CHAN_FAILURE, c->remote_id);
        return 0;
    }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* application-facing channel API                                      */
/* ------------------------------------------------------------------ */

/* Allocates a free channel slot and writes the fixed part of CHANNEL_OPEN (type, sender id, window,
 * max packet) into *b; the caller appends whatever fields its channel type adds and sends it. Returns
 * the new channel's id, or -1 (nothing allocated) if there is no room or we cannot open channels yet. */
static int open_begin(ssh_session *s, const char *chan_type, sbuf *b)
{
    int i;
    if (!s->auth_ok || s->closed) return -1;
    i = find_free_chan(s);
    if (i < 0) return -1;
    memset(&s->chan[i], 0, sizeof(s->chan[i]));
    s->chan[i].state = CH_OPENING;
    s->chan[i].local_window = SSH_LOCAL_WINDOW;
    sb_init(&s->chan[i].out);
    sb_init(b);
    sb_put_u8(b, M_CHAN_OPEN);
    sb_put_cstr(b, chan_type);
    sb_put_u32(b, (u32)i);
    sb_put_u32(b, SSH_LOCAL_WINDOW);
    sb_put_u32(b, SSH_LOCAL_MAXPKT);
    return i;
}

static int open_send(ssh_session *s, int i, sbuf *b)
{
    if (b->oom || ssh_send_packet(s, b->p, b->len) < 0) { sb_free(b); ssh_chan_reset(&s->chan[i]); return -1; }
    sb_free(b);
    return i;
}

int ssh_channel_open_session(ssh_session *s)
{
    sbuf b;
    int i = open_begin(s, "session", &b);
    if (i < 0) return -1;
    return open_send(s, i, &b);
}

/* RFC 4254 s.7.2: a "direct-tcpip" channel -- local port forwarding.  The server connects to
 * host:port and, once that succeeds, relays channel data there; originator_ip/port describe the
 * client end of the connection that asked for the forward (cosmetic: some servers log or ACL on it,
 * but a fabricated value is harmless if the real one is not to hand). */
int ssh_channel_open_direct_tcpip(ssh_session *s, const char *host, int port,
                                   const char *originator_ip, int originator_port)
{
    sbuf b;
    int i = open_begin(s, "direct-tcpip", &b);
    if (i < 0) return -1;
    sb_put_cstr(&b, host);
    sb_put_u32(&b, (u32)port);
    sb_put_cstr(&b, originator_ip);
    sb_put_u32(&b, (u32)originator_port);
    return open_send(s, i, &b);
}

static int req_begin(ssh_session *s, int ch, sbuf *b, const char *type)
{
    ssh_chan *c = get_chan(s, ch);
    if (!c || c->state != CH_OPEN || s->closed) return -1;
    sb_init(b);
    sb_put_u8(b, M_CHAN_REQUEST);
    sb_put_u32(b, c->remote_id);
    sb_put_cstr(b, type);
    sb_put_u8(b, 1);                                       /* want reply */
    return 0;
}

static int req_send(ssh_session *s, sbuf *b)
{
    int rc = -1;
    if (!b->oom) rc = ssh_send_packet(s, b->p, b->len);
    sb_free(b);
    return rc;
}

int ssh_channel_request_pty(ssh_session *s, int ch, const char *term, int cols, int rows, int pxw, int pxh)
{
    /* RFC 4254 s.8 terminal modes: opcode byte + uint32, terminated by 0. */
    static const struct { u8 op; u32 val; } modes[] = {
        { 1, 3 }, { 2, 28 }, { 3, 127 }, { 4, 21 }, { 5, 4 },       /* INTR QUIT ERASE KILL EOF */
        { 36, 1 }, { 50, 1 }, { 51, 1 }, { 53, 1 }, { 54, 1 },      /* ICRNL ISIG ICANON ECHO ECHOE */
        { 55, 1 }, { 70, 1 }, { 72, 1 },                            /* ECHOK OPOST ONLCR */
        { 128, 38400 }, { 129, 38400 }
    };
    sbuf b, m;
    size_t i;
    if (req_begin(s, ch, &b, "pty-req") < 0) return -1;
    sb_init(&m);
    for (i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) { sb_put_u8(&m, modes[i].op); sb_put_u32(&m, modes[i].val); }
    sb_put_u8(&m, 0);
    sb_put_cstr(&b, term);
    sb_put_u32(&b, (u32)cols); sb_put_u32(&b, (u32)rows);
    sb_put_u32(&b, (u32)pxw);  sb_put_u32(&b, (u32)pxh);
    sb_put_str(&b, m.p, m.len);
    if (m.oom) b.oom = 1;
    sb_free(&m);
    return req_send(s, &b);
}

int ssh_channel_request_shell(ssh_session *s, int ch)
{
    sbuf b;
    if (req_begin(s, ch, &b, "shell") < 0) return -1;
    return req_send(s, &b);
}

int ssh_channel_request_exec(ssh_session *s, int ch, const char *cmd)
{
    sbuf b;
    if (req_begin(s, ch, &b, "exec") < 0) return -1;
    sb_put_cstr(&b, cmd);
    return req_send(s, &b);
}

int ssh_channel_request_subsystem(ssh_session *s, int ch, const char *name)
{
    sbuf b;
    if (req_begin(s, ch, &b, "subsystem") < 0) return -1;
    sb_put_cstr(&b, name);
    return req_send(s, &b);
}

int ssh_channel_setenv(ssh_session *s, int ch, const char *name, const char *value)
{
    sbuf b;
    if (req_begin(s, ch, &b, "env") < 0) return -1;
    sb_put_cstr(&b, name);
    sb_put_cstr(&b, value);
    return req_send(s, &b);
}

int ssh_channel_request_x11(ssh_session *s, int ch, int single_connection,
                             const u8 *real_cookie, size_t real_cookie_len, int screen)
{
    sbuf b;
    char hexcookie[2 * X11_COOKIE_LEN + 1];

    if (real_cookie_len != 0 && real_cookie_len != X11_COOKIE_LEN) return -1;
    if (req_begin(s, ch, &b, "x11-req") < 0) return -1;
    if (ssh_rng_bytes(s->x11_fake_cookie, X11_COOKIE_LEN) < 0) { sb_free(&b); return -1; }
    hex_encode(s->x11_fake_cookie, X11_COOKIE_LEN, hexcookie, sizeof(hexcookie));

    /* RFC 4254 s.6.3.1 field order: single-connection boolean, auth-protocol string (always
     * MIT-MAGIC-COOKIE-1 -- not user-configurable in v1), the fake cookie's hex-encoded ASCII text
     * as a string (the wire value here is explicitly hex text, not raw binary), screen number. */
    sb_put_u8(&b, single_connection ? 1 : 0);
    sb_put_cstr(&b, X11_AUTH_PROTO);
    sb_put_str(&b, hexcookie, 2 * X11_COOKIE_LEN);
    sb_put_u32(&b, (u32)screen);

    if (req_send(s, &b) < 0) return -1;

    if (real_cookie_len) memcpy(s->x11_real_cookie, real_cookie, real_cookie_len);
    s->x11_real_cookie_len = real_cookie_len;
    s->x11_active = 1;                                     /* only now: the request actually went out */
    return 0;
}

int ssh_channel_window_change(ssh_session *s, int ch, int cols, int rows, int pxw, int pxh)
{
    sbuf b;
    ssh_chan *c = get_chan(s, ch);
    if (!c || c->state != CH_OPEN || s->closed) return -1;
    sb_init(&b);
    sb_put_u8(&b, M_CHAN_REQUEST);
    sb_put_u32(&b, c->remote_id);
    sb_put_cstr(&b, "window-change");
    sb_put_u8(&b, 0);
    sb_put_u32(&b, (u32)cols); sb_put_u32(&b, (u32)rows);
    sb_put_u32(&b, (u32)pxw);  sb_put_u32(&b, (u32)pxh);
    return req_send(s, &b);
}

int ssh_channel_write(ssh_session *s, int ch, const u8 *data, size_t len)
{
    ssh_chan *c = get_chan(s, ch);
    size_t room;
    if (!c || s->closed || c->want_eof || c->want_close) return -1;
    room = c->out.len >= SSH_MAX_BACKLOG ? 0 : SSH_MAX_BACKLOG - c->out.len;
    if (len > room) len = room;
    if (len && sb_put(&c->out, data, len) < 0) return -1;
    chan_flush(s, ch);
    return (int)len;
}

size_t ssh_channel_backlog(const ssh_session *s, int ch)
{
    if (ch < 0 || ch >= SSH_MAX_CHANNELS || s->chan[ch].state == CH_FREE) return 0;
    return s->chan[ch].out.len;
}

int ssh_channel_eof(ssh_session *s, int ch)
{
    ssh_chan *c = get_chan(s, ch);
    if (!c) return -1;
    c->want_eof = 1;
    chan_flush(s, ch);
    return 0;
}

int ssh_channel_close(ssh_session *s, int ch)
{
    ssh_chan *c = get_chan(s, ch);
    if (!c) return -1;
    c->want_close = 1;
    if (c->state == CH_OPENING) return 0;                  /* closed as soon as it opens */
    chan_flush(s, ch);
    return 0;
}
