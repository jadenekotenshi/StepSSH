/* ssh_chan.c -- RFC 4254 connection protocol: channels and flow control. */
#include <stdlib.h>
#include <string.h>
#include "ssh_priv.h"

void ssh_chan_reset(ssh_chan *c)
{
    sb_free(&c->out);
    memset(c, 0, sizeof(*c));
}

static ssh_chan *get_chan(ssh_session *s, int id)
{
    if (id < 0 || id >= SSH_MAX_CHANNELS || s->chan[id].state == CH_FREE) return NULL;
    return &s->chan[id];
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
    case M_CHAN_OPEN: {                                    /* server-initiated: refuse */
        size_t n;
        u32 sender;
        sr_str(r, &n);
        sender = sr_u32(r);
        if (r->err) return 0;
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
        if (n) ssh_push_event(s, SSH_EV_CHAN_DATA, (int)id, d, n, (int)ext, 0, NULL, NULL);
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

int ssh_channel_open_session(ssh_session *s)
{
    int i;
    sbuf b;
    if (!s->auth_ok || s->closed) return -1;
    for (i = 0; i < SSH_MAX_CHANNELS && s->chan[i].state != CH_FREE; i++) ;
    if (i == SSH_MAX_CHANNELS) return -1;
    memset(&s->chan[i], 0, sizeof(s->chan[i]));
    s->chan[i].state = CH_OPENING;
    s->chan[i].local_window = SSH_LOCAL_WINDOW;
    sb_init(&s->chan[i].out);
    sb_init(&b);
    sb_put_u8(&b, M_CHAN_OPEN);
    sb_put_cstr(&b, "session");
    sb_put_u32(&b, (u32)i);
    sb_put_u32(&b, SSH_LOCAL_WINDOW);
    sb_put_u32(&b, SSH_LOCAL_MAXPKT);
    if (b.oom || ssh_send_packet(s, b.p, b.len) < 0) { sb_free(&b); ssh_chan_reset(&s->chan[i]); return -1; }
    sb_free(&b);
    return i;
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
