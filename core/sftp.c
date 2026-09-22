/* sftp.c -- SFTP v3 client: protocol, request tracking, directory listing, pipelined transfers. */
#include <stdlib.h>
#include <string.h>
#include "sftp.h"
#include "wire.h"

#define SFTP_MAX_PACKET   (1024UL * 1024UL)
#define SFTP_MAX_NAMES    50000UL
#define XFER_CHUNK        32768UL
#define XFER_WINDOW       8

enum { T_INIT = 1, T_VERSION = 2, T_OPEN = 3, T_CLOSE = 4, T_READ = 5, T_WRITE = 6, T_LSTAT = 7,
       T_SETSTAT = 9, T_OPENDIR = 11, T_READDIR = 12, T_REMOVE = 13, T_MKDIR = 14, T_RMDIR = 15,
       T_REALPATH = 16, T_STAT = 17, T_RENAME = 18, T_READLINK = 19 };

typedef struct pend { u32 id; sftp_cb cb; void *ctx; struct pend *next; } pend;

struct sftp {
    sbuf in, out;
    int  ready, failed;
    char err[160];
    void (*ready_cb)(sftp *s, void *ctx);
    void *ready_ctx;
    u32  next_id;
    pend *head, *tail;
    size_t npend;
};

static char *dupn(const u8 *p, size_t n)
{
    char *s = (char *)malloc(n + 1);
    if (!s) return NULL;
    if (n) memcpy(s, p, n);
    s[n] = '\0';
    return s;
}

static void set_error(sftp *s, const char *msg)
{
    if (s->failed) return;
    s->failed = 1;
    strncpy(s->err, msg, sizeof(s->err) - 1);
    s->err[sizeof(s->err) - 1] = '\0';
}

sftp *sftp_new(void)
{
    sftp *s = (sftp *)calloc(1, sizeof(*s));
    if (!s) return NULL;
    sb_init(&s->in); sb_init(&s->out);
    return s;
}

int sftp_is_ready(const sftp *s) { return s->ready; }
const char *sftp_error(const sftp *s) { return s->failed ? s->err : NULL; }
size_t sftp_pending(const sftp *s) { return s->npend; }
const u8 *sftp_output(sftp *s, size_t *len) { *len = s->out.len; return s->out.p; }
void sftp_output_done(sftp *s, size_t n) { sb_consume(&s->out, n); }

/* ------------------------------------------------------------------ */
/* attributes                                                          */
/* ------------------------------------------------------------------ */

static void parse_attrs(sreader *r, sftp_attrs *a)
{
    memset(a, 0, sizeof(*a));
    a->flags = sr_u32(r);
    if (a->flags & SFTP_ATTR_SIZE) a->size = sr_u64(r);
    if (a->flags & SFTP_ATTR_UIDGID) { a->uid = sr_u32(r); a->gid = sr_u32(r); }
    if (a->flags & SFTP_ATTR_PERMISSIONS) a->perms = sr_u32(r);
    if (a->flags & SFTP_ATTR_ACMODTIME) { a->atime = sr_u32(r); a->mtime = sr_u32(r); }
    if (a->flags & 0x80000000UL) {                               /* extended pairs: skip */
        u32 n = sr_u32(r), i;
        for (i = 0; i < n && !r->err; i++) {
            size_t l;
            sr_str(r, &l); sr_str(r, &l);
        }
    }
}

static void put_perm_attrs(sbuf *b, u32 mode)
{
    if (mode) { sb_put_u32(b, SFTP_ATTR_PERMISSIONS); sb_put_u32(b, mode & 07777UL); }
    else sb_put_u32(b, 0);
}

/* ------------------------------------------------------------------ */
/* sending requests                                                    */
/* ------------------------------------------------------------------ */

static u32 begin(sftp *s, sbuf *b, int type)
{
    u32 id;
    if (s->failed || !s->ready) return 0;
    id = ++s->next_id;
    if (id == 0) id = ++s->next_id;
    sb_init(b);
    sb_put_u32(b, 0);                                            /* length, patched in finish() */
    sb_put_u8(b, (u8)type);
    sb_put_u32(b, id);
    return id;
}

static u32 finish(sftp *s, sbuf *b, u32 id, sftp_cb cb, void *ctx)
{
    pend *p;
    u32 len;
    if (b->oom) { sb_free(b); set_error(s, "out of memory"); return 0; }
    p = (pend *)malloc(sizeof(*p));
    if (!p) { sb_free(b); set_error(s, "out of memory"); return 0; }
    len = (u32)(b->len - 4);
    STORE32_BE(b->p, len);
    sb_put(&s->out, b->p, b->len);
    sb_free(b);
    p->id = id; p->cb = cb; p->ctx = ctx; p->next = NULL;
    if (s->tail) s->tail->next = p; else s->head = p;
    s->tail = p;
    s->npend++;
    return s->out.oom ? 0 : id;
}

static u32 req_path(sftp *s, int type, const char *path, sftp_cb cb, void *ctx)
{
    sbuf b;
    u32 id = begin(s, &b, type);
    if (!id) return 0;
    sb_put_cstr(&b, path);
    return finish(s, &b, id, cb, ctx);
}

static u32 req_handle(sftp *s, int type, const u8 *h, size_t hl, sftp_cb cb, void *ctx)
{
    sbuf b;
    u32 id = begin(s, &b, type);
    if (!id) return 0;
    sb_put_str(&b, h, hl);
    return finish(s, &b, id, cb, ctx);
}

u32 sftp_opendir(sftp *s, const char *p, sftp_cb cb, void *c) { return req_path(s, T_OPENDIR, p, cb, c); }
u32 sftp_readdir(sftp *s, const u8 *h, size_t hl, sftp_cb cb, void *c) { return req_handle(s, T_READDIR, h, hl, cb, c); }
u32 sftp_close(sftp *s, const u8 *h, size_t hl, sftp_cb cb, void *c) { return req_handle(s, T_CLOSE, h, hl, cb, c); }
u32 sftp_stat(sftp *s, const char *p, sftp_cb cb, void *c) { return req_path(s, T_STAT, p, cb, c); }
u32 sftp_lstat(sftp *s, const char *p, sftp_cb cb, void *c) { return req_path(s, T_LSTAT, p, cb, c); }
u32 sftp_rmdir(sftp *s, const char *p, sftp_cb cb, void *c) { return req_path(s, T_RMDIR, p, cb, c); }
u32 sftp_remove(sftp *s, const char *p, sftp_cb cb, void *c) { return req_path(s, T_REMOVE, p, cb, c); }
u32 sftp_realpath(sftp *s, const char *p, sftp_cb cb, void *c) { return req_path(s, T_REALPATH, p, cb, c); }
u32 sftp_readlink(sftp *s, const char *p, sftp_cb cb, void *c) { return req_path(s, T_READLINK, p, cb, c); }

u32 sftp_open(sftp *s, const char *path, u32 pflags, u32 mode, sftp_cb cb, void *ctx)
{
    sbuf b;
    u32 id = begin(s, &b, T_OPEN);
    if (!id) return 0;
    sb_put_cstr(&b, path);
    sb_put_u32(&b, pflags);
    put_perm_attrs(&b, mode);
    return finish(s, &b, id, cb, ctx);
}

u32 sftp_read(sftp *s, const u8 *h, size_t hl, u64 off, u32 len, sftp_cb cb, void *ctx)
{
    sbuf b;
    u32 id = begin(s, &b, T_READ);
    if (!id) return 0;
    sb_put_str(&b, h, hl);
    sb_put_u64(&b, off);
    sb_put_u32(&b, len);
    return finish(s, &b, id, cb, ctx);
}

u32 sftp_write(sftp *s, const u8 *h, size_t hl, u64 off, const u8 *data, u32 len, sftp_cb cb, void *ctx)
{
    sbuf b;
    u32 id = begin(s, &b, T_WRITE);
    if (!id) return 0;
    sb_put_str(&b, h, hl);
    sb_put_u64(&b, off);
    sb_put_str(&b, data, len);
    return finish(s, &b, id, cb, ctx);
}

u32 sftp_setmode(sftp *s, const char *path, u32 mode, sftp_cb cb, void *ctx)
{
    sbuf b;
    u32 id = begin(s, &b, T_SETSTAT);
    if (!id) return 0;
    sb_put_cstr(&b, path);
    put_perm_attrs(&b, mode);
    return finish(s, &b, id, cb, ctx);
}

u32 sftp_mkdir(sftp *s, const char *path, u32 mode, sftp_cb cb, void *ctx)
{
    sbuf b;
    u32 id = begin(s, &b, T_MKDIR);
    if (!id) return 0;
    sb_put_cstr(&b, path);
    put_perm_attrs(&b, mode);
    return finish(s, &b, id, cb, ctx);
}

u32 sftp_rename(sftp *s, const char *from, const char *to, sftp_cb cb, void *ctx)
{
    sbuf b;
    u32 id = begin(s, &b, T_RENAME);
    if (!id) return 0;
    sb_put_cstr(&b, from);
    sb_put_cstr(&b, to);
    return finish(s, &b, id, cb, ctx);
}

int sftp_start(sftp *s, void (*ready)(sftp *s, void *ctx), void *ctx)
{
    sbuf b;
    s->ready_cb = ready; s->ready_ctx = ctx;
    sb_init(&b);
    sb_put_u32(&b, 5);
    sb_put_u8(&b, T_INIT);
    sb_put_u32(&b, 3);                                           /* protocol version 3 */
    if (b.oom) { sb_free(&b); return -1; }
    sb_put(&s->out, b.p, b.len);
    sb_free(&b);
    return 0;
}

/* ------------------------------------------------------------------ */
/* receiving                                                           */
/* ------------------------------------------------------------------ */

static pend *take_pending(sftp *s, u32 id)
{
    pend *p, *prev = NULL;
    for (p = s->head; p; prev = p, p = p->next) {
        if (p->id == id) {
            if (prev) prev->next = p->next; else s->head = p->next;
            if (s->tail == p) s->tail = prev;
            s->npend--;
            return p;
        }
    }
    return NULL;
}

static void free_names(sftp_name *n, int count)
{
    int i;
    if (!n) return;
    for (i = 0; i < count; i++) { free(n[i].name); free(n[i].longname); }
    free(n);
}

static int handle_response(sftp *s, int type, sreader *r)
{
    sftp_response resp;
    sftp_name *names = NULL;
    char *msg = NULL;
    pend *p;
    u32 id = sr_u32(r), i, count;
    size_t l;
    const u8 *d;

    if (r->err) { set_error(s, "malformed SFTP response"); return -1; }
    p = take_pending(s, id);
    if (!p) return 0;                                            /* unknown id: ignore */
    memset(&resp, 0, sizeof(resp));
    resp.id = id; resp.type = type;

    switch (type) {
    case SFTP_R_STATUS:
        resp.status = sr_u32(r);
        d = sr_str(r, &l);
        msg = (!r->err && d) ? dupn(d, l) : NULL;
        resp.message = msg ? msg : "";
        break;
    case SFTP_R_HANDLE:
        resp.handle = sr_str(r, &resp.handle_len);
        break;
    case SFTP_R_DATA:
        resp.data = sr_str(r, &resp.data_len);
        break;
    case SFTP_R_NAME:
        count = sr_u32(r);
        if (r->err || count > SFTP_MAX_NAMES) { free(p); set_error(s, "malformed SFTP name list"); return -1; }
        names = (sftp_name *)calloc(count ? count : 1, sizeof(sftp_name));
        if (!names) { free(p); set_error(s, "out of memory"); return -1; }
        for (i = 0; i < count && !r->err; i++) {
            size_t nl, ll;
            const u8 *nm = sr_str(r, &nl), *lg = sr_str(r, &ll);
            names[i].name = (!r->err && nm) ? dupn(nm, nl) : NULL;
            names[i].longname = (!r->err && lg) ? dupn(lg, ll) : NULL;
            if (!r->err) parse_attrs(r, &names[i].attrs);
        }
        resp.nnames = (int)count;
        resp.names = names;
        break;
    case SFTP_R_ATTRS:
        parse_attrs(r, &resp.attrs);
        break;
    default:
        free(p);
        set_error(s, "unexpected SFTP response type");
        return -1;
    }
    if (r->err) {
        free(msg); free_names(names, resp.nnames); free(p);
        set_error(s, "truncated SFTP response");
        return -1;
    }
    p->cb(s, &resp, p->ctx);
    free(p);
    free(msg);
    free_names(names, resp.nnames);
    return 0;
}

int sftp_input(sftp *s, const u8 *data, size_t len)
{
    if (s->failed) return -1;
    if (sb_put(&s->in, data, len) < 0) { set_error(s, "out of memory"); return -1; }
    while (!s->failed && s->in.len >= 4) {
        u32 plen = LOAD32_BE(s->in.p);
        sreader r;
        int type;
        if (plen < 1 || plen > SFTP_MAX_PACKET) { set_error(s, "bad SFTP packet length"); return -1; }
        if (s->in.len < 4 + (size_t)plen) break;
        sr_init(&r, s->in.p + 4, plen);
        type = sr_u8(&r);
        if (type == T_VERSION) {
            u32 ver = sr_u32(&r);
            if (ver < 3) { set_error(s, "server speaks an SFTP version older than 3"); return -1; }
            s->ready = 1;
            sb_consume(&s->in, 4 + (size_t)plen);
            if (s->ready_cb) s->ready_cb(s, s->ready_ctx);
            continue;
        }
        if (!s->ready) { set_error(s, "SFTP packet before VERSION"); return -1; }
        /* The response may issue more requests, which only touch s->out, never s->in. */
        if (handle_response(s, type, &r) < 0) return -1;
        sb_consume(&s->in, 4 + (size_t)plen);
    }
    return s->failed ? -1 : 0;
}

void sftp_abort(sftp *s, const char *why)
{
    pend *p;
    sftp_response resp;
    set_error(s, why ? why : "connection lost");
    while ((p = s->head) != NULL) {
        s->head = p->next;
        if (!s->head) s->tail = NULL;
        s->npend--;
        memset(&resp, 0, sizeof(resp));
        resp.id = p->id; resp.type = SFTP_R_STATUS; resp.status = SFTP_CONNECTION_LOST; resp.message = s->err;
        p->cb(s, &resp, p->ctx);
        free(p);
    }
}

void sftp_free(sftp *s)
{
    if (!s) return;
    sftp_abort(s, "session closed");
    sb_free(&s->in); sb_free(&s->out);
    free(s);
}

/* ------------------------------------------------------------------ */
/* directory listing                                                   */
/* ------------------------------------------------------------------ */

struct sftp_dirlist {
    sftp *s;
    sftp_dirlist_cb cb;
    void *ctx;
    u8 *handle; size_t hlen;
    sftp_name *entries;
    int n, cap;
    int ok, done;
    char err[160];
};

static void dl_fail(sftp_dirlist *d, const char *msg)
{
    if (d->ok || !d->err[0]) {
        strncpy(d->err, msg, sizeof(d->err) - 1);
        d->err[sizeof(d->err) - 1] = '\0';
    }
    d->ok = 0;
}

static void dl_finish(sftp_dirlist *d)
{
    d->done = 1;
    d->cb(d, d->ctx);
}

static void dl_closed(sftp *s, const sftp_response *r, void *ctx)
{
    (void)s; (void)r;
    dl_finish((sftp_dirlist *)ctx);
}

static void dl_close_and_finish(sftp_dirlist *d)
{
    if (d->handle && sftp_close(d->s, d->handle, d->hlen, dl_closed, d)) return;
    dl_finish(d);
}

static void dl_read(sftp *s, const sftp_response *r, void *ctx)
{
    sftp_dirlist *d = (sftp_dirlist *)ctx;
    int i;
    if (r->type == SFTP_R_NAME) {
        for (i = 0; i < r->nnames; i++) {
            const sftp_name *nm = &r->names[i];
            if (!nm->name || !strcmp(nm->name, ".") || !strcmp(nm->name, "..")) continue;
            if (d->n == d->cap) {
                int ncap = d->cap ? d->cap * 2 : 64;
                sftp_name *ne = (sftp_name *)realloc(d->entries, (size_t)ncap * sizeof(sftp_name));
                if (!ne) { dl_fail(d, "out of memory"); dl_close_and_finish(d); return; }
                d->entries = ne; d->cap = ncap;
            }
            d->entries[d->n].name = dupn((const u8 *)nm->name, strlen(nm->name));
            d->entries[d->n].longname = dupn((const u8 *)(nm->longname ? nm->longname : ""), nm->longname ? strlen(nm->longname) : 0);
            d->entries[d->n].attrs = nm->attrs;
            d->n++;
        }
        if (!sftp_readdir(s, d->handle, d->hlen, dl_read, d)) { dl_fail(d, sftp_error(s) ? sftp_error(s) : "request failed"); dl_close_and_finish(d); }
        return;
    }
    if (r->type == SFTP_R_STATUS && r->status != SFTP_EOF) dl_fail(d, r->message);
    dl_close_and_finish(d);
}

static void dl_opened(sftp *s, const sftp_response *r, void *ctx)
{
    sftp_dirlist *d = (sftp_dirlist *)ctx;
    if (r->type != SFTP_R_HANDLE) {
        dl_fail(d, r->type == SFTP_R_STATUS ? r->message : "unexpected response");
        dl_finish(d);
        return;
    }
    d->handle = (u8 *)malloc(r->handle_len ? r->handle_len : 1);
    if (!d->handle) { dl_fail(d, "out of memory"); dl_finish(d); return; }
    memcpy(d->handle, r->handle, r->handle_len);
    d->hlen = r->handle_len;
    if (!sftp_readdir(s, d->handle, d->hlen, dl_read, d)) { dl_fail(d, "request failed"); dl_close_and_finish(d); }
}

sftp_dirlist *sftp_list(sftp *s, const char *path, sftp_dirlist_cb cb, void *ctx)
{
    sftp_dirlist *d = (sftp_dirlist *)calloc(1, sizeof(*d));
    if (!d) return NULL;
    d->s = s; d->cb = cb; d->ctx = ctx; d->ok = 1;
    if (!sftp_opendir(s, path, dl_opened, d)) { free(d); return NULL; }
    return d;
}

int sftp_dirlist_ok(const sftp_dirlist *d) { return d->ok; }
const char *sftp_dirlist_error(const sftp_dirlist *d) { return d->err; }
int sftp_dirlist_count(const sftp_dirlist *d) { return d->n; }
const sftp_name *sftp_dirlist_entry(const sftp_dirlist *d, int i) { return (i >= 0 && i < d->n) ? &d->entries[i] : NULL; }

void sftp_dirlist_free(sftp_dirlist *d)
{
    if (!d) return;
    free_names(d->entries, d->n);
    free(d->handle);
    free(d);
}

/* ------------------------------------------------------------------ */
/* transfers                                                           */
/* ------------------------------------------------------------------ */

typedef struct { sftp_xfer *x; u64 off; u32 len; } xreq;

struct sftp_xfer {
    sftp *s;
    int   upload;
    FILE *f;
    sftp_xfer_cb cb;
    void *ctx;
    int   state;                       /* public: RUNNING until fully drained */
    int   failed, cancelled, finished, closing, close_done;
    char  err[160];
    u8   *handle; size_t hlen;
    u64   total, done;
    u64   next_off;
    u64   eof_at; int eof_known;       /* download */
    int   outstanding;
    struct { u64 off; u32 len; } retry[XFER_WINDOW];
    int   nretry;
    long  file_pos;
    int   local_eof;                   /* upload: nothing left to read locally */
    u8   *chunk;                       /* upload read buffer */
};

static void xf_pump(sftp_xfer *x);

static void xf_fail(sftp_xfer *x, const char *msg)
{
    if (!x->failed) {
        x->failed = 1;
        strncpy(x->err, msg, sizeof(x->err) - 1);
        x->err[sizeof(x->err) - 1] = '\0';
    }
}

static void xf_closed(sftp *s, const sftp_response *r, void *ctx)
{
    sftp_xfer *x = (sftp_xfer *)ctx;
    (void)s;
    if (r->type == SFTP_R_STATUS && r->status != SFTP_OK && !x->failed && !x->cancelled)
        xf_fail(x, r->message);                                   /* e.g. a delayed write error reported on close */
    x->close_done = 1;
    xf_pump(x);
}

/* Decide whether the transfer is over, and if so close the handle and report. */
static void xf_maybe_finish(sftp_xfer *x)
{
    int all_done;
    if (x->finished || x->outstanding > 0) return;
    if (x->upload) all_done = x->local_eof;
    else all_done = x->nretry == 0 && (x->eof_known || (x->total && x->next_off >= x->total));
    if (!(x->failed || x->cancelled || all_done)) return;
    if (x->handle && !x->closing) {
        x->closing = 1;
        if (sftp_close(x->s, x->handle, x->hlen, xf_closed, x)) return;
        x->close_done = 1;                                        /* could not queue it: nothing to wait for */
    }
    if (x->handle && !x->close_done) return;
    x->finished = 1;
    x->state = x->failed ? SFTP_XFER_FAILED : (x->cancelled ? SFTP_XFER_CANCELLED : SFTP_XFER_DONE);
    x->cb(x, x->ctx);
}

static int xf_seek(sftp_xfer *x, u64 off)
{
    if ((long)off == x->file_pos) return 0;
    if (fseek(x->f, (long)off, SEEK_SET) != 0) return -1;
    x->file_pos = (long)off;
    return 0;
}

static void xf_read_done(sftp *s, const sftp_response *r, void *ctx)
{
    xreq *q = (xreq *)ctx;
    sftp_xfer *x = q->x;
    u64 off = q->off;
    u32 len = q->len;
    (void)s;
    free(q);
    x->outstanding--;

    if (r->type == SFTP_R_DATA && !x->failed && !x->cancelled) {
        size_t n = r->data_len;
        if (n > len) n = len;
        if (n == 0) {
            x->eof_known = 1;
            if (off < x->eof_at) x->eof_at = off;
        } else {
            if (xf_seek(x, off) != 0 || fwrite(r->data, 1, n, x->f) != n) {
                xf_fail(x, "cannot write the local file");
            } else {
                x->file_pos += (long)n;
                x->done += n;
                if (n < len && x->nretry < XFER_WINDOW) {          /* short read: fetch the rest */
                    x->retry[x->nretry].off = off + n;
                    x->retry[x->nretry].len = len - (u32)n;
                    x->nretry++;
                }
            }
        }
    } else if (r->type == SFTP_R_STATUS) {
        if (r->status == SFTP_EOF) {
            x->eof_known = 1;
            if (off < x->eof_at) x->eof_at = off;
        } else if (r->status != SFTP_OK && !x->failed && !x->cancelled) {
            xf_fail(x, r->message);
        }
    }
    x->cb(x, x->ctx);
    xf_pump(x);
}

static void xf_write_done(sftp *s, const sftp_response *r, void *ctx)
{
    xreq *q = (xreq *)ctx;
    sftp_xfer *x = q->x;
    u32 len = q->len;
    (void)s;
    free(q);
    x->outstanding--;
    if (r->type == SFTP_R_STATUS && r->status == SFTP_OK) x->done += len;
    else if (!x->failed && !x->cancelled) xf_fail(x, r->type == SFTP_R_STATUS ? r->message : "unexpected response");
    x->cb(x, x->ctx);
    xf_pump(x);
}

static void xf_pump(sftp_xfer *x)
{
    while (!x->failed && !x->cancelled && x->handle && x->outstanding < XFER_WINDOW) {
        xreq *q;
        u32 id;
        if (!x->upload) {
            u64 off, limit;
            u32 len;
            if (x->nretry > 0) {
                x->nretry--;
                off = x->retry[x->nretry].off; len = x->retry[x->nretry].len;
            } else {
                limit = x->eof_known ? x->eof_at : (x->total ? x->total : (u64)0xffffffffffffffffULL);
                if (x->next_off >= limit) break;
                off = x->next_off;
                len = XFER_CHUNK;
                if (limit - off < len) len = (u32)(limit - off);
                x->next_off += len;
            }
            q = (xreq *)malloc(sizeof(*q));
            if (!q) { xf_fail(x, "out of memory"); break; }
            q->x = x; q->off = off; q->len = len;
            id = sftp_read(x->s, x->handle, x->hlen, off, len, xf_read_done, q);
            if (!id) { free(q); xf_fail(x, sftp_error(x->s) ? sftp_error(x->s) : "request failed"); break; }
        } else {
            size_t n;
            if (x->local_eof) break;
            n = fread(x->chunk, 1, XFER_CHUNK, x->f);
            if (n == 0) {
                if (ferror(x->f)) xf_fail(x, "cannot read the local file");
                x->local_eof = 1;
                break;
            }
            q = (xreq *)malloc(sizeof(*q));
            if (!q) { xf_fail(x, "out of memory"); break; }
            q->x = x; q->off = x->next_off; q->len = (u32)n;
            id = sftp_write(x->s, x->handle, x->hlen, x->next_off, x->chunk, (u32)n, xf_write_done, q);
            if (!id) { free(q); xf_fail(x, sftp_error(x->s) ? sftp_error(x->s) : "request failed"); break; }
            x->next_off += n;
        }
        x->outstanding++;
    }
    xf_maybe_finish(x);
}

static void xf_opened(sftp *s, const sftp_response *r, void *ctx)
{
    sftp_xfer *x = (sftp_xfer *)ctx;
    (void)s;
    if (r->type != SFTP_R_HANDLE) {
        xf_fail(x, r->type == SFTP_R_STATUS ? r->message : "unexpected response");
        x->cb(x, x->ctx);
        xf_maybe_finish(x);
        return;
    }
    x->handle = (u8 *)malloc(r->handle_len ? r->handle_len : 1);
    if (!x->handle) { xf_fail(x, "out of memory"); x->cb(x, x->ctx); xf_maybe_finish(x); return; }
    memcpy(x->handle, r->handle, r->handle_len);
    x->hlen = r->handle_len;
    xf_pump(x);
}

static sftp_xfer *xf_new(sftp *s, FILE *f, int upload, u64 total, sftp_xfer_cb cb, void *ctx)
{
    sftp_xfer *x = (sftp_xfer *)calloc(1, sizeof(*x));
    if (!x) return NULL;
    x->s = s; x->f = f; x->upload = upload; x->total = total; x->cb = cb; x->ctx = ctx;
    x->eof_at = (u64)0xffffffffffffffffULL;
    x->file_pos = ftell(f);
    if (x->file_pos < 0) x->file_pos = 0;
    if (upload) {
        x->chunk = (u8 *)malloc(XFER_CHUNK);
        if (!x->chunk) { free(x); return NULL; }
    }
    return x;
}

sftp_xfer *sftp_download(sftp *s, const char *remote, FILE *out, u64 size_hint, sftp_xfer_cb cb, void *ctx)
{
    sftp_xfer *x = xf_new(s, out, 0, size_hint, cb, ctx);
    if (!x) return NULL;
    if (!sftp_open(s, remote, SFTP_OPEN_READ, 0, xf_opened, x)) { free(x); return NULL; }
    return x;
}

sftp_xfer *sftp_upload(sftp *s, const char *remote, FILE *in, u32 mode, u64 size_hint, sftp_xfer_cb cb, void *ctx)
{
    sftp_xfer *x = xf_new(s, in, 1, size_hint, cb, ctx);
    if (!x) return NULL;
    if (!sftp_open(s, remote, SFTP_OPEN_WRITE | SFTP_OPEN_CREAT | SFTP_OPEN_TRUNC, mode, xf_opened, x)) {
        free(x->chunk); free(x); return NULL;
    }
    return x;
}

int sftp_xfer_state(const sftp_xfer *x) { return x->state; }
u64 sftp_xfer_bytes(const sftp_xfer *x) { return x->done; }
u64 sftp_xfer_total(const sftp_xfer *x) { return x->total; }
const char *sftp_xfer_error(const sftp_xfer *x) { return x->err; }

void sftp_xfer_cancel(sftp_xfer *x)
{
    if (x->finished) return;
    x->cancelled = 1;
    xf_maybe_finish(x);
}

void sftp_xfer_free(sftp_xfer *x)
{
    if (!x) return;
    free(x->handle);
    free(x->chunk);
    free(x);
}
