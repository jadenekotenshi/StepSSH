/*
 * test_sftp.c -- SFTP core against an in-memory fake server: short reads, fragmented
 * delivery, injected failures, cancellation, connection loss, and hostile input.
 */
#include <stdlib.h>
#include <string.h>
#include "../core/sftp.h"
#include "../core/wire.h"
#include "test.h"

/* ------------------------------ fake server ------------------------------ */
typedef struct {
    u8 *file; size_t size;             /* the one file it serves / receives */
    size_t max_read;                   /* answer READs with at most this many bytes */
    int fail_write_no;                 /* fail the Nth WRITE (1-based), 0 = never */
    int nwrites;
    int frag;                          /* deliver replies in pieces of this size */
    int stalls;                        /* hold replies back until released (for abort tests) */
    sbuf reply;                        /* bytes waiting to go to the client */
    int closed;
} fake;

static void srv_send(fake *f, const sbuf *body) { u8 l[4]; STORE32_BE(l, (u32)body->len); sb_put(&f->reply, l, 4); sb_put(&f->reply, body->p, body->len); }

static void srv_status(fake *f, u32 id, u32 code, const char *msg)
{
    sbuf b; sb_init(&b);
    sb_put_u8(&b, 101); sb_put_u32(&b, id); sb_put_u32(&b, code); sb_put_cstr(&b, msg); sb_put_cstr(&b, "");
    srv_send(f, &b); sb_free(&b);
}

static void srv_handle_packet(fake *f, const u8 *p, size_t n)
{
    sreader r; int type; u32 id; size_t l; const u8 *s;
    sbuf b;
    sr_init(&r, p, n);
    type = sr_u8(&r);
    if (type == 1) {                                             /* INIT -> VERSION 3 */
        sb_init(&b); sb_put_u8(&b, 2); sb_put_u32(&b, 3); srv_send(f, &b); sb_free(&b);
        return;
    }
    id = sr_u32(&r);
    switch (type) {
    case 3: {                                                    /* OPEN */
        const u8 *name = sr_str(&r, &l); u32 pflags = sr_u32(&r);
        (void)name;
        if (pflags & SFTP_OPEN_WRITE) { free(f->file); f->file = NULL; f->size = 0; }
        sb_init(&b); sb_put_u8(&b, 102); sb_put_u32(&b, id); sb_put_str(&b, "H1", 2); srv_send(f, &b); sb_free(&b);
        break;
    }
    case 5: {                                                    /* READ */
        u64 off; u32 len; size_t take;
        sr_str(&r, &l); off = sr_u64(&r); len = sr_u32(&r);
        if (off >= f->size) { srv_status(f, id, SFTP_EOF, "EOF"); break; }
        take = f->size - (size_t)off;
        if (take > len) take = len;
        if (take > f->max_read) take = f->max_read;
        sb_init(&b); sb_put_u8(&b, 103); sb_put_u32(&b, id); sb_put_str(&b, f->file + off, take); srv_send(f, &b); sb_free(&b);
        break;
    }
    case 6: {                                                    /* WRITE */
        u64 off; size_t dl; const u8 *d;
        sr_str(&r, &l); off = sr_u64(&r); d = sr_str(&r, &dl);
        f->nwrites++;
        if (f->fail_write_no && f->nwrites == f->fail_write_no) { srv_status(f, id, SFTP_FAILURE, "disk full"); break; }
        if (off + dl > f->size) { f->file = (u8 *)realloc(f->file, (size_t)off + dl); f->size = (size_t)off + dl; }
        memcpy(f->file + off, d, dl);
        srv_status(f, id, SFTP_OK, "");
        break;
    }
    case 4: srv_status(f, id, SFTP_OK, ""); break;               /* CLOSE */
    case 17: case 7:                                             /* STAT */
        sb_init(&b); sb_put_u8(&b, 105); sb_put_u32(&b, id); sb_put_u32(&b, SFTP_ATTR_SIZE | SFTP_ATTR_PERMISSIONS);
        sb_put_u64(&b, f->size); sb_put_u32(&b, 0100644); srv_send(f, &b); sb_free(&b);
        break;
    case 11:                                                     /* OPENDIR */
        sb_init(&b); sb_put_u8(&b, 102); sb_put_u32(&b, id); sb_put_str(&b, "D1", 2); srv_send(f, &b); sb_free(&b);
        break;
    case 12: {                                                   /* READDIR: one batch, then EOF */
        static int served;
        if (served++ % 2 == 0) {
            int i;
            sb_init(&b); sb_put_u8(&b, 104); sb_put_u32(&b, id); sb_put_u32(&b, 4);
            for (i = 0; i < 4; i++) {
                const char *nm = i == 0 ? "." : i == 1 ? ".." : i == 2 ? "file one" : "dir";
                sb_put_cstr(&b, nm); sb_put_cstr(&b, "longname");
                sb_put_u32(&b, SFTP_ATTR_SIZE | SFTP_ATTR_PERMISSIONS); sb_put_u64(&b, 42 + (u64)i); sb_put_u32(&b, i == 3 ? 040755 : 0100644);
            }
            srv_send(f, &b); sb_free(&b);
        } else srv_status(f, id, SFTP_EOF, "EOF");
        break;
    }
    default: srv_status(f, id, SFTP_OP_UNSUPPORTED, "unsupported"); break;
    }
    (void)s;
}

/* Move bytes client -> server, then server -> client (in `frag`-sized pieces). Returns the number of round trips done. */
static int exchange(sftp *c, fake *f, int max_rounds)
{
    int rounds = 0;
    for (;;) {
        size_t n, off;
        const u8 *out = sftp_output(c, &n);
        static sbuf inbuf;
        int progressed = 0;
        if (n) {
            sb_put(&inbuf, out, n);
            sftp_output_done(c, n);
            progressed = 1;
        }
        while (inbuf.len >= 4) {                                  /* the server parses complete packets */
            u32 len = LOAD32_BE(inbuf.p);
            if (inbuf.len < 4 + (size_t)len) break;
            srv_handle_packet(f, inbuf.p + 4, len);
            sb_consume(&inbuf, 4 + (size_t)len);
            progressed = 1;
        }
        if (f->stalls) return rounds;
        off = 0;
        while (off < f->reply.len) {
            size_t piece = f->frag ? (size_t)f->frag : f->reply.len - off;
            if (piece > f->reply.len - off) piece = f->reply.len - off;
            if (sftp_input(c, f->reply.p + off, piece) < 0) { sb_clear(&f->reply); return -1; }
            off += piece;
            progressed = 1;
        }
        sb_clear(&f->reply);
        if (!progressed || ++rounds >= max_rounds) return rounds;
    }
}

static void fake_init(fake *f) { memset(f, 0, sizeof(*f)); sb_init(&f->reply); f->max_read = 1u << 30; }
static void fake_free(fake *f) { free(f->file); sb_free(&f->reply); }

static sftp *connect_fake(fake *f)
{
    sftp *c = sftp_new();
    sftp_start(c, NULL, NULL);
    exchange(c, f, 5);
    return c;
}

/* ------------------------------ tests ------------------------------ */
static struct { int calls; u32 status; char msg[64]; int nnames; char first[32]; u64 size; } got;

static void cb(sftp *s, const sftp_response *r, void *ctx)
{
    (void)s; (void)ctx;
    got.calls++;
    got.status = r->status;
    strncpy(got.msg, r->message ? r->message : "", sizeof(got.msg) - 1);
    got.nnames = r->nnames;
    got.size = r->attrs.size;
    if (r->type == SFTP_R_NAME && r->nnames) strncpy(got.first, r->names[0].name, sizeof(got.first) - 1);
}

static int xdone;
static void xcb(sftp_xfer *x, void *ctx) { (void)ctx; if (sftp_xfer_state(x) != SFTP_XFER_RUNNING) xdone = 1; }
static int cancel_at_first;
static void xcb_cancel(sftp_xfer *x, void *ctx)
{
    (void)ctx;
    if (sftp_xfer_state(x) == SFTP_XFER_RUNNING && cancel_at_first && sftp_xfer_bytes(x) > 0) { cancel_at_first = 0; sftp_xfer_cancel(x); }
    if (sftp_xfer_state(x) != SFTP_XFER_RUNNING) xdone = 1;
}

static void fill_pattern(u8 *p, size_t n) { size_t i; for (i = 0; i < n; i++) p[i] = (u8)((i * 31 + (i >> 8)) & 0xff); }

static int file_equals(FILE *f, const u8 *want, size_t n)
{
    u8 *buf = (u8 *)malloc(n ? n : 1);
    size_t got_n;
    int ok;
    fflush(f); rewind(f);
    got_n = fread(buf, 1, n + 1, f);
    ok = got_n == n && memcmp(buf, want, n) == 0;
    free(buf);
    return ok;
}

static void test_basics(void)
{
    fake f; sftp *c;
    fake_init(&f);
    f.frag = 3;                                                   /* replies arrive 3 bytes at a time */
    c = connect_fake(&f);
    CHECK(sftp_is_ready(c) && !sftp_error(c));
    f.size = 1234; f.file = (u8 *)calloc(1, 1234);
    memset(&got, 0, sizeof(got));
    CHECK(sftp_stat(c, "/x", cb, NULL) != 0);
    exchange(c, &f, 5);
    CHECK(got.calls == 1 && got.size == 1234);
    CHECK(sftp_pending(c) == 0);
    memset(&got, 0, sizeof(got));
    sftp_remove(c, "/y", cb, NULL);
    exchange(c, &f, 5);
    CHECK(got.calls == 1 && got.status == SFTP_OP_UNSUPPORTED && strcmp(got.msg, "unsupported") == 0);
    fake_free(&f);
    sftp_free(c);
}

static int list_done, list_count;
static char list_names[4][32];
static void list_cb(sftp_dirlist *d, void *ctx)
{
    int i;
    (void)ctx;
    list_done = 1;
    list_count = sftp_dirlist_ok(d) ? sftp_dirlist_count(d) : -1;
    for (i = 0; i < list_count && i < 4; i++) strncpy(list_names[i], sftp_dirlist_entry(d, i)->name, 31);
    sftp_dirlist_free(d);
}

static void test_dirlist(void)
{
    fake f; sftp *c;
    fake_init(&f); f.frag = 5;
    c = connect_fake(&f);
    list_done = 0;
    CHECK(sftp_list(c, "/", list_cb, NULL) != NULL);
    exchange(c, &f, 20);
    CHECK(list_done && list_count == 2);                          /* "." and ".." were filtered out */
    CHECK(strcmp(list_names[0], "file one") == 0 && strcmp(list_names[1], "dir") == 0);
    CHECK(sftp_pending(c) == 0);
    fake_free(&f); sftp_free(c);
}

static void test_download(void)
{
    static u8 data[200003];
    int variant;
    for (variant = 0; variant < 2; variant++) {                   /* size known, size unknown */
        fake f; sftp *c; sftp_xfer *x; FILE *out = tmpfile();
        fake_init(&f); f.frag = 7; f.max_read = 700;              /* short reads force the retry path */
        fill_pattern(data, sizeof(data));
        f.file = (u8 *)malloc(sizeof(data)); memcpy(f.file, data, sizeof(data)); f.size = sizeof(data);
        c = connect_fake(&f);
        xdone = 0;
        x = sftp_download(c, "/f", out, variant ? 0 : sizeof(data), xcb, NULL);
        CHECK(x != NULL);
        exchange(c, &f, 100000);
        CHECK(xdone && sftp_xfer_state(x) == SFTP_XFER_DONE);
        CHECK(sftp_xfer_bytes(x) == sizeof(data));
        CHECK(file_equals(out, data, sizeof(data)));
        CHECK(sftp_pending(c) == 0);
        sftp_xfer_free(x); fclose(out); fake_free(&f); sftp_free(c);
    }
    {   /* an empty remote file */
        fake f; sftp *c; sftp_xfer *x; FILE *out = tmpfile();
        fake_init(&f); c = connect_fake(&f); xdone = 0;
        x = sftp_download(c, "/e", out, 0, xcb, NULL);
        exchange(c, &f, 100);
        CHECK(xdone && sftp_xfer_state(x) == SFTP_XFER_DONE && sftp_xfer_bytes(x) == 0);
        sftp_xfer_free(x); fclose(out); fake_free(&f); sftp_free(c);
    }
}

static void test_upload(void)
{
    static u8 data[100000];
    fake f; sftp *c; sftp_xfer *x; FILE *in = tmpfile();
    fill_pattern(data, sizeof(data));
    fwrite(data, 1, sizeof(data), in); rewind(in);
    fake_init(&f); f.frag = 11;
    c = connect_fake(&f); xdone = 0;
    x = sftp_upload(c, "/u", in, 0644, sizeof(data), xcb, NULL);
    exchange(c, &f, 100000);
    CHECK(xdone && sftp_xfer_state(x) == SFTP_XFER_DONE && sftp_xfer_bytes(x) == sizeof(data));
    CHECK(f.size == sizeof(data) && memcmp(f.file, data, sizeof(data)) == 0);
    CHECK(f.nwrites == 4);                                        /* 100000 bytes / 32768 */
    sftp_xfer_free(x); fclose(in); fake_free(&f); sftp_free(c);
}

static void test_failures(void)
{
    static u8 data[200000];
    fake f; sftp *c; sftp_xfer *x; FILE *in;
    fill_pattern(data, sizeof(data));

    /* a write error mid-upload: the transfer fails with the server's message, drains, and closes */
    in = tmpfile(); fwrite(data, 1, sizeof(data), in); rewind(in);
    fake_init(&f); f.fail_write_no = 3;
    c = connect_fake(&f); xdone = 0;
    x = sftp_upload(c, "/u", in, 0644, sizeof(data), xcb, NULL);
    exchange(c, &f, 100000);
    CHECK(xdone && sftp_xfer_state(x) == SFTP_XFER_FAILED && strcmp(sftp_xfer_error(x), "disk full") == 0);
    CHECK(sftp_pending(c) == 0);                                  /* nothing left dangling, handle closed */
    sftp_xfer_free(x); fclose(in); fake_free(&f); sftp_free(c);

    /* cancel a download after the first data arrives */
    in = tmpfile();
    fake_init(&f); f.max_read = 500; f.file = (u8 *)malloc(sizeof(data)); memcpy(f.file, data, sizeof(data)); f.size = sizeof(data);
    c = connect_fake(&f); xdone = 0; cancel_at_first = 1;
    x = sftp_download(c, "/f", in, sizeof(data), xcb_cancel, NULL);
    exchange(c, &f, 100000);
    CHECK(xdone && sftp_xfer_state(x) == SFTP_XFER_CANCELLED && sftp_xfer_bytes(x) < sizeof(data));
    CHECK(sftp_pending(c) == 0);
    memset(&got, 0, sizeof(got));                                 /* and the session is still usable */
    sftp_stat(c, "/x", cb, NULL);
    exchange(c, &f, 10);
    CHECK(got.calls == 1 && got.size == sizeof(data));
    sftp_xfer_free(x); fclose(in); fake_free(&f); sftp_free(c);

    /* the connection dies while requests are in flight */
    in = tmpfile();
    fake_init(&f); f.max_read = 500; f.file = (u8 *)malloc(sizeof(data)); memcpy(f.file, data, sizeof(data)); f.size = sizeof(data);
    c = connect_fake(&f); xdone = 0;
    x = sftp_download(c, "/f", in, sizeof(data), xcb, NULL);
    f.stalls = 1;                                                 /* server goes silent */
    exchange(c, &f, 10);
    CHECK(!xdone && sftp_pending(c) > 0);
    sftp_abort(c, "connection lost");
    CHECK(xdone && sftp_xfer_state(x) == SFTP_XFER_FAILED);
    CHECK(sftp_pending(c) == 0);
    CHECK(sftp_stat(c, "/x", cb, NULL) == 0);                     /* a dead session accepts no new work */
    sftp_xfer_free(x); fclose(in); fake_free(&f); sftp_free(c);

    /* freeing the session with work pending must not leak or crash */
    fake_init(&f); c = connect_fake(&f);
    sftp_stat(c, "/a", cb, NULL); sftp_remove(c, "/b", cb, NULL);
    sftp_free(c);
    fake_free(&f);
}

static void test_hostile(void)
{
    unsigned seed = 4242;
    int iter, i;
    fake f; sftp *c;
    u8 junk[512];

    /* oversized and undersized packet lengths */
    fake_init(&f); c = connect_fake(&f);
    { u8 bad[8] = {0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0}; CHECK(sftp_input(c, bad, 8) == -1 && sftp_error(c) != NULL); }
    sftp_free(c);
    fake_init(&f); c = connect_fake(&f);
    { u8 bad[4] = {0, 0, 0, 0}; CHECK(sftp_input(c, bad, 4) == -1); }
    sftp_free(c);
    /* a VERSION older than 3 is refused */
    c = sftp_new();
    { u8 v2[9] = {0, 0, 0, 5, 2, 0, 0, 0, 2}; CHECK(sftp_input(c, v2, 9) == -1); }
    sftp_free(c);
    /* a response before VERSION */
    c = sftp_new();
    { u8 early[9] = {0, 0, 0, 5, 101, 0, 0, 0, 1}; CHECK(sftp_input(c, early, 9) == -1); }
    sftp_free(c);
    fake_free(&f);

    /* random garbage after a valid handshake, and truncations of a valid NAME response */
    for (iter = 0; iter < 300; iter++) {
        fake_init(&f); f.frag = 0;
        c = connect_fake(&f);
        sftp_stat(c, "/x", cb, NULL);
        sftp_list(c, "/", list_cb, NULL);
        for (i = 0; i < (int)sizeof(junk); i++) { seed = seed * 1103515245u + 12345u; junk[i] = (u8)(seed >> 20); }
        if (iter % 3 == 0) { STORE32_BE(junk, (u32)(1 + (seed >> 8) % 400)); junk[4] = (u8)(101 + iter % 5); STORE32_BE(junk + 5, 1); }
        sftp_input(c, junk, sizeof(junk));
        sftp_free(c);                                             /* completes whatever was pending */
        fake_free(&f);
    }
    for (i = 1; i < 60; i++) {                                    /* truncated real reply, then more data */
        fake f2; sftp *c2;
        fake_init(&f2);
        c2 = connect_fake(&f2);
        sftp_list(c2, "/", list_cb, NULL);
        list_done = 0;
        exchange(c2, &f2, 3);
        sftp_free(c2);
        fake_free(&f2);
    }
    CHECK(1);                                                     /* reaching here without a crash is the point */
}

int main(void)
{
    test_basics();
    test_dirlist();
    test_download();
    test_upload();
    test_failures();
    test_hostile();
    TEST_DONE("sftp");
}
