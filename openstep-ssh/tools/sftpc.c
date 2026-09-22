/*
 * sftpc -- command-line SFTP client used to test core/sftp.c against a real sftp-server.
 *
 *   sftpc [-p port] [-i keyfile] user@host  cmd args [+ cmd args ...]
 *
 *   ls PATH | get REMOTE LOCAL | put LOCAL REMOTE | mkdir P | rmdir P | rm P
 *   mv FROM TO | stat P | realpath P | chmod OCTAL P
 *
 * Several commands can run in one session, separated by a literal "+".
 * Environment: SSHC_PASSPHRASE for encrypted keys; SFTPC_CANCEL_AFTER=<bytes> cancels
 * the first transfer once that many bytes have moved.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include "../core/ssh.h"
#include "../core/sftp.h"
#include "../core/rng.h"

static ssh_session *ssh;
static sftp *sf;
static int chan = -1, exit_code = 0, finished;
static char **cmds[32];
static int ncmds, cur = -1;
static sftp_xfer *xfer;
static unsigned long cancel_after;
static FILE *xfile;

static void fail(const char *fmt, const char *a)
{
    fprintf(stderr, "sftpc: "); fprintf(stderr, fmt, a); fprintf(stderr, "\n");
    exit_code = 1;
}

static int dial(const char *host, const char *port)
{
    struct addrinfo hints, *res, *ai;
    int fd = -1;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static void next_cmd(void);

static void cmd_done(void) { next_cmd(); }

/* ---- per-command callbacks ---- */
static void status_cb(sftp *s, const sftp_response *r, void *ctx)
{
    (void)s; (void)ctx;
    if (r->type == SFTP_R_STATUS && r->status != SFTP_OK) fail("%s", r->message);
    cmd_done();
}

static void path_cb(sftp *s, const sftp_response *r, void *ctx)
{
    (void)s; (void)ctx;
    if (r->type == SFTP_R_NAME && r->nnames > 0) printf("%s\n", r->names[0].name);
    else if (r->type == SFTP_R_STATUS) fail("%s", r->message);
    cmd_done();
}

static void stat_cb(sftp *s, const sftp_response *r, void *ctx)
{
    (void)s; (void)ctx;
    if (r->type == SFTP_R_ATTRS)
        printf("size=%lu mode=%o %s\n", (unsigned long)r->attrs.size, (unsigned)(r->attrs.perms & 07777),
               SFTP_S_ISDIR(r->attrs.perms) ? "dir" : SFTP_S_ISREG(r->attrs.perms) ? "file" : "other");
    else if (r->type == SFTP_R_STATUS) fail("%s", r->message);
    cmd_done();
}

static int name_cmp(const void *a, const void *b)
{
    return strcmp(((const sftp_name *)a)->name, ((const sftp_name *)b)->name);
}

static void list_cb(sftp_dirlist *d, void *ctx)
{
    int i, n = sftp_dirlist_count(d);
    sftp_name *copy;
    (void)ctx;
    if (!sftp_dirlist_ok(d)) { fail("%s", sftp_dirlist_error(d)); sftp_dirlist_free(d); cmd_done(); return; }
    copy = (sftp_name *)malloc((size_t)(n ? n : 1) * sizeof(sftp_name));
    for (i = 0; i < n; i++) copy[i] = *sftp_dirlist_entry(d, i);
    qsort(copy, (size_t)n, sizeof(sftp_name), name_cmp);
    for (i = 0; i < n; i++)
        printf("%c %lu %s\n", SFTP_S_ISDIR(copy[i].attrs.perms) ? 'd' : '-', (unsigned long)copy[i].attrs.size, copy[i].name);
    free(copy);
    sftp_dirlist_free(d);
    cmd_done();
}

static void xfer_cb(sftp_xfer *x, void *ctx)
{
    (void)ctx;
    if (sftp_xfer_state(x) == SFTP_XFER_RUNNING) {
        if (cancel_after && sftp_xfer_bytes(x) >= cancel_after) { cancel_after = 0; sftp_xfer_cancel(x); }
        return;
    }
    if (xfile) { fclose(xfile); xfile = NULL; }
    if (sftp_xfer_state(x) == SFTP_XFER_FAILED) fail("%s", sftp_xfer_error(x));
    else if (sftp_xfer_state(x) == SFTP_XFER_CANCELLED) printf("cancelled after %lu bytes\n", (unsigned long)sftp_xfer_bytes(x));
    else printf("transferred %lu bytes\n", (unsigned long)sftp_xfer_bytes(x));
    xfer = NULL;
    sftp_xfer_free(x);
    cmd_done();
}

static void stat_then_get(sftp *s, const sftp_response *r, void *ctx)
{
    char **c = (char **)ctx;
    u64 size = (r->type == SFTP_R_ATTRS) ? r->attrs.size : 0;
    xfile = fopen(c[2], "wb");
    if (!xfile) { fail("cannot create %s", c[2]); cmd_done(); return; }
    xfer = sftp_download(s, c[1], xfile, size, xfer_cb, NULL);
    if (!xfer) { fclose(xfile); xfile = NULL; fail("%s", "cannot start download"); cmd_done(); }
}

static void start_cmd(char **c)
{
    const char *op = c[0];
    struct stat st;
    if (!strcmp(op, "ls")) { if (!sftp_list(sf, c[1], list_cb, NULL)) { fail("%s", "cannot list"); cmd_done(); } }
    else if (!strcmp(op, "stat")) sftp_stat(sf, c[1], stat_cb, NULL);
    else if (!strcmp(op, "realpath")) sftp_realpath(sf, c[1], path_cb, NULL);
    else if (!strcmp(op, "mkdir")) sftp_mkdir(sf, c[1], 0755, status_cb, NULL);
    else if (!strcmp(op, "rmdir")) sftp_rmdir(sf, c[1], status_cb, NULL);
    else if (!strcmp(op, "rm")) sftp_remove(sf, c[1], status_cb, NULL);
    else if (!strcmp(op, "mv")) sftp_rename(sf, c[1], c[2], status_cb, NULL);
    else if (!strcmp(op, "chmod")) sftp_setmode(sf, c[2], (u32)strtoul(c[1], NULL, 8), status_cb, NULL);
    else if (!strcmp(op, "get")) sftp_stat(sf, c[1], stat_then_get, c);
    else if (!strcmp(op, "put")) {
        xfile = fopen(c[1], "rb");
        if (!xfile || stat(c[1], &st) != 0) { fail("cannot read %s", c[1]); cmd_done(); return; }
        xfer = sftp_upload(sf, c[2], xfile, (u32)(st.st_mode & 0777), (u64)st.st_size, xfer_cb, NULL);
        if (!xfer) { fclose(xfile); xfile = NULL; fail("%s", "cannot start upload"); cmd_done(); }
    } else { fail("unknown command %s", op); cmd_done(); }
}

static void next_cmd(void)
{
    if (exit_code || ++cur >= ncmds) {
        finished = 1;
        ssh_channel_close(ssh, chan);
        return;
    }
    start_cmd(cmds[cur]);
}

static void sftp_ready(sftp *s, void *ctx) { (void)s; (void)ctx; next_cmd(); }

static void pump_sftp_out(void)
{
    size_t n;
    const u8 *p;
    int w;
    if (!sf || chan < 0) return;
    for (;;) {
        p = sftp_output(sf, &n);
        if (!n) return;
        w = ssh_channel_write(ssh, chan, p, n);
        if (w <= 0) return;
        sftp_output_done(sf, (size_t)w);
    }
}

static int has_method(const char *list, const char *m)
{
    size_t n = strlen(m);
    const char *p = list;
    while (*p) {
        const char *e = strchr(p, ',');
        size_t l = e ? (size_t)(e - p) : strlen(p);
        if (l == n && memcmp(p, m, n) == 0) return 1;
        if (!e) break;
        p = e + 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *port = "22", *keyfile = NULL;
    int opt, fd, tried = 0, done = 0, i, have_key = 0;
    char *user, *host, *at;
    ssh_key key;
    u8 buf[16384];
    static char keybuf[16384];

    while ((opt = getopt(argc, argv, "p:i:")) != -1) {
        if (opt == 'p') port = optarg; else if (opt == 'i') keyfile = optarg; else return 2;
    }
    if (optind + 2 > argc) { fprintf(stderr, "usage: sftpc [-p port] [-i key] user@host cmd args [+ cmd ...]\n"); return 2; }
    user = strdup(argv[optind]);
    at = strchr(user, '@');
    if (!at) return 2;
    *at = '\0'; host = at + 1;
    if (getenv("SFTPC_CANCEL_AFTER")) cancel_after = strtoul(getenv("SFTPC_CANCEL_AFTER"), NULL, 10);

    cmds[0] = &argv[optind + 1];
    ncmds = 1;
    for (i = optind + 1; i < argc; i++)
        if (!strcmp(argv[i], "+")) { argv[i] = NULL; cmds[ncmds++] = &argv[i + 1]; }

    if (!ssh_rng_seed_system()) return 2;
    if (keyfile) {
        FILE *f = fopen(keyfile, "rb");
        size_t n;
        const char *err;
        if (!f) return 2;
        n = fread(keybuf, 1, sizeof(keybuf) - 1, f);
        fclose(f);
        if (ssh_key_parse_private(keybuf, n, getenv("SSHC_PASSPHRASE"), &key, &err) != 0) { fprintf(stderr, "sftpc: key: %s\n", err); return 2; }
        have_key = 1;
    }
    fd = dial(host, port);
    if (fd < 0) { fprintf(stderr, "sftpc: cannot connect\n"); return 2; }
    ssh = ssh_new(user);
    ssh_start(ssh);

    while (!done) {
        ssh_event ev;
        const u8 *out;
        size_t outlen;
        fd_set rf;
        int n;

        while (ssh_next_event(ssh, &ev)) {
            switch (ev.type) {
            case SSH_EV_HOSTKEY: ssh_hostkey_accept(ssh, 1); break;
            case SSH_EV_AUTH_NEEDED:
            case SSH_EV_AUTH_FAILED:
                if (have_key && !tried && has_method(ev.text, "publickey")) { tried = 1; ssh_auth_publickey(ssh, &key); }
                else { fprintf(stderr, "sftpc: authentication failed\n"); exit_code = 2; done = 1; }
                break;
            case SSH_EV_AUTH_OK: chan = ssh_channel_open_session(ssh); break;
            case SSH_EV_CHAN_OPEN: ssh_channel_request_subsystem(ssh, chan, "sftp"); break;
            case SSH_EV_CHAN_SUCCESS:
                sf = sftp_new();
                sftp_start(sf, sftp_ready, NULL);
                break;
            case SSH_EV_CHAN_FAILURE: fprintf(stderr, "sftpc: server refused the sftp subsystem\n"); exit_code = 2; done = 1; break;
            case SSH_EV_CHAN_DATA:
                if (sf && sftp_input(sf, ev.data, ev.len) < 0) { fail("protocol error: %s", sftp_error(sf)); done = 1; }
                break;
            case SSH_EV_CHAN_CLOSE: done = 1; break;
            case SSH_EV_DISCONNECT: case SSH_EV_ERROR:
                fprintf(stderr, "sftpc: %s\n", ev.text); exit_code = exit_code ? exit_code : 2; done = 1; break;
            default: break;
            }
        }
        pump_sftp_out();
        out = ssh_output(ssh, &outlen);
        while (outlen) {
            ssize_t w = write(fd, out, outlen);
            if (w <= 0) { done = 1; break; }
            ssh_output_done(ssh, (size_t)w);
            out = ssh_output(ssh, &outlen);
        }
        if (done || ssh_is_closed(ssh)) break;
        FD_ZERO(&rf);
        FD_SET(fd, &rf);
        n = select(fd + 1, &rf, NULL, NULL, NULL);
        if (n < 0) { if (errno == EINTR) continue; break; }
        if (FD_ISSET(fd, &rf)) {
            ssize_t r = read(fd, buf, sizeof(buf));
            if (r <= 0) break;
            ssh_rng_add_timing(0);
            ssh_input(ssh, buf, (size_t)r);
        }
    }
    (void)finished;
    if (sf) sftp_free(sf);
    close(fd);
    ssh_free(ssh);
    return exit_code;
}
