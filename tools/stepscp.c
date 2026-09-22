/*
 * stepscp -- file copy, syntax-compatible with OpenSSH's `scp` for the common case (exactly one
 * source and one target, one of them remote). The wire protocol is SFTP, not the legacy scp/rcp
 * protocol -- like modern OpenSSH, which can use either; unlike it, this only ever uses SFTP, so
 * it needs a real sftp-server on the far end (every OpenSSH sshd has one; nothing else does).
 *
 *   stepscp [-r] [-p] [-P port] [-i identity_file] [-c ciphers] [-m macs] [-o option] [-q] [-C]
 *           source target
 *
 * Either source or target (never both) is [user@]host:path; the other is a local path. -r copies
 * a whole directory tree. Unlike `cp -r`/real `scp -r`, the destination is always the exact copy
 * of the source tree -- it is never nested one level deeper because a same-named destination
 * already exists.
 *
 * -p preserves the source file's permission bits on upload (sftp_upload already sets them from
 * the local file); it does *not* preserve modification times in either direction -- core/sftp.c
 * does not expose a way to set them, so this is a real, documented gap rather than a silent one.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
/* OPENSTEP 4.2's <dirent.h> is a thin forwarder: it only pulls in the real DIR/struct dirent
 * definitions (from <sys/dir.h>/<sys/dirent.h>) when the feature-test macro _POSIX_SOURCE is
 * defined; without it, the header is effectively empty ("undefined type, found DIR" -- found on
 * real hardware). Defined only around this one include, not for the whole file, since a
 * feature-test macro can in principle change what *other* headers expose too, and the
 * sys/socket.h/netinet/in.h networking code elsewhere in this file is already proven working
 * without it -- no reason to risk changing that. */
#define _POSIX_SOURCE 1
#include <dirent.h>
#undef _POSIX_SOURCE
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include "../core/ssh.h"
#include "../core/sftp.h"
#include "../core/rng.h"
#include "../core/oscompat.h"
#include "clicommon.h"

enum { ITEM_FILE, ITEM_DIR };
typedef struct { char *local, *remote; int kind; } item;

static ssh_session *ssh;
static sftp *sf;
static int chan = -1, exit_code, done, quiet, preserve, uploading;
static item *items; static int n_items, cap_items, cur = -1;
static sftp_xfer *xfer;
static FILE *xfile;

static void fail(const char *fmt, const char *a) { fprintf(stderr, "stepscp: "); fprintf(stderr, fmt, a); fprintf(stderr, "\n"); exit_code = 1; }

/* "dir/name" into a fixed 2048-byte buffer -- unlike a passphrase prompt, a path that overflows
 * this can't just be truncated (that would silently point at the wrong file), so this refuses
 * instead: the entry is skipped with a warning rather than sprintf() overrunning the buffer for
 * a pathologically deep -r tree. */
static int join_path(char out[2048], const char *dir, const char *name)
{
    size_t dl = strlen(dir), nl = strlen(name);
    if (dl + 1 + nl + 1 > 2048) { fail("path too long, skipping: %s/...", dir); return -1; }
    memcpy(out, dir, dl);
    out[dl] = '/';
    memcpy(out + dl + 1, name, nl + 1);
    return 0;
}

static void push(const char *local, const char *remote, int kind)
{
    if (n_items == cap_items) { cap_items = cap_items ? cap_items * 2 : 64; items = (item *)realloc(items, (size_t)cap_items * sizeof(item)); }
    items[n_items].local = cli_xstrdup(local);
    items[n_items].remote = cli_xstrdup(remote);
    items[n_items].kind = kind;
    n_items++;
}

static void advance(void);

static void upload_dir(const item *it)
{
    DIR *d = opendir(it->local);
    struct dirent *de;
    if (!d) { fail("cannot read directory %s", it->local); advance(); return; }
    while ((de = readdir(d)) != NULL) {
        char lp[2048], rp[2048];
        struct stat st;
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        if (join_path(lp, it->local, de->d_name) < 0 || join_path(rp, it->remote, de->d_name) < 0) continue;
        if (stat(lp, &st) != 0) continue;
        push(lp, rp, S_ISDIR(st.st_mode) ? ITEM_DIR : ITEM_FILE);
    }
    closedir(d);
    advance();
}

static void mkdir_then_list(sftp *s, const sftp_response *r, void *ctx)
{
    (void)s; (void)r; (void)ctx;
    upload_dir(&items[cur]);           /* status ignored: "already exists" is fine too */
}

static void download_list_cb(sftp_dirlist *dl, void *ctx)
{
    item *it = (item *)ctx;
    int i, n;
    if (!sftp_dirlist_ok(dl)) { fail("cannot list %s", it->remote); sftp_dirlist_free(dl); advance(); return; }
    n = sftp_dirlist_count(dl);
    for (i = 0; i < n; i++) {
        const sftp_name *e = sftp_dirlist_entry(dl, i);
        char lp[2048], rp[2048];
        if (!strcmp(e->name, ".") || !strcmp(e->name, "..")) continue;
        if (join_path(lp, it->local, e->name) < 0 || join_path(rp, it->remote, e->name) < 0) continue;
        if (SFTP_S_ISDIR(e->attrs.perms)) push(lp, rp, ITEM_DIR);
        else if (SFTP_S_ISREG(e->attrs.perms)) push(lp, rp, ITEM_FILE);
    }
    sftp_dirlist_free(dl);
    advance();
}

static void xfer_cb(sftp_xfer *x, void *ctx)
{
    (void)ctx;
    if (sftp_xfer_state(x) == SFTP_XFER_RUNNING) return;
    if (xfile) { fclose(xfile); xfile = NULL; }
    if (sftp_xfer_state(x) == SFTP_XFER_FAILED) fail("%s", sftp_xfer_error(x));
    else if (!quiet) fprintf(stderr, "%s\n", items[cur].kind == ITEM_FILE ? items[cur].remote : items[cur].local);
    xfer = NULL;
    sftp_xfer_free(x);
    advance();
}

static void stat_then_download(sftp *s, const sftp_response *r, void *ctx)
{
    item *it = (item *)ctx;
    u64 size = (r->type == SFTP_R_ATTRS) ? r->attrs.size : 0;
    xfile = fopen(it->local, "wb");
    if (!xfile) { fail("cannot create %s", it->local); advance(); return; }
    xfer = sftp_download(s, it->remote, xfile, size, xfer_cb, NULL);
    if (!xfer) { fclose(xfile); xfile = NULL; fail("%s", "cannot start download"); advance(); }
}

static void advance(void)
{
    item *it;
    if (exit_code || ++cur >= n_items) { done = 1; if (chan >= 0) ssh_channel_close(ssh, chan); return; }
    it = &items[cur];
    if (uploading) {
        if (it->kind == ITEM_DIR) { sftp_mkdir(sf, it->remote, 0755, mkdir_then_list, NULL); return; }
        {
            struct stat st;
            xfile = fopen(it->local, "rb");
            if (!xfile || stat(it->local, &st) != 0) { fail("cannot read %s", it->local); advance(); return; }
            xfer = sftp_upload(sf, it->remote, xfile, preserve ? (u32)(st.st_mode & 0777) : 0644, (u64)st.st_size, xfer_cb, NULL);
            if (!xfer) { fclose(xfile); xfile = NULL; fail("%s", "cannot start upload"); advance(); }
        }
    } else {
        if (it->kind == ITEM_DIR) {
            mkdir(it->local, 0755);            /* EEXIST is fine; a real failure surfaces on the files inside */
            sftp_list(sf, it->remote, download_list_cb, it);
            return;
        }
        sftp_stat(sf, it->remote, stat_then_download, it);
    }
}

static void sftp_ready(sftp *s, void *ctx) { (void)s; (void)ctx; advance(); }

static void pump_sftp_out(void)
{
    size_t n; const u8 *p; int w;
    if (!sf || chan < 0) return;
    for (;;) {
        p = sftp_output(sf, &n);
        if (!n) return;
        w = ssh_channel_write(ssh, chan, p, n);
        if (w <= 0) return;
        sftp_output_done(sf, (size_t)w);
    }
}

int main(int argc, char **argv)
{
    const char *port = "22", *keyfile = NULL, *ciphers = NULL, *macs = NULL, *known_hosts = NULL;
    int recursive = 0, strict_hostkey = 1, opt, fd, tried_key = 0, tried_pw = 0, have_key = 0;
    char *user, *host, *rpath, *lpath;
    const char *src, *dst;
    ssh_key key;
    u8 buf[16384];
    static char keybuf[65536];

    while ((opt = getopt(argc, argv, "rpP:i:c:m:o:qC")) != -1) {
        switch (opt) {
        case 'r': recursive = 1; break;
        case 'p': preserve = 1; break;
        case 'P': port = optarg; break;
        case 'i': keyfile = optarg; break;
        case 'c': ciphers = optarg; break;
        case 'm': macs = optarg; break;
        case 'o':
            if (!strncmp(optarg, "UserKnownHostsFile=", 19)) known_hosts = optarg + 19;
            else if (!strncmp(optarg, "StrictHostKeyChecking=", 22)) strict_hostkey = strcmp(optarg + 22, "no") != 0;
            else fprintf(stderr, "stepscp: -o %s: not recognised; ignoring\n", optarg);
            break;
        case 'q': quiet = 1; break;
        case 'C': break;
        default:
            fprintf(stderr, "usage: stepscp [-r] [-p] [-P port] [-i identity_file] [-c ciphers] [-m macs] [-q] source target\n");
            return 2;
        }
    }
    if (optind + 2 != argc) { fprintf(stderr, "stepscp: need exactly one source and one target (remote<->remote copies are not supported)\n"); return 2; }
    src = argv[optind]; dst = argv[optind + 1];
    if (!known_hosts) known_hosts = cli_default_known_hosts();

    {
        /* scp's own heuristic: "host:path", where nothing before the first ':' contains '/'. */
        const char *sc = strchr(src, ':'), *dc = strchr(dst, ':');
        int s_remote = sc && !memchr(src, '/', (size_t)(sc - src));
        int d_remote = dc && !memchr(dst, '/', (size_t)(dc - dst));
        if (s_remote == d_remote) {
            fprintf(stderr, "stepscp: exactly one of source/target must be remote (user@host:path)\n");
            return 2;
        }
        uploading = d_remote;
        {
            const char *remote_arg = uploading ? dst : src;
            const char *colon = strchr(remote_arg, ':');
            const char *deflogin = cli_current_user();
            if (!deflogin) { fprintf(stderr, "stepscp: cannot determine the local user name\n"); return 2; }
            {
                char hostpart[512];
                size_t hl = (size_t)(colon - remote_arg);
                if (hl >= sizeof(hostpart)) hl = sizeof(hostpart) - 1;
                memcpy(hostpart, remote_arg, hl); hostpart[hl] = '\0';
                cli_split_userhost(hostpart, deflogin, &user, &host);
            }
            rpath = cli_xstrdup(colon + 1);
            lpath = cli_xstrdup(uploading ? src : dst);
        }
    }

    if (!ssh_rng_seed_system()) { fprintf(stderr, "stepscp: no system entropy\n"); return 2; }
    if (keyfile) {
        FILE *f = fopen(keyfile, "rb");
        size_t n; const char *err; const char *pass = getenv("STEPSSH_PASSPHRASE"); int rc, tries;
        if (!f) { fprintf(stderr, "stepscp: %s: %s\n", keyfile, strerror(errno)); return 2; }
        n = fread(keybuf, 1, sizeof(keybuf) - 1, f);
        fclose(f);
        rc = ssh_key_parse_private(keybuf, n, pass, &key, &err);
        for (tries = 0; (rc == -2 || rc == -3) && tries < 3; tries++) {
            char prompt[320];
            sprintf(prompt, "stepscp: Enter passphrase for %.280s: ", keyfile);
            pass = cli_read_secret("stepscp", prompt);
            if (!pass) break;
            rc = ssh_key_parse_private(keybuf, n, pass, &key, &err);
        }
        if (rc != 0) { fprintf(stderr, "stepscp: %s: %s\n", keyfile, err); return 2; }
        have_key = 1;
    }

    fd = cli_dial("stepscp", host, port);
    if (fd < 0) return 2;
    ssh = ssh_new(user);
    ssh_set_prefs(ssh, ciphers, macs);
    ssh_start(ssh);

    push(lpath, rpath, recursive ? ITEM_DIR : ITEM_FILE);
    if (!recursive) {
        struct stat st;
        if (uploading && stat(lpath, &st) == 0 && S_ISDIR(st.st_mode)) {
            fprintf(stderr, "stepscp: %s is a directory; use -r\n", lpath);
            return 2;
        }
    }

    while (!done) {
        ssh_event ev;
        const u8 *out; size_t outlen;
        fd_set rf; int n;

        while (ssh_next_event(ssh, &ev)) {
            switch (ev.type) {
            case SSH_EV_HOSTKEY: {
                char fp[96], keytype[48];
                strncpy(fp, ev.text, sizeof(fp) - 1); fp[sizeof(fp) - 1] = '\0';
                strncpy(keytype, ev.text2, sizeof(keytype) - 1); keytype[sizeof(keytype) - 1] = '\0';
                ssh_hostkey_accept(ssh, !strict_hostkey || cli_check_hostkey("stepscp", known_hosts, host, atoi(port),
                                                                             ev.data, ev.len, fp, keytype, quiet));
                break;
            }
            case SSH_EV_AUTH_NEEDED:
            case SSH_EV_AUTH_FAILED:
                if (have_key && !tried_key && cli_has_method(ev.text, "publickey")) { tried_key = 1; ssh_auth_publickey(ssh, &key); }
                else if (!tried_pw && cli_has_method(ev.text, "password")) {
                    char prompt[256]; const char *pw = getenv("STEPSSH_PASSWORD");
                    tried_pw = 1;
                    /* field widths, not snprintf (not guaranteed on OPENSTEP 4.2): user/host come
                     * from argv and could in principle be longer than this buffer. */
                    sprintf(prompt, "%.100s@%.100s's password: ", user, host);
                    if (!pw) pw = cli_read_secret("stepscp", prompt);
                    if (!pw) { done = 1; break; }
                    ssh_auth_password(ssh, pw);
                } else {
                    fprintf(stderr, "stepscp: %s@%s: Permission denied (%s).\n", user, host, ev.text);
                    exit_code = 2; done = 1;
                }
                break;
            case SSH_EV_AUTH_OK: chan = ssh_channel_open_session(ssh); break;
            case SSH_EV_CHAN_OPEN: ssh_channel_request_subsystem(ssh, chan, "sftp"); break;
            case SSH_EV_CHAN_SUCCESS: sf = sftp_new(); sftp_start(sf, sftp_ready, NULL); break;
            case SSH_EV_CHAN_FAILURE: fprintf(stderr, "stepscp: server refused the sftp subsystem\n"); exit_code = 2; done = 1; break;
            case SSH_EV_CHAN_DATA:
                if (sf && sftp_input(sf, ev.data, ev.len) < 0) { fail("protocol error: %s", sftp_error(sf)); done = 1; }
                break;
            case SSH_EV_CHAN_CLOSE: done = 1; break;
            case SSH_EV_DISCONNECT: case SSH_EV_ERROR:
                fprintf(stderr, "stepscp: %s\n", ev.text); exit_code = exit_code ? exit_code : 2; done = 1; break;
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
        FD_ZERO(&rf); FD_SET(fd, &rf);
        n = select(fd + 1, &rf, NULL, NULL, NULL);
        if (n < 0) { if (errno == EINTR) continue; break; }
        if (FD_ISSET(fd, &rf)) {
            ssize_t r = read(fd, buf, sizeof(buf));
            if (r <= 0) break;
            ssh_rng_add_timing(0);
            ssh_input(ssh, buf, (size_t)r);
        }
    }
    if (sf) sftp_free(sf);
    close(fd);
    ssh_free(ssh);
    if (have_key) ssh_key_wipe(&key);
    return exit_code;
}
