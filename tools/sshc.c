/*
 * sshc -- minimal command-line client used to test the SSH engine against real
 * servers on the development host.  Not part of the OPENSTEP build.
 *
 *   sshc [-p port] [-i keyfile] [-c ciphers] [-m macs] [-F fingerprint]
 *        [-e command] [-t] [-v] user@host
 *
 * Password / keyboard-interactive answers come from $SSHC_PASSWORD.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include "../core/ssh.h"
#include "../core/rng.h"

static int verbose;

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

static int load_key(const char *path, ssh_key *k)
{
    FILE *f = fopen(path, "rb");
    static char buf[16384];
    size_t n;
    const char *err;
    if (!f) { perror(path); return -1; }
    n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    if (ssh_key_parse_private(buf, n, getenv("SSHC_PASSPHRASE"), k, &err) != 0) {
        fprintf(stderr, "sshc: %s: %s\n", path, err);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *port = "22", *keyfile = NULL, *ciphers = NULL, *macs = NULL, *kexlist = NULL;
    const char *want_fp = NULL, *cmd = NULL, *target = NULL;
    int opt, fd, ch = -1, exit_status = 255, done = 0;
    int tried_key = 0, tried_pw = 0, tried_kbd = 0, stdin_open = 1, chan_ready = 0;
    char *user, *host, *at;
    ssh_session *s;
    ssh_key key;
    int have_key = 0;
    const char *pw = getenv("SSHC_PASSWORD");
    u8 buf[16384];

    while ((opt = getopt(argc, argv, "p:i:c:m:k:F:e:tv")) != -1) {
        switch (opt) {
        case 'p': port = optarg; break;
        case 'i': keyfile = optarg; break;
        case 'c': ciphers = optarg; break;
        case 'm': macs = optarg; break;
        case 'k': kexlist = optarg; break;
        case 'F': want_fp = optarg; break;
        case 'e': cmd = optarg; break;
        case 't': break;
        case 'v': verbose = 1; break;
        default: fprintf(stderr, "usage: sshc [-p port] [-i key] [-c ciphers] [-m macs] [-F fp] [-e cmd] [-t] [-v] user@host\n"); return 2;
        }
    }
    if (optind >= argc) { fprintf(stderr, "sshc: missing user@host\n"); return 2; }
    target = argv[optind];
    user = strdup(target);
    at = strchr(user, '@');
    if (!at) { fprintf(stderr, "sshc: need user@host\n"); return 2; }
    *at = '\0'; host = at + 1;

    if (!ssh_rng_seed_system()) { fprintf(stderr, "sshc: no system entropy\n"); return 2; }
    if (keyfile) { if (load_key(keyfile, &key) != 0) return 2; have_key = 1; }

    fd = dial(host, port);
    if (fd < 0) { fprintf(stderr, "sshc: cannot connect to %s:%s\n", host, port); return 2; }

    s = ssh_new(user);
    ssh_set_prefs(s, ciphers, macs);
    ssh_set_kex_prefs(s, kexlist);
    if (ssh_start(s) < 0) { fprintf(stderr, "sshc: start failed\n"); }

    while (!done) {
        ssh_event ev;
        const u8 *out;
        size_t outlen;
        fd_set rf, wf;
        int maxfd, n;

        while (ssh_next_event(s, &ev)) {
            switch (ev.type) {
            case SSH_EV_HOSTKEY:
                if (verbose) fprintf(stderr, "sshc: host key %s %s\n", ev.text2, ev.text);
                if (want_fp && strcmp(want_fp, ev.text) != 0) {
                    fprintf(stderr, "sshc: fingerprint mismatch (got %s)\n", ev.text);
                    ssh_hostkey_accept(s, 0);
                } else {
                    ssh_hostkey_accept(s, 1);
                }
                break;
            case SSH_EV_BANNER:
                fputs(ev.text, stderr);
                break;
            case SSH_EV_AUTH_NEEDED:
            case SSH_EV_AUTH_FAILED:
                if (verbose) fprintf(stderr, "sshc: auth methods: %s\n", ev.text);
                if (have_key && !tried_key && has_method(ev.text, "publickey")) {
                    tried_key = 1; ssh_auth_publickey(s, &key);
                } else if (pw && !tried_pw && has_method(ev.text, "password")) {
                    tried_pw = 1; ssh_auth_password(s, pw);
                } else if (pw && !tried_kbd && has_method(ev.text, "keyboard-interactive")) {
                    tried_kbd = 1; ssh_auth_kbdint_start(s);
                } else {
                    fprintf(stderr, "sshc: authentication failed (server allows: %s)\n", ev.text);
                    done = 1;
                }
                break;
            case SSH_EV_KBDINT: {
                int i, cnt = ssh_kbdint_count(s);
                const char *ans[8];
                for (i = 0; i < cnt && i < 8; i++) ans[i] = pw ? pw : "";
                ssh_auth_kbdint_respond(s, ans, cnt);
                break;
            }
            case SSH_EV_AUTH_OK:
                if (verbose) fprintf(stderr, "sshc: authenticated; kex=%s cipher=%s mac=%s server=%s\n",
                                     ssh_kex_name(s), ssh_cipher_name(s), ssh_mac_name(s), ssh_server_version(s));
                ch = ssh_channel_open_session(s);
                break;
            case SSH_EV_CHAN_OPEN:
                if (cmd) {
                    ssh_channel_request_exec(s, ch, cmd);
                } else {
                    ssh_channel_request_pty(s, ch, "vt100", 80, 24, 0, 0);
                    ssh_channel_request_shell(s, ch);
                }
                chan_ready = 1;
                break;
            case SSH_EV_CHAN_OPEN_FAILED:
                fprintf(stderr, "sshc: channel open failed: %s\n", ev.text);
                done = 1;
                break;
            case SSH_EV_CHAN_FAILURE:
                fprintf(stderr, "sshc: channel request refused\n");
                break;
            case SSH_EV_CHAN_DATA:
                fwrite(ev.data, 1, ev.len, ev.ext ? stderr : stdout);
                fflush(ev.ext ? stderr : stdout);
                break;
            case SSH_EV_CHAN_EXIT:
                exit_status = ev.code;
                break;
            case SSH_EV_CHAN_CLOSE:
                ssh_disconnect(s, "bye");
                done = 1;
                break;
            case SSH_EV_DISCONNECT:
                if (verbose) fprintf(stderr, "sshc: server disconnected: %s\n", ev.text);
                done = 1;
                break;
            case SSH_EV_ERROR:
                fprintf(stderr, "sshc: error: %s\n", ev.text);
                done = 1;
                break;
            default:
                break;
            }
        }

        out = ssh_output(s, &outlen);
        while (outlen) {                                    /* blocking write is fine for a test tool */
            ssize_t w = write(fd, out, outlen);
            if (w <= 0) { done = 1; break; }
            ssh_output_done(s, (size_t)w);
            out = ssh_output(s, &outlen);
        }
        if (done || ssh_is_closed(s)) break;

        FD_ZERO(&rf); FD_ZERO(&wf);
        FD_SET(fd, &rf);
        maxfd = fd;
        if (chan_ready && stdin_open && ssh_channel_backlog(s, ch) < 65536) {
            FD_SET(0, &rf);
        }
        n = select(maxfd + 1, &rf, &wf, NULL, NULL);
        if (n < 0) { if (errno == EINTR) continue; perror("select"); break; }
        if (FD_ISSET(fd, &rf)) {
            ssize_t r = read(fd, buf, sizeof(buf));
            if (r <= 0) { if (verbose) fprintf(stderr, "sshc: connection closed\n"); break; }
            ssh_rng_add_timing(0);
            ssh_input(s, buf, (size_t)r);
        }
        if (FD_ISSET(0, &rf)) {
            ssize_t r = read(0, buf, sizeof(buf));
            if (r <= 0) { stdin_open = 0; if (cmd) ssh_channel_eof(s, ch); }
            else ssh_channel_write(s, ch, buf, (size_t)r);
        }
    }
    close(fd);
    ssh_free(s);
    if (have_key) ssh_key_wipe(&key);
    return exit_status & 0xff;
}
