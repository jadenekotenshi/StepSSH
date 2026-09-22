/*
 * stepssh -- command-line SSH-2 client, syntax-compatible with OpenSSH's `ssh` for the subset of
 * functionality this engine implements.
 *
 *   stepssh [-p port] [-l login_name] [-i identity_file] [-c cipher_spec] [-m mac_spec]
 *           [-o option] [-F configfile] [-q] [-v] [-t] [-T] [-4] [-6] [user@]hostname [command]
 *
 * Not implemented, and rejected with an explanation rather than silently ignored (accepting a
 * flag whose entire point is a missing capability would look like it worked): -L/-R/-D (port
 * forwarding -- local forwarding is in the StepSSH.app GUI, under Connection > Port Forwarding),
 * -A (agent forwarding), -N (only meaningful with forwarding), -X/-Y (X11 forwarding). ssh_config
 * files (-F) are not parsed; only a handful of -o options are recognised (see run_opt() below).
 *
 * Authentication tries, in order: a key (-i; STEPSSH_PASSPHRASE or an interactive prompt for an
 * encrypted one), then a password (STEPSSH_PASSWORD or an interactive prompt), then
 * keyboard-interactive (answered interactively, one prompt at a time, honouring each prompt's
 * echo flag -- STEPSSH_PASSWORD also answers a single-prompt "Password:"-style exchange
 * non-interactively). Host keys go through ~/.ssh/known_hosts exactly as OpenSSH's `ssh` does
 * (trust-on-first-use, loud refusal on a changed key) -- see tools/clicommon.c.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include "../core/ssh.h"
#include "../core/rng.h"
#include "../core/oscompat.h"
#include "clicommon.h"

static int verbose, quiet;

static int load_key(const char *path, ssh_key *k)
{
    FILE *f = fopen(path, "rb");
    static char buf[16384];
    size_t n;
    const char *err;
    const char *pass = getenv("STEPSSH_PASSPHRASE");
    int rc, tries;

    if (!f) { fprintf(stderr, "stepssh: %s: %s\n", path, strerror(errno)); return -1; }
    n = fread(buf, 1, sizeof(buf), f);
    fclose(f);

    rc = ssh_key_parse_private(buf, n, pass, k, &err);
    for (tries = 0; (rc == -2 || rc == -3) && tries < 3; tries++) {
        char prompt[320];
        sprintf(prompt, "stepssh: Enter passphrase for %.280s: ", path);
        pass = cli_read_secret("stepssh", prompt);
        if (!pass) break;
        rc = ssh_key_parse_private(buf, n, pass, k, &err);
    }
    if (rc != 0) { fprintf(stderr, "stepssh: %s: %s\n", path, err); return -1; }
    return 0;
}

/* A handful of ssh_config(5) option names, since -F (a config *file*) is not parsed at all. */
static void run_opt(const char *opt, const char **known_hosts, int *strict)
{
    if (!strncmp(opt, "UserKnownHostsFile=", 19)) {
        *known_hosts = opt + 19;
    } else if (!strncmp(opt, "StrictHostKeyChecking=", 22)) {
        const char *v = opt + 22;
        *strict = strcmp(v, "no") != 0;    /* "no" only recognised value that changes anything */
    } else {
        fprintf(stderr, "stepssh: -o %s: not recognised; ignoring\n", opt);
    }
}

static void reject(char opt)
{
    const char *why;
    switch (opt) {
    case 'L': case 'R': case 'D':
        why = "port forwarding is not available from the command line"
              " (local forwarding is in the StepSSH.app GUI: Connection > Port Forwarding)";
        break;
    case 'A': why = "agent forwarding is not implemented by this SSH engine"; break;
    case 'N': why = "-N (no remote command) is only useful with port forwarding, not implemented here"; break;
    case 'X': case 'Y': why = "X11 forwarding is not implemented by this SSH engine"; break;
    default: why = "not implemented"; break;
    }
    fprintf(stderr, "stepssh: -%c: %s\n", opt, why);
}

int main(int argc, char **argv)
{
    const char *port = "22", *keyfile = NULL, *ciphers = NULL, *macs = NULL, *kexlist = NULL;
    const char *known_hosts = NULL, *login_opt = NULL;
    int strict_hostkey = 1, force_pty = 0, no_pty = 0;
    int opt, fd, ch = -1, exit_status = 255, done = 0;
    int tried_key = 0, tried_pw = 0, tried_kbd = 0, stdin_open = 1, chan_ready = 0, have_pty = 0;
    int raw_token = -1;
    char *user = NULL, *host = NULL, *cmd = NULL;
    ssh_session *s;
    ssh_key key;
    int have_key = 0;
    u8 buf[16384];

    while ((opt = getopt(argc, argv, "p:l:i:c:m:o:F:e:qvtT46CL:R:D:ANXY")) != -1) {
        switch (opt) {
        case 'p': port = optarg; break;
        case 'l': login_opt = optarg; break;
        case 'i': keyfile = optarg; break;
        case 'c': ciphers = optarg; break;
        case 'm': macs = optarg; break;
        case 'o': run_opt(optarg, &known_hosts, &strict_hostkey); break;
        case 'F': fprintf(stderr, "stepssh: -F: config files are not read; -F is accepted and ignored\n"); break;
        case 'e': break;                    /* the ~ escape character: no escape sequences are implemented */
        case 'q': quiet = 1; break;
        case 'v': verbose = 1; break;
        case 't': force_pty = 1; break;
        case 'T': no_pty = 1; break;
        case '4': case '6': break;          /* address family: this build always tries whatever the resolver returns */
        case 'C': break;                    /* compression: not implemented; silently not compressing is harmless */
        case 'L': case 'R': case 'D': case 'A': case 'N': case 'X': case 'Y': reject((char)opt); return 2;
        default:
            fprintf(stderr, "usage: stepssh [-p port] [-l login_name] [-i identity_file] [-c ciphers] [-m macs]\n"
                            "               [-o option] [-q] [-v] [-t] [-T] [user@]hostname [command]\n");
            return 2;
        }
    }
    if (optind >= argc) { fprintf(stderr, "stepssh: missing hostname\n"); return 2; }
    if (!known_hosts) known_hosts = cli_default_known_hosts();

    {
        const char *deflogin = login_opt ? login_opt : cli_current_user();
        if (!deflogin) { fprintf(stderr, "stepssh: cannot determine the local user name; use -l\n"); return 2; }
        cli_split_userhost(argv[optind], deflogin, &user, &host);
    }
    optind++;
    if (optind < argc) {
        size_t total = 1;
        int i;
        for (i = optind; i < argc; i++) total += strlen(argv[i]) + 1;
        cmd = (char *)malloc(total);
        cmd[0] = '\0';
        for (i = optind; i < argc; i++) {
            if (i > optind) strcat(cmd, " ");
            strcat(cmd, argv[i]);
        }
    }

    if (!cli_seed_rng("stepssh")) return 2;
    if (keyfile) { if (load_key(keyfile, &key) != 0) return 2; have_key = 1; }

    fd = cli_dial("stepssh", host, port);
    if (fd < 0) return 2;

    s = ssh_new(user);
    ssh_set_prefs(s, ciphers, macs);
    ssh_set_kex_prefs(s, kexlist);
    if (ssh_start(s) < 0) fprintf(stderr, "stepssh: start failed\n");

    while (!done) {
        ssh_event ev;
        const u8 *out;
        size_t outlen;
        fd_set rf, wf;
        int maxfd, n;

        while (ssh_next_event(s, &ev)) {
            switch (ev.type) {
            case SSH_EV_HOSTKEY: {
                char fp[96], keytype[48];
                strncpy(fp, ev.text, sizeof(fp) - 1); fp[sizeof(fp) - 1] = '\0';
                strncpy(keytype, ev.text2, sizeof(keytype) - 1); keytype[sizeof(keytype) - 1] = '\0';
                if (!strict_hostkey) {
                    ssh_hostkey_accept(s, 1);
                } else {
                    ssh_hostkey_accept(s, cli_check_hostkey("stepssh", known_hosts, host, atoi(port),
                                                            ev.data, ev.len, fp, keytype, quiet));
                }
                break;
            }
            case SSH_EV_BANNER:
                if (!quiet) fputs(ev.text, stderr);
                break;
            case SSH_EV_AUTH_NEEDED:
            case SSH_EV_AUTH_FAILED:
                if (verbose) fprintf(stderr, "stepssh: auth methods: %s\n", ev.text);
                if (have_key && !tried_key && cli_has_method(ev.text, "publickey")) {
                    tried_key = 1; ssh_auth_publickey(s, &key);
                } else if (!tried_pw && cli_has_method(ev.text, "password")) {
                    const char *pw = getenv("STEPSSH_PASSWORD");
                    char prompt[256];
                    tried_pw = 1;
                    /* field widths, not snprintf (not guaranteed on OPENSTEP 4.2): user/host come
                     * from argv and could in principle be longer than this buffer. */
                    sprintf(prompt, "%.100s@%.100s's password: ", user, host);
                    if (!pw) pw = cli_read_secret("stepssh", prompt);
                    if (!pw) { done = 1; break; }
                    ssh_auth_password(s, pw);
                } else if (!tried_kbd && cli_has_method(ev.text, "keyboard-interactive")) {
                    tried_kbd = 1; ssh_auth_kbdint_start(s);
                } else {
                    fprintf(stderr, "stepssh: %s@%s: Permission denied (%s).\n", user, host, ev.text);
                    done = 1;
                }
                break;
            case SSH_EV_KBDINT: {
                int i, cnt = ssh_kbdint_count(s);
                const char *ans[16];
                const char *pw = getenv("STEPSSH_PASSWORD");
                const char *name = ssh_kbdint_name(s), *instr = ssh_kbdint_instruction(s);
                if (!quiet && name && name[0]) fprintf(stderr, "%s\n", name);
                if (!quiet && instr && instr[0]) fprintf(stderr, "%s\n", instr);
                for (i = 0; i < cnt && i < 16; i++) {
                    int echo = 0;
                    const char *p = ssh_kbdint_prompt(s, i, &echo);
                    if (pw && cnt == 1) {
                        ans[i] = pw;
                    } else if (echo) {
                        char line[256];
                        fputs(p, stderr); fflush(stderr);
                        if (!fgets(line, sizeof(line), stdin)) line[0] = '\0';
                        line[strcspn(line, "\r\n")] = '\0';
                        ans[i] = cli_xstrdup(line);
                    } else {
                        const char *r = cli_read_secret("stepssh", p);
                        ans[i] = r ? r : "";
                    }
                }
                ssh_auth_kbdint_respond(s, ans, cnt);
                break;
            }
            case SSH_EV_AUTH_OK:
                if (verbose) fprintf(stderr, "stepssh: authenticated; kex=%s cipher=%s mac=%s server=%s\n",
                                     ssh_kex_name(s), ssh_cipher_name(s), ssh_mac_name(s), ssh_server_version(s));
                ch = ssh_channel_open_session(s);
                break;
            case SSH_EV_CHAN_OPEN:
                have_pty = (!cmd || force_pty) && !no_pty;
                if (have_pty) {
                    const char *term = getenv("TERM");
                    ssh_channel_request_pty(s, ch, term && *term ? term : "vt100", 80, 24, 0, 0);
                }
                if (cmd) ssh_channel_request_exec(s, ch, cmd);
                else ssh_channel_request_shell(s, ch);
                chan_ready = 1;
                if (have_pty) raw_token = cli_raw_enter(0);
                break;
            case SSH_EV_CHAN_OPEN_FAILED:
                fprintf(stderr, "stepssh: channel open failed: %s\n", ev.text);
                done = 1;
                break;
            case SSH_EV_CHAN_FAILURE:
                fprintf(stderr, "stepssh: channel request refused\n");
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
                if (verbose) fprintf(stderr, "stepssh: server disconnected: %s\n", ev.text);
                done = 1;
                break;
            case SSH_EV_ERROR:
                fprintf(stderr, "stepssh: error: %s\n", ev.text);
                done = 1;
                break;
            default:
                break;
            }
        }

        out = ssh_output(s, &outlen);
        while (outlen) {                                    /* blocking write; fine for a CLI tool */
            ssize_t w = write(fd, out, outlen);
            if (w <= 0) { done = 1; break; }
            ssh_output_done(s, (size_t)w);
            out = ssh_output(s, &outlen);
        }
        if (done || ssh_is_closed(s)) break;

        FD_ZERO(&rf); FD_ZERO(&wf);
        FD_SET(fd, &rf);
        maxfd = fd;
        if (chan_ready && stdin_open && ssh_channel_backlog(s, ch) < 65536) FD_SET(0, &rf);
        n = select(maxfd + 1, &rf, &wf, NULL, NULL);
        if (n < 0) { if (errno == EINTR) continue; perror("stepssh: select"); break; }
        if (FD_ISSET(fd, &rf)) {
            ssize_t r = read(fd, buf, sizeof(buf));
            if (r <= 0) { if (verbose) fprintf(stderr, "stepssh: connection closed\n"); break; }
            ssh_rng_add_timing(0);
            ssh_input(s, buf, (size_t)r);
        }
        if (FD_ISSET(0, &rf)) {
            ssize_t r = read(0, buf, sizeof(buf));
            if (r <= 0) { stdin_open = 0; ssh_channel_eof(s, ch); }
            else ssh_channel_write(s, ch, buf, (size_t)r);
        }
    }
    if (have_pty) cli_raw_restore(0, raw_token);
    close(fd);
    ssh_free(s);
    if (have_key) ssh_key_wipe(&key);
    free(user); free(host); free(cmd);
    return exit_status & 0xff;
}
