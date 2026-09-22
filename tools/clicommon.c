#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <termios.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "clicommon.h"
#include "../core/ssh_types.h"
#include "../core/knownhosts.h"

int cli_dial(const char *tool, const char *host, const char *service)
{
    struct addrinfo hints, *res, *ai;
    int fd = -1, gai;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    gai = getaddrinfo(host, service, &hints, &res);
    if (gai != 0) {
        fprintf(stderr, "%s: %s: %s\n", tool, host, gai_strerror(gai));
        return -1;
    }
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) fprintf(stderr, "%s: cannot connect to %s port %s\n", tool, host, service);
    return fd;
}

int cli_has_method(const char *list, const char *m)
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

char *cli_read_secret(const char *tool, const char *prompt)
{
    static char buf[256];
    struct termios oldt, newt;
    int have_termios;
    size_t n;

    if (!isatty(0)) {
        fprintf(stderr, "%s: a password/passphrase is needed, but stdin is not a terminal to prompt on\n", tool);
        return NULL;
    }
    fputs(prompt, stderr);
    fflush(stderr);
    have_termios = tcgetattr(0, &oldt) == 0;
    if (have_termios) {
        newt = oldt;
        newt.c_lflag &= (tcflag_t)~ECHO;
        tcsetattr(0, TCSAFLUSH, &newt);
    }
    if (!fgets(buf, sizeof(buf), stdin)) {
        if (have_termios) tcsetattr(0, TCSAFLUSH, &oldt);
        fputc('\n', stderr);
        return NULL;
    }
    if (have_termios) tcsetattr(0, TCSAFLUSH, &oldt);
    fputc('\n', stderr);
    n = strlen(buf);
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) buf[--n] = '\0';
    return buf;
}

int cli_confirm(const char *prompt)
{
    char line[16];
    if (!isatty(0)) return 0;
    fputs(prompt, stderr);
    fflush(stderr);
    if (!fgets(line, sizeof(line), stdin)) return 0;
    return line[0] == 'y' || line[0] == 'Y';
}

const char *cli_default_known_hosts(void)
{
    static char buf[1024];
    const char *home = getenv("HOME");
    if (home && strlen(home) + 20 < sizeof(buf)) {
        strcpy(buf, home);
        strcat(buf, "/.ssh/known_hosts");
    } else {
        strcpy(buf, "known_hosts");
    }
    return buf;
}

int cli_check_hostkey(const char *tool, const char *known_hosts_path, const char *host, int port,
                      const u8 *blob, size_t blen, const char *fp, const char *keytype, int quiet)
{
    int r = kh_check(known_hosts_path, host, port, blob, blen);
    char q[512];

    if (r == KH_MATCH) return 1;

    if (r == KH_UNKNOWN) {
        fprintf(stderr, "%s: the authenticity of host '%s' cannot be established.\n", tool, host);
        fprintf(stderr, "%s: %s key fingerprint is %s\n", tool, keytype, fp);
        sprintf(q, "%s: are you sure you want to continue connecting (yes/no)? ", tool);
        if (!cli_confirm(q)) {
            fprintf(stderr, "%s: host key verification failed\n", tool);
            return 0;
        }
        if (kh_add(known_hosts_path, host, port, blob, blen) == 0 && !quiet)
            fprintf(stderr, "%s: permanently added '%s' (%s) to the list of known hosts (%s)\n",
                    tool, host, keytype, known_hosts_path);
        return 1;
    }

    /* KH_CHANGED: refuse by default, exactly like ssh's own StrictHostKeyChecking. */
    fprintf(stderr, "%s: WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\n", tool);
    fprintf(stderr, "%s: the %s host key for '%s' has changed, and the new key fingerprint is %s\n",
            tool, keytype, host, fp);
    fprintf(stderr, "%s: someone could be eavesdropping on you right now (man-in-the-middle attack),"
                    " or the host key was legitimately changed.\n", tool);
    fprintf(stderr, "%s: add the correct host key in %s to get rid of this message,\n", tool, known_hosts_path);
    fprintf(stderr, "%s: or, if you are certain this is expected, connect anyway.\n", tool);
    sprintf(q, "%s: host key verification failed. Connect anyway (yes/no)? ", tool);
    return cli_confirm(q);
}

/* Only one raw-mode terminal is ever active at a time in these tools, so a single static save
 * slot (rather than something the caller would need to store and pass back by pointer) is enough. */
static struct termios cli_raw_saved;

int cli_raw_enter(int fd)
{
    struct termios raw;
    if (!isatty(fd)) return -1;
    if (tcgetattr(fd, &cli_raw_saved) != 0) return -1;
    raw = cli_raw_saved;
    raw.c_lflag &= (tcflag_t)~(ECHO | ICANON | ISIG | IEXTEN);
    raw.c_iflag &= (tcflag_t)~(IXON | ICRNL | BRKINT | INPCK | ISTRIP);
    raw.c_oflag &= (tcflag_t)~OPOST;
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    tcsetattr(fd, TCSAFLUSH, &raw);
    return 1;
}

void cli_raw_restore(int fd, int token)
{
    if (token != 1) return;
    tcsetattr(fd, TCSAFLUSH, &cli_raw_saved);
}

void cli_split_userhost(const char *arg, const char *deflogin, char **user, char **host)
{
    const char *at = strchr(arg, '@');
    if (at) {
        size_t ulen = (size_t)(at - arg);
        *user = (char *)malloc(ulen + 1);
        memcpy(*user, arg, ulen);
        (*user)[ulen] = '\0';
        *host = cli_xstrdup(at + 1);
    } else {
        *user = cli_xstrdup(deflogin);
        *host = cli_xstrdup(arg);
    }
}

char *cli_xstrdup(const char *s)
{
    size_t n = strlen(s) + 1;
    char *p = (char *)malloc(n);
    if (!p) { fprintf(stderr, "out of memory\n"); exit(2); }
    memcpy(p, s, n);
    return p;
}

const char *cli_current_user(void)
{
    static char buf[256];
    char *p = getlogin();
    struct passwd *pw;

    if (p && *p) { strncpy(buf, p, sizeof(buf) - 1); buf[sizeof(buf) - 1] = '\0'; return buf; }
    p = getenv("LOGNAME");
    if (!p || !*p) p = getenv("USER");
    if (p && *p) { strncpy(buf, p, sizeof(buf) - 1); buf[sizeof(buf) - 1] = '\0'; return buf; }
    pw = getpwuid(getuid());
    if (pw && pw->pw_name) { strncpy(buf, pw->pw_name, sizeof(buf) - 1); buf[sizeof(buf) - 1] = '\0'; return buf; }
    return NULL;
}
