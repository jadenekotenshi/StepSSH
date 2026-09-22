#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <termios.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "clicommon.h"
#include "../core/ssh_types.h"
#include "../core/knownhosts.h"

/* getaddrinfo()/struct addrinfo (RFC 2553, later POSIX.1-2001) postdate OPENSTEP 4.2 by several
 * years and are not declared there at all -- gethostbyname()/struct hostent, the API they
 * replaced, is what genuinely existed on a mid-1990s BSD-derived Unix, so that is what this uses.
 * IPv4 only, matching this project's stated scope (the README already lists IPv6 as
 * unsupported); `service` must be numeric (every caller here always passes one). */
int cli_dial(const char *tool, const char *host, const char *service)
{
    struct hostent *he;
    struct sockaddr_in sin;
    unsigned long addr, port;
    char *end;
    int fd;

    port = strtoul(service, &end, 10);
    if (*end != '\0' || port == 0 || port > 65535) {
        fprintf(stderr, "%s: %s: not a valid port number\n", tool, service);
        return -1;
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons((unsigned short)port);

    /* Not "!= (unsigned long)-1": inet_addr()'s failure sentinel is a 32-bit 0xffffffff, which
     * zero-extends into a 64-bit unsigned long as 0x00000000ffffffff -- never equal to a 64-bit
     * all-ones -1, so that comparison never caught a real failure (found on the Mac: it silently
     * treated a plain hostname as if it had resolved to 255.255.255.255). INADDR_NONE is already
     * the correctly-typed constant for this exact comparison. */
    addr = inet_addr(host);
    if (addr != INADDR_NONE) {
        sin.sin_addr.s_addr = addr;
    } else {
        he = gethostbyname(host);
        if (!he || he->h_addrtype != AF_INET) {
            fprintf(stderr, "%s: %s: host not found\n", tool, host);
            return -1;
        }
        memcpy(&sin.sin_addr, he->h_addr_list[0], (size_t)he->h_length);
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { fprintf(stderr, "%s: socket: %s\n", tool, strerror(errno)); return -1; }
    if (connect(fd, (struct sockaddr *)&sin, sizeof(sin)) != 0) {
        fprintf(stderr, "%s: cannot connect to %s port %s: %s\n", tool, host, service, strerror(errno));
        close(fd);
        return -1;
    }
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
