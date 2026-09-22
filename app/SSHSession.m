#import "SSHSession.h"
#import "PromptPanel.h"
#import "SFTPBrowser.h"
#import "PortForward.h"
#import "PortForwardController.h"
#include "knownhosts.h"
#include "rng.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "oscompat.h"

#ifndef INADDR_NONE
#define INADDR_NONE ((unsigned long)0xffffffff)
#endif
#ifndef O_NONBLOCK
#define O_NONBLOCK O_NDELAY
#endif
#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

#ifdef OPENSTEP
/* OPENSTEP's headers lack prototypes for these (see core/oscompat.h).  select() needs
 * fd_set and struct timeval, so it is declared here rather than there. */
extern int fcntl(int fd, int cmd, ...);
extern int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
                  struct timeval *timeout);
#endif

#ifdef OPENSTEP
typedef int sock_len_t;                    /* 4.4BSD-era getsockopt takes int * */
#else
typedef socklen_t sock_len_t;
#endif

#define TICK_SECONDS     0.02
#define CONNECT_TIMEOUT  30
#define KEEPALIVE_SECS   45
#define TICKS_PER_SEC    50

@interface SSHSession (Private)
- (void)status:(NSString *)msg;
- (void)buildWindow;
- (void)beginConnect;
- (void)connected;
- (void)pump;
- (void)processEvents;
- (void)flushOutput;
- (void)flushPending;
- (void)endWithMessage:(NSString *)msg;
- (void)handleHostKey:(ssh_event *)ev;
- (void)handleAuth:(const char *)methods failed:(BOOL)failed code:(int)code text:(const char *)text;
- (void)handleKbdInt;
- (void)loadKey;
- (void)refreshTitle;
- (void)handleSFTPEvent:(ssh_event *)ev;
- (void)flushSFTP;
- (void)closeSFTPChannel;
- (void)sftpEnded:(NSString *)why;
- (void)sftpBecameReady;
- (void)pumpForwards;
- (BOOL)findTunnelForChannel:(int)ch tunnel:(PortTunnel **)outT forward:(PortForward **)outPF;
- (void)handleForwardEvent:(ssh_event *)ev tunnel:(PortTunnel *)t forward:(PortForward *)pf;
- (void)stopAllForwards;
@end

/* strdup() is not ANSI C; keep the dependency out of the app. */
static char *dup_cstr(const char *s)
{
    size_t n = strlen(s) + 1;
    char *p = (char *)malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

static BOOL has_method(const char *list, const char *m)
{
    size_t n = strlen(m);
    const char *p = list;
    while (*p) {
        const char *e = strchr(p, ',');
        size_t l = e ? (size_t)(e - p) : strlen(p);
        if (l == n && memcmp(p, m, n) == 0) return YES;
        if (!e) break;
        p = e + 1;
    }
    return NO;
}

static void sftp_ready_thunk(sftp *core, void *ctx) { [(SSHSession *)ctx sftpBecameReady]; }

@implementation SSHSession

- (id)initWithHost:(NSString *)h port:(int)p user:(NSString *)u keyPath:(NSString *)k
    knownHostsPath:(NSString *)kh owner:(id)o
{
    self = [super init];
    if (!self) return nil;
    host = [h copy];
    port = p;
    user = [u copy];
    keyPath = [k copy];
    knownHostsPath = [kh copy];
    owner = o;
    fd = -1;
    channel = -1;
    sftpChannel = -1;
    exitStatus = -1;
    sb_init(&pendingIn);
    forwards = [[NSMutableArray alloc] init];
    return self;
}

- (void)dealloc
{
    [self shutdown];
    ssh_key_wipe(&key);
    sb_free(&pendingIn);
    [host release]; [user release]; [keyPath release]; [knownHostsPath release];
    [window release]; [termView release]; [scroller release]; [browser release];
    [forwards release]; [forwardController release];
    [super dealloc];
}

- (NSWindow *)window { return window; }
- (BOOL)isActive { return state != SESS_ENDED && state != 0; }

/* ---------------------------------------------------------------- */
/* window                                                           */

- (void)buildWindow
{
    static float offset = 0.0;
    NSSize cs;
    float sw = [NSScroller scrollerWidth];
    NSRect content;
    NSView *container;
    NSRect scr = [[NSScreen mainScreen] frame];

    termView = [[TerminalView alloc] initWithFrame:NSMakeRect(0, 0, 100, 100)];
    cs = [termView contentSizeForCols:80 rows:24];
    content = NSMakeRect(0, 0, cs.width + sw, cs.height);

    window = [[NSWindow alloc] initWithContentRect:content
                                         styleMask:(NSTitledWindowMask | NSClosableWindowMask |
                                                    NSMiniaturizableWindowMask | NSResizableWindowMask)
                                           backing:NSBackingStoreBuffered
                                             defer:NO];
    [window setReleasedWhenClosed:NO];
    [window setDelegate:(id)self];
    [window setMinSize:NSMakeSize(200, 100)];
    if ([window respondsToSelector:@selector(setResizeIncrements:)])      /* snap to whole cells */
        [window setResizeIncrements:NSMakeSize(1, 1)];

    container = [[NSView alloc] initWithFrame:content];
    [termView setFrame:NSMakeRect(0, 0, cs.width, cs.height)];
    [termView setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];
    scroller = [[NSScroller alloc] initWithFrame:NSMakeRect(cs.width, 0, sw, cs.height)];
    [scroller setAutoresizingMask:(NSViewHeightSizable | NSViewMinXMargin)];
    [container addSubview:termView];
    [container addSubview:scroller];
    [window setContentView:container];
    [container release];

    [termView setDelegate:self];
    [termView setScroller:scroller];
    [window setTitle:[NSString stringWithFormat:@"%@@%@", user, host]];
    [window setFrameTopLeftPoint:NSMakePoint(scr.origin.x + 60 + offset,
                                             NSMaxY(scr) - 40 - offset)];
    offset += 24.0;
    if (offset > 240.0) offset = 0.0;
    [window makeKeyAndOrderFront:nil];
    [window makeFirstResponder:termView];
}

- (void)status:(NSString *)msg
{
    NSString *line = [NSString stringWithFormat:@"\r\n[%@]\r\n", msg];
    const char *c = [line cString];
    [termView writeBytes:(const unsigned char *)c length:(int)strlen(c)];
}

- (void)refreshTitle
{
    vt *t = [termView terminal];
    if (t->title_changed) {
        t->title_changed = 0;
        [window setTitle:[NSString stringWithFormat:@"%@@%@ - %@", user, host,
                                                    [NSString stringWithCString:t->title]]];
    }
}

/* ---------------------------------------------------------------- */
/* connecting                                                       */

- (void)start
{
    [self buildWindow];
    [self loadKey];
    ssh = ssh_new([user cString]);
    if (!ssh) { [self endWithMessage:@"out of memory"]; return; }
    timer = [[NSTimer scheduledTimerWithTimeInterval:TICK_SECONDS target:self
                                            selector:@selector(tick:) userInfo:nil repeats:YES] retain];
    [self beginConnect];
}

- (void)loadKey
{
    NSData *data;
    const char *err = "";
    char *pass;
    int rc, attempt;

    if (!keyPath || [keyPath length] == 0) return;
    data = [NSData dataWithContentsOfFile:[keyPath stringByExpandingTildeInPath]];
    if (!data) {
        [self status:[NSString stringWithFormat:@"Cannot read key file %@", keyPath]];
        return;
    }
    rc = ssh_key_parse_private((const char *)[data bytes], [data length], NULL, &key, &err);
    for (attempt = 0; rc == -2 || rc == -3; attempt++) {              /* -2: needs a passphrase, -3: wrong one */
        if (attempt >= 3) { [self status:@"Three wrong passphrases; not using this key."]; return; }
        pass = [PromptPanel askSecret:[NSString stringWithFormat:@"%@Passphrase for key %@:",
                                       attempt ? @"Incorrect. Try again. " : @"", keyPath]
                                title:@"Secure Shell"];
        if (!pass) { [self status:@"No passphrase given; not using this key."]; return; }
        /* bcrypt-pbkdf is deliberately slow: seconds on an old CPU.  Say so before the window freezes. */
        [self status:@"Unlocking key (this can take several seconds on a slow machine) ..."];
        [window displayIfNeeded];
        rc = ssh_key_parse_private((const char *)[data bytes], [data length], pass, &key, &err);
        memset(pass, 0, strlen(pass));
        free(pass);
    }
    if (rc == 0) haveKey = 1;
    else [self status:[NSString stringWithFormat:@"Key %@ not usable: %s", keyPath, err]];
}

- (void)beginConnect
{
    struct sockaddr_in sa;
    unsigned long addr;
    struct hostent *he;
    const char *h = [host cString];
    int flags, rc;

    state = SESS_CONNECTING;
    [self status:[NSString stringWithFormat:@"Connecting to %@ port %d ...", host, port]];
    [window displayIfNeeded];                                         /* show it before we may block in DNS */

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    addr = inet_addr(h);
    if (addr != INADDR_NONE) {
        sa.sin_addr.s_addr = addr;
    } else {
        he = gethostbyname(h);                                        /* IPv4 only; may block briefly */
        if (!he || he->h_addrtype != AF_INET || he->h_length != 4) {
            [self endWithMessage:[NSString stringWithFormat:@"Cannot resolve host name '%@'", host]];
            return;
        }
        memcpy(&sa.sin_addr, he->h_addr, 4);
    }
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { [self endWithMessage:@"Cannot create socket"]; return; }
    flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    connectDeadline = ticks + CONNECT_TIMEOUT * TICKS_PER_SEC;
    rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    if (rc == 0) [self connected];
    else if (errno != EINPROGRESS) {
        [self endWithMessage:[NSString stringWithFormat:@"Connection failed: %s", strerror(errno)]];
    }
}

- (void)connected
{
    if (!ssh_rng_ready()) {
        [self endWithMessage:@"Not enough random data to start a secure session"];
        return;
    }
    state = SESS_HANDSHAKE;
    keepaliveAt = ticks + KEEPALIVE_SECS * TICKS_PER_SEC;
    [self status:@"Connected. Negotiating ..."];
    if (ssh_start(ssh) < 0) { [self processEvents]; return; }
    [self flushOutput];
}

/* ---------------------------------------------------------------- */
/* the poll loop                                                    */

- (void)tick:(NSTimer *)t
{
    if (inTick || state == SESS_ENDED) return;
    inTick = 1;
    ticks++;

    if (state == SESS_CONNECTING && fd >= 0) {
        fd_set wf;
        struct timeval tv;
        int err = 0;
        sock_len_t len = sizeof(err);
        FD_ZERO(&wf);
        FD_SET(fd, &wf);
        tv.tv_sec = 0; tv.tv_usec = 0;
        if (select(fd + 1, NULL, &wf, NULL, &tv) > 0) {
            getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&err, &len);
            if (err) [self endWithMessage:[NSString stringWithFormat:@"Connection failed: %s", strerror(err)]];
            else [self connected];
        } else if ((int)(ticks - connectDeadline) > 0) {
            [self endWithMessage:@"Connection timed out"];
        }
    } else if (state >= SESS_HANDSHAKE && state < SESS_ENDED) {
        [self pump];
        if (state == SESS_ACTIVE && (int)(ticks - keepaliveAt) > 0) {   /* keep NAT/firewall state alive */
            ssh_send_ignore(ssh);
            [self flushOutput];
            keepaliveAt = ticks + KEEPALIVE_SECS * TICKS_PER_SEC;
        }
    }
    inTick = 0;
}

- (void)pump
{
    unsigned char buf[16384];
    int i;
    int n;

    [self flushOutput];
    for (i = 0; i < 8 && state != SESS_ENDED; i++) {
        n = recv(fd, (char *)buf, sizeof(buf), 0);
        if (n > 0) {
            ssh_rng_add_timing(0);
            ssh_input(ssh, buf, (size_t)n);
            [self processEvents];
            [self flushOutput];
        } else if (n == 0) {
            if (state != SESS_ENDED) [self endWithMessage:@"Connection closed by remote host"];
            return;
        } else if (errno == EWOULDBLOCK || errno == EINTR) {
            break;
        } else {
            [self endWithMessage:[NSString stringWithFormat:@"Network error: %s", strerror(errno)]];
            return;
        }
    }
    if (state != SESS_ENDED) { [self flushPending]; [self flushSFTP]; [self pumpForwards]; }
    [self refreshTitle];
}

- (void)flushOutput
{
    const u8 *p;
    size_t len;
    int w;
    if (!ssh || fd < 0) return;
    p = ssh_output(ssh, &len);
    while (len) {
        w = send(fd, (char *)p, len, 0);            /* OPENSTEP's prototype takes char *, not const */
        if (w > 0) {
            ssh_output_done(ssh, (size_t)w);
            p = ssh_output(ssh, &len);
        } else if (w < 0 && (errno == EWOULDBLOCK || errno == EINTR)) {
            return;                                                   /* try again next tick */
        } else {
            [self endWithMessage:[NSString stringWithFormat:@"Network error: %s", strerror(errno)]];
            return;
        }
    }
}

- (void)flushPending
{
    int w;
    if (state != SESS_ACTIVE || channel < 0 || pendingIn.len == 0) return;
    w = ssh_channel_write(ssh, channel, pendingIn.p, pendingIn.len);
    if (w > 0) sb_consume(&pendingIn, (size_t)w);
    [self flushOutput];
}

/* ---------------------------------------------------------------- */
/* protocol events                                                  */

- (void)processEvents
{
    ssh_event ev;
    while (state != SESS_ENDED && ssh_next_event(ssh, &ev)) {
        {
            PortTunnel *t; PortForward *pf;
            if ([self findTunnelForChannel:ev.channel tunnel:&t forward:&pf]) {
                [self handleForwardEvent:&ev tunnel:t forward:pf];
                continue;
            }
        }
        if (sftpChannel >= 0 && ev.channel == sftpChannel &&
            (ev.type == SSH_EV_CHAN_OPEN || ev.type == SSH_EV_CHAN_OPEN_FAILED || ev.type == SSH_EV_CHAN_SUCCESS ||
             ev.type == SSH_EV_CHAN_FAILURE || ev.type == SSH_EV_CHAN_DATA || ev.type == SSH_EV_CHAN_EOF ||
             ev.type == SSH_EV_CHAN_CLOSE || ev.type == SSH_EV_CHAN_EXIT)) {
            [self handleSFTPEvent:&ev];                               /* the file-browser channel, not the shell */
            continue;
        }
        switch (ev.type) {
        case SSH_EV_HOSTKEY:
            [self handleHostKey:&ev];
            break;
        case SSH_EV_BANNER:
            [termView writeBytes:(const unsigned char *)ev.text length:(int)strlen(ev.text)];
            break;
        case SSH_EV_AUTH_NEEDED:
            [self handleAuth:ev.text failed:NO code:0 text:NULL];
            break;
        case SSH_EV_AUTH_FAILED:
            [self handleAuth:ev.text failed:YES code:ev.code text:ev.text];
            break;
        case SSH_EV_KBDINT:
            [self handleKbdInt];
            break;
        case SSH_EV_AUTH_OK:
            state = SESS_ACTIVE;
            channel = ssh_channel_open_session(ssh);
            if (channel < 0) [self endWithMessage:@"Cannot open a session channel"];
            else if (openBrowserOnLogin) [self openFileBrowser];
            break;
        case SSH_EV_CHAN_OPEN: {
            vt *t = [termView terminal];
            ssh_channel_request_pty(ssh, channel, "xterm", t->cols, t->rows, 0, 0);
            ssh_channel_request_shell(ssh, channel);
            [window makeFirstResponder:termView];
            break;
        }
        case SSH_EV_CHAN_OPEN_FAILED:
            [self endWithMessage:[NSString stringWithFormat:@"Server refused the session: %s", ev.text]];
            break;
        case SSH_EV_CHAN_FAILURE:
            break;                                                    /* e.g. an optional request was declined */
        case SSH_EV_CHAN_DATA:
            [termView writeBytes:ev.data length:(int)ev.len];
            break;
        case SSH_EV_CHAN_EXIT:
            exitStatus = ev.code;
            break;
        case SSH_EV_CHAN_CLOSE:
            if (exitStatus >= 0)
                [self endWithMessage:[NSString stringWithFormat:@"Connection closed (exit status %d)", exitStatus]];
            else
                [self endWithMessage:@"Connection closed"];
            break;
        case SSH_EV_DISCONNECT:
            [self endWithMessage:[NSString stringWithFormat:@"Server disconnected: %s", ev.text]];
            break;
        case SSH_EV_ERROR:
            [self endWithMessage:[NSString stringWithFormat:@"Error: %s", ev.text]];
            break;
        default:
            break;
        }
    }
}

- (void)handleHostKey:(ssh_event *)ev
{
    NSString *fp = [NSString stringWithCString:ev->text];
    NSString *type = [NSString stringWithCString:ev->text2];
    int r = kh_check([knownHostsPath cString], [host cString], port, ev->data, ev->len);
    int ans;

    if (r == KH_MATCH) { ssh_hostkey_accept(ssh, 1); return; }

    if (r == KH_UNKNOWN) {
        ans = NSRunAlertPanel(@"Unknown host",
            @"The authenticity of host '%@' can't be established.\n\nThe %@ key fingerprint is:\n%@\n\n\
If you trust this host, connect to remember its key.",
            @"Connect", @"Cancel", nil, host, type, fp);
        if (ans == NSAlertDefaultReturn) {
            kh_add([knownHostsPath cString], [host cString], port, ev->data, ev->len);
            ssh_hostkey_accept(ssh, 1);
        } else {
            ssh_hostkey_accept(ssh, 0);
        }
        return;
    }

    /* KH_CHANGED: the safe answer is the default button. */
    ans = NSRunAlertPanel(@"WARNING: HOST KEY HAS CHANGED",
        @"The %@ key for '%@' is different from the one saved in %@.\n\n\
Someone may be eavesdropping on this connection, or the host's key was legitimately replaced.\n\n\
New fingerprint:\n%@",
        @"Cancel", @"Connect Once", nil, type, host, knownHostsPath, fp);
    ssh_hostkey_accept(ssh, ans == NSAlertAlternateReturn ? 1 : 0);
}

- (void)handleAuth:(const char *)methods failed:(BOOL)failed code:(int)code text:(const char *)text
{
    char *pw;
    NSString *prompt;

    if (failed) {
        if (code == 2) [self status:[NSString stringWithFormat:@"Server wants a new password: %s", text]];
        else [self status:@"Authentication failed."];
    }

    if (haveKey && !triedKey && has_method(methods, "publickey")) {
        triedKey = 1;
        [self status:@"Trying public key ..."];
        ssh_auth_publickey(ssh, &key);
        return;
    }
    if (has_method(methods, "password") && passwordTries < 3) {
        prompt = [NSString stringWithFormat:@"%@%@@%@'s password:",
                  passwordTries ? @"Try again. " : @"", user, host];
        pw = [PromptPanel askSecret:prompt title:@"Secure Shell"];
        if (!pw) { [self endWithMessage:@"Authentication cancelled"]; return; }
        passwordTries++;
        ssh_auth_password(ssh, pw);
        memset(pw, 0, strlen(pw));
        free(pw);
        return;
    }
    if (has_method(methods, "keyboard-interactive") && kbdTries < 3) {
        kbdTries++;
        ssh_auth_kbdint_start(ssh);
        return;
    }
    {
        NSString *why = @"";
        if (has_method(methods, "publickey") && !haveKey)
            why = @"\nThis server accepts a public key, and no usable key was loaded. Choose a private key file \
(ed25519, RSA or ECDSA) in the New Connection panel, or use Generate Key in the Connection menu.";
        else if (triedKey)
            why = @"\nThe server rejected the key: its public half must be listed in the server's authorized_keys.";
        [self endWithMessage:[NSString stringWithFormat:@"Permission denied (server accepts: %s)%@", methods, why]];
    }
}

- (void)handleKbdInt
{
    int i, n = ssh_kbdint_count(ssh), echo, ok = 1;
    char **answers = (char **)calloc((size_t)(n ? n : 1), sizeof(char *));
    NSString *heading = [NSString stringWithCString:ssh_kbdint_instruction(ssh)];

    for (i = 0; i < n && ok; i++) {
        NSString *p = [NSString stringWithCString:ssh_kbdint_prompt(ssh, i, &echo)];
        if ([heading length]) p = [NSString stringWithFormat:@"%@\n%@", heading, p];
        if (echo) {
            NSString *t = [PromptPanel askText:p title:@"Secure Shell"];
            if (t) answers[i] = dup_cstr([t cString]); else ok = 0;
        } else {
            answers[i] = [PromptPanel askSecret:p title:@"Secure Shell"];
            if (!answers[i]) ok = 0;
        }
        heading = @"";
    }
    if (ok) {
        ssh_auth_kbdint_respond(ssh, (const char **)answers, n);
    } else {
        [self endWithMessage:@"Authentication cancelled"];
    }
    for (i = 0; i < n; i++) if (answers[i]) { memset(answers[i], 0, strlen(answers[i])); free(answers[i]); }
    free(answers);
}

/* ---------------------------------------------------------------- */
/* teardown                                                         */

- (void)endWithMessage:(NSString *)msg
{
    if (state == SESS_ENDED) return;
    state = SESS_ENDED;
    [self status:msg];
    [timer invalidate];
    [timer release];
    timer = nil;
    [self sftpEnded:msg];
    [self stopAllForwards];
    if (fd >= 0) { close(fd); fd = -1; }
    if (ssh) { ssh_free(ssh); ssh = NULL; }
    channel = -1;
    sftpChannel = -1;
    [window setTitle:[NSString stringWithFormat:@"%@@%@ (closed)", user, host]];
    if (ssh_rng_ready()) {                                            /* refresh the seed file for next launch */
        NSString *seed = [[knownHostsPath stringByDeletingLastPathComponent]
                              stringByAppendingPathComponent:@"random_seed"];
        ssh_rng_save_seed([seed cString]);
    }
}

- (void)shutdown
{
    [self sftpEnded:@"closed"];
    [self stopAllForwards];
    if (browser) { [browser closeWindow]; }
    if (ssh && state != SESS_ENDED) ssh_disconnect(ssh, "user closed the window");
    if (ssh) [self flushOutput];
    state = SESS_ENDED;
    [timer invalidate];
    [timer release];
    timer = nil;
    if (fd >= 0) { close(fd); fd = -1; }
    if (ssh) { ssh_free(ssh); ssh = NULL; }
}

/* ---------------------------------------------------------------- */
/* file browser (SFTP on a second channel)                          */

- (void)setOpensBrowserOnLogin:(BOOL)flag { openBrowserOnLogin = flag ? 1 : 0; }
- (SFTPBrowser *)fileBrowser { return browser; }
- (sftp *)sftpCore { return sftpCore; }

- (void)openFileBrowser
{
    if (state != SESS_ACTIVE || !ssh) {
        NSRunAlertPanel(@"File browser", @"Log in first; the file browser uses this connection.", @"OK", nil, nil);
        return;
    }
    if (browser) { [browser show]; return; }
    if (sftpChannel >= 0) {                                           /* previous browser's channel is still closing */
        NSRunAlertPanel(@"File browser", @"The previous file browser is still closing. Try again in a moment.", @"OK", nil, nil);
        return;
    }
    browser = [[SFTPBrowser alloc] initWithSession:self host:host user:user];
    [browser show];
    [browser setStatus:@"Opening the file transfer channel ..."];
    sftpChannel = ssh_channel_open_session(ssh);
    if (sftpChannel < 0) {
        [browser sftpFailed:@"Cannot open another channel on this connection."];
    }
    [self flushOutput];
}

- (void)sftpBecameReady { [browser sftpReady]; }

- (void)handleSFTPEvent:(ssh_event *)ev
{
    switch (ev->type) {
    case SSH_EV_CHAN_OPEN:
        ssh_channel_request_subsystem(ssh, sftpChannel, "sftp");
        break;
    case SSH_EV_CHAN_OPEN_FAILED:
        sftpChannel = -1;
        [browser sftpFailed:[NSString stringWithFormat:@"The server refused the channel: %s", ev->text]];
        break;
    case SSH_EV_CHAN_FAILURE:
        [browser sftpFailed:@"This server does not offer SFTP."];
        [self closeSFTPChannel];
        break;
    case SSH_EV_CHAN_SUCCESS:
        if (!sftpCore) {
            sftpCore = sftp_new();
            if (!sftpCore || sftp_start(sftpCore, sftp_ready_thunk, self) != 0) [browser sftpFailed:@"Cannot start SFTP."];
            [self flushSFTP];
        }
        break;
    case SSH_EV_CHAN_DATA:
        if (sftpCore && !sftpClosing) {
            if (sftp_input(sftpCore, ev->data, ev->len) < 0) {
                NSString *why = [NSString stringWithFormat:@"SFTP error: %s", sftp_error(sftpCore)];
                [self closeSFTPChannel];
                [browser sftpFailed:why];
            } else {
                [self flushSFTP];
            }
        }
        break;
    case SSH_EV_CHAN_EOF:
        break;
    case SSH_EV_CHAN_CLOSE:                                          /* the channel is gone: forget its id */
        sftpChannel = -1;
        sftpClosing = 0;
        if (sftpCore) { sftp_abort(sftpCore, "file transfer channel closed"); sftp_free(sftpCore); sftpCore = NULL; }
        [browser sessionEnded];
        break;
    default:
        break;
    }
}

/* Push the SFTP engine's pending bytes into the channel, then out on the socket. */
- (void)flushSFTP
{
    size_t n;
    const u8 *p;
    int w;
    if (!sftpCore || sftpChannel < 0 || !ssh || sftpClosing) return;
    for (;;) {
        p = sftp_output(sftpCore, &n);
        if (!n) break;
        w = ssh_channel_write(ssh, sftpChannel, p, n);
        if (w <= 0) break;
        sftp_output_done(sftpCore, (size_t)w);
    }
    [self flushOutput];
}

- (void)sftpKick { [self flushSFTP]; }

/* Ask the server to close the channel.  sftpChannel stays set until the CLOSE event
 * arrives, so that event is routed here and not mistaken for the shell closing. */
- (void)closeSFTPChannel
{
    if (sftpChannel < 0 || sftpClosing || !ssh) return;
    sftpClosing = 1;
    if (sftpCore) sftp_abort(sftpCore, "file browser closed");
    ssh_channel_close(ssh, sftpChannel);
    [self flushOutput];
}

- (void)browserClosed:(id)aBrowser
{
    if (aBrowser != browser) return;
    [self closeSFTPChannel];
    [browser autorelease];                                            /* we are inside its windowWillClose: */
    browser = nil;
}

/* The whole connection ended (or is closing): the browser can no longer work. */
- (void)sftpEnded:(NSString *)why
{
    if (sftpCore) { sftp_abort(sftpCore, why ? [why cString] : "connection closed"); sftp_free(sftpCore); sftpCore = NULL; }
    [browser sessionEnded];
}

/* ---------------------------------------------------------------- */
/* port forwarding ("ssh -L": one direct-tcpip channel per tunneled connection)      */

- (void)openPortForwarding
{
    if (state != SESS_ACTIVE || !ssh) {
        NSRunAlertPanel(@"Port Forwarding", @"Log in first; forwarding uses this connection.", @"OK", nil, nil);
        return;
    }
    if (!forwardController) forwardController = [[PortForwardController alloc] initWithSession:self];
    [forwardController show];
}

- (PortForwardController *)portForwardController { return forwardController; }
- (NSArray *)portForwards { return forwards; }

- (PortForward *)addForwardWithLocalPort:(int)lp remoteHost:(NSString *)rh remotePort:(int)rp
{
    PortForward *pf;
    if (state != SESS_ACTIVE || !ssh) return nil;
    pf = [[[PortForward alloc] initWithLocalPort:lp remoteHost:rh remotePort:rp] autorelease];
    if (![pf startListening]) return nil;
    [forwards addObject:pf];
    return pf;
}

- (void)removeForward:(PortForward *)pf
{
    [pf stopListening];                        /* also closes every tunnel's local socket right away */
    [forwards removeObject:pf];
}

- (void)portForwardControllerClosed:(id)pfc
{
    if (pfc != forwardController) return;
    [forwardController autorelease];                                  /* we are inside its windowWillClose: */
    forwardController = nil;
}

/* One tick's worth of plain-socket I/O for every forward: accept new connections, relay bytes each
 * way.  Data already received on a channel (SSH_EV_CHAN_DATA, handled in handleForwardEvent:) is
 * buffered in outToLocal and flushed here rather than in the event handler, so a local socket that
 * cannot take it all right away is retried on the next tick instead of blocking. */
- (void)pumpForwards
{
    int fi, ti;
    if (state != SESS_ACTIVE || !ssh) return;
    for (fi = 0; fi < (int)[forwards count]; fi++) {
        PortForward *pf = [forwards objectAtIndex:fi];
        if (pf->listenFD >= 0) {
            struct sockaddr_in a;
            sock_len_t alen = sizeof(a);
            int nfd = accept(pf->listenFD, (struct sockaddr *)&a, &alen);
            if (nfd >= 0) {
                int flags = fcntl(nfd, F_GETFL, 0);
                PortTunnel *t = [[[PortTunnel alloc] init] autorelease];
                fcntl(nfd, F_SETFL, flags | O_NONBLOCK);
                t->localFD = nfd;
                t->channel = ssh_channel_open_direct_tcpip(ssh, [pf->remoteHost cString], pf->remotePort,
                                                            "127.0.0.1", pf->localPort);
                if (t->channel < 0) close(nfd);
                else [pf->tunnels addObject:t];
            }
        }
        for (ti = 0; ti < (int)[pf->tunnels count]; ti++) {
            PortTunnel *t = [pf->tunnels objectAtIndex:ti];
            unsigned char buf[16384];
            int n;

            if (t->outToLocal.len) {
                int w = send(t->localFD, (char *)t->outToLocal.p, t->outToLocal.len, 0);
                if (w > 0) sb_consume(&t->outToLocal, (size_t)w);
                else if (w < 0 && errno != EWOULDBLOCK && errno != EINTR) t->localClosed = t->remoteClosed = YES;
            }
            if (t->channelOpen && !t->localClosed && t->outToLocal.len == 0) {
                n = recv(t->localFD, (char *)buf, sizeof(buf), 0);
                if (n > 0) {
                    ssh_channel_write(ssh, t->channel, buf, (size_t)n);
                } else if (n == 0) {
                    ssh_channel_eof(ssh, t->channel);
                    t->localClosed = YES;
                } else if (errno != EWOULDBLOCK && errno != EINTR) {
                    t->localClosed = YES;
                    if (t->channel >= 0) ssh_channel_close(ssh, t->channel);
                }
            }
            if (t->localClosed && t->remoteClosed && t->outToLocal.len == 0) {
                if (t->channel >= 0) { ssh_channel_close(ssh, t->channel); t->channel = -1; }
                if (t->localFD >= 0) { close(t->localFD); t->localFD = -1; }
                [pf->tunnels removeObjectAtIndex:ti];
                ti--;
            }
        }
    }
    [self flushOutput];
    if (forwardController) [forwardController reload];                 /* connection counts may have changed */
}

- (BOOL)findTunnelForChannel:(int)ch tunnel:(PortTunnel **)outT forward:(PortForward **)outPF
{
    int fi, ti;
    if (ch < 0) return NO;
    for (fi = 0; fi < (int)[forwards count]; fi++) {
        PortForward *pf = [forwards objectAtIndex:fi];
        for (ti = 0; ti < (int)[pf->tunnels count]; ti++) {
            PortTunnel *t = [pf->tunnels objectAtIndex:ti];
            if (t->channel == ch) { *outT = t; *outPF = pf; return YES; }
        }
    }
    return NO;
}

- (void)handleForwardEvent:(ssh_event *)ev tunnel:(PortTunnel *)t forward:(PortForward *)pf
{
    switch (ev->type) {
    case SSH_EV_CHAN_OPEN:
        t->channelOpen = YES;
        break;
    case SSH_EV_CHAN_OPEN_FAILED:                                       /* the server could not reach host:port */
        t->channel = -1;
        if (t->localFD >= 0) { close(t->localFD); t->localFD = -1; }
        [pf->tunnels removeObject:t];
        break;
    case SSH_EV_CHAN_DATA:
        sb_put(&t->outToLocal, ev->data, ev->len);                      /* flushed to the socket in pumpForwards */
        break;
    case SSH_EV_CHAN_EOF:
        t->remoteClosed = YES;
        break;
    case SSH_EV_CHAN_CLOSE:
        t->channel = -1;
        if (t->localFD >= 0) { close(t->localFD); t->localFD = -1; }
        [pf->tunnels removeObject:t];
        break;
    default:
        break;
    }
}

- (void)stopAllForwards
{
    int i;
    for (i = 0; i < (int)[forwards count]; i++) [[forwards objectAtIndex:i] stopListening];
    [forwards removeAllObjects];
    if (forwardController) { [forwardController closeWindow]; }
}

/* ---------------------------------------------------------------- */
/* TerminalView delegate                                            */

- (void)terminalView:(id)tv sendBytes:(const unsigned char *)bytes length:(int)n
{
    if (state != SESS_ACTIVE || channel < 0) return;
    sb_put(&pendingIn, bytes, (size_t)n);
    [self flushPending];
}

- (void)terminalView:(id)tv resizedToCols:(int)c rows:(int)r
{
    if (state == SESS_ACTIVE && channel >= 0 && ssh) {
        ssh_channel_window_change(ssh, channel, c, r, 0, 0);
        [self flushOutput];
    }
}

/* ---------------------------------------------------------------- */
/* window delegate                                                  */

- (BOOL)windowShouldClose:(id)sender
{
    int ans;
    if (state != SESS_ACTIVE) return YES;
    ans = NSRunAlertPanel(@"Close connection?",
                          @"The session to %@ is still open. Closing the window will disconnect it.",
                          @"Disconnect", @"Cancel", nil, host);
    return ans == NSAlertDefaultReturn;
}

- (void)windowWillClose:(NSNotification *)notification
{
    [self shutdown];
    [window setDelegate:nil];
    [owner sessionDidEnd:self];
}

- (void)windowDidResize:(NSNotification *)notification
{
    [termView fitToFrame];
}

@end
