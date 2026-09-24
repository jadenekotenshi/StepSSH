/*
 * x11_smoke.m -- drives the real SSHSession's X11 forwarding against a real local sshd
 * (X11Forwarding yes) and real Xvfb X servers on the development Mac. This is the strongest
 * check the whole feature gets: a real X11 client (xdpyinfo) run through a real sshd's own X11
 * forwarding, relayed by this project's code, into a real X server that only succeeds if the
 * cookie substitution was byte-correct -- a real X server refusing a wrong cookie is proof this
 * isn't just "the bytes looked right," the same way test_ssh_x11.c's synthetic vectors could not
 * prove on their own.
 *
 * usage: x11_smoke <port> <user> <keyfile> <known_hosts> <cookie-hex> <auth-display-port> <open-display-port>
 *   <auth-display-port> is a real Xvfb requiring the given cookie (MIT-MAGIC-COOKIE-1).
 *   <open-display-port> is a real Xvfb requiring no authentication at all.
 */
#import "Compat.h"
#import "SSHSession.h"
#import "TerminalView.h"
#include <stdio.h>
#include <stdlib.h>
#include "rng.h"

void PSmoveto(float x, float y) { }
void PSshow(const char *s) { }
@implementation NSFont (OpenStepHostStub)
- (float)widthOfString:(NSString *)s { return [self maximumAdvancement].width; }
@end

@interface Owner : NSObject { int ended; } - (int)ended; @end
@implementation Owner
- (void)sessionDidEnd:(SSHSession *)s { ended = 1; }
- (int)ended { return ended; }
@end

static TerminalView *find_terminal(NSWindow *w)
{
    NSEnumerator *e = [[[w contentView] subviews] objectEnumerator];
    id v;
    while ((v = [e nextObject])) if ([v isKindOfClass:[TerminalView class]]) return v;
    return nil;
}

static NSString *screen_text(TerminalView *tv)
{
    [tv selectAll:nil];
    return [tv selectedText];
}

static void spin(double seconds)
{
    [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:seconds]];
}

static int wait_for(TerminalView *tv, NSString *needle, double timeout)
{
    double waited = 0;
    while (waited < timeout) {
        if ([screen_text(tv) rangeOfString:needle].length > 0) return 1;
        spin(0.05);
        waited += 0.05;
    }
    return 0;
}

static void wait_active(SSHSession *s, double timeout)
{
    double w = 0;
    while (![s isActive] && w < timeout) { spin(0.05); w += 0.05; }
}

static int pass, fail;
#define EXPECT(cond, what) do { if (cond) { pass++; printf("  ok   %s\n", what); } else { fail++; printf("  FAIL %s\n", what); } } while (0)

/* Connects a fresh session with X11 forwarding enabled, points it at one Xvfb, and runs xdpyinfo
 * through the real shell. `wantSuccess` says whether that command is expected to actually reach
 * a real X server (a wrong cookie must NOT succeed, but must also not take the session down). */
static void run_x11_case(int port, const char *user, const char *keyfile, const char *knownHosts,
                          int displayPort, NSString *cookieHex, BOOL wantSuccess, const char *label)
{
    Owner *owner = [[Owner alloc] init];
    SSHSession *s = [[SSHSession alloc] initWithHost:@"127.0.0.1" port:port
                                                 user:[NSString stringWithCString:user]
                                              keyPath:[NSString stringWithCString:keyfile]
                                       knownHostsPath:[NSString stringWithCString:knownHosts]
                                                owner:owner];
    TerminalView *tv;
    char msg[256];

    [s setX11Enabled:YES displayHost:@"127.0.0.1" displayPort:displayPort cookieHex:cookieHex];
    [s start];
    tv = find_terminal([s window]);
    sprintf(msg, "%s: session builds a window", label);
    EXPECT(tv != nil, msg);
    if (!tv) { [s release]; [owner release]; return; }

    sprintf(msg, "%s: authenticates", label);
    EXPECT(wait_for(tv, @"Trying public key", 10), msg);
    wait_active(s, 5);
    spin(0.5);

    /* "GOT_$DISPLAY" (typed, unevaluated) must not literally match "GOT_localhost" (the searched
     * text) the way plain "DISPLAY=" would match the echoed keystrokes of "echo DISPLAY=$DISPLAY"
     * before the shell ever evaluates it -- same evaluation trick run_x11_case's own "still alive"
     * check below and session_smoke.m's "SMOKE_$((6*7))" already use, needed here for the same
     * reason: a premature match sends the next command before this one has actually finished,
     * racing the rest of the sequence. */
    [s terminalView:tv sendBytes:(const unsigned char *)"echo GOT_$DISPLAY\r" length:18];
    sprintf(msg, "%s: sshd exported a real DISPLAY for the session", label);
    EXPECT(wait_for(tv, @"GOT_localhost", 10), msg);

    [s terminalView:tv sendBytes:(const unsigned char *)"/opt/X11/bin/xdpyinfo | head -1\r" length:33];
    if (wantSuccess) {
        sprintf(msg, "%s: xdpyinfo reaches the real X server through the forward", label);
        EXPECT(wait_for(tv, @"name of display", 10), msg);
    } else {
        sprintf(msg, "%s: xdpyinfo is correctly refused (wrong cookie)", label);
        EXPECT(wait_for(tv, @"unable to open display", 10), msg);
    }

    /* the session itself must survive regardless: a wrong REAL cookie is not core/x11.c's own
     * X11_BAD path (that's for the incoming ConnectionSetup not matching what WE advertised via
     * x11-req -- a different, hostile-channel scenario, unit-tested directly in test_x11.c) --
     * here the substituted cookie reaches the real X server just fine, wire-correctly, and IT is
     * the one that refuses it. The proof this case actually wants is that our own relay carries
     * that real rejection back without wedging the x11 channel's own teardown or touching the
     * rest of the session. */
    [s terminalView:tv sendBytes:(const unsigned char *)"echo STILL_ALIVE_$((6*7))\r" length:26];
    sprintf(msg, "%s: the session keeps working afterward", label);
    EXPECT(wait_for(tv, @"STILL_ALIVE_42", 10), msg);

    [s terminalView:tv sendBytes:(const unsigned char *)"exit\r" length:5];
    wait_for(tv, @"Connection closed", 10);
    [[s window] close];
    spin(0.2);
    [s release];
    [owner release];
}

int main(int argc, char *argv[])
{
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    int port, authPort, openPort;
    NSString *cookie, *wrongCookie;

    if (argc < 8) {
        fprintf(stderr, "usage: x11_smoke port user keyfile known_hosts cookie-hex auth-display-port open-display-port\n");
        return 2;
    }
    ssh_rng_seed_system();
    [NSApplication sharedApplication];

    port = atoi(argv[1]);
    cookie = [NSString stringWithCString:argv[5]];
    authPort = atoi(argv[6]);
    openPort = atoi(argv[7]);

    /* 1: the real cookie -- must reach the real, authenticated Xvfb */
    run_x11_case(port, argv[2], argv[3], argv[4], authPort, cookie, YES, "real cookie");

    /* 2: a deliberately wrong cookie against the SAME authenticated Xvfb -- must be refused, and
     * must not disturb the rest of the session (core/x11.c's X11_BAD path, live). Flipping the
     * cookie's own first hex digit to something else is a simple, guaranteed-different, still
     * validly-formatted 32-hex-char value. */
    {
        NSString *first = [cookie substringToIndex:1];
        NSString *flipped = [first isEqualToString:@"a"] ? @"b" : @"a";
        wrongCookie = [flipped stringByAppendingString:[cookie substringFromIndex:1]];
    }
    run_x11_case(port, argv[2], argv[3], argv[4], authPort, wrongCookie, NO, "wrong cookie");

    /* 3: no cookie configured at all -- the empty-auth rewrite path, against a real Xvfb that
     * itself requires no authentication (confirmed set up that way by the shell script) */
    run_x11_case(port, argv[2], argv[3], argv[4], openPort, @"", YES, "no cookie, open display");

    printf("x11 smoke: %d passed, %d failed\n", pass, fail);
    [pool release];
    return fail ? 1 : 0;
}
