/*
 * session_smoke.m -- drives the real SSHSession (socket, poll loop, auth, PTY, terminal
 * view) against a local OpenSSH server on the development Mac.
 * usage: session_smoke <port> <user> <keyfile> <known_hosts>
 * A window is created (it is what SSHSession builds); the host key is pre-trusted so
 * no modal alert can block the test.
 */
#import "Compat.h"
#import "SSHSession.h"
#import "TerminalView.h"
#import "SFTPBrowser.h"
#import "DebugLogController.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include "rng.h"
#include "PortForward.h"

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

/* Run the loop until the screen contains `needle` or the time is up. */
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

/* Run the loop until the browser has nothing left to do (or time runs out). */
static int wait_idle(SFTPBrowser *b, double timeout)
{
    double waited = 0;
    while (waited < timeout) {
        if ([b isReady] && ![b isBusy]) return 1;
        spin(0.05);
        waited += 0.05;
    }
    return 0;
}

/* Polls a plain (non-blocking) socket for at least one byte, pumping the run loop meanwhile so
 * SSHSession's NSTimer keeps ticking (real time must pass for it to fire, same reason wait_for/
 * wait_idle do this). Returns the byte count (0 = the peer closed, -1 = a real error, -2 = timeout). */
static int wait_for_bytes(int fd, char *buf, int cap, double timeout)
{
    double waited = 0;
    while (waited < timeout) {
        int n = recv(fd, buf, cap - 1, 0);
        if (n > 0) { buf[n] = 0; return n; }
        if (n == 0) return 0;
        if (errno != EWOULDBLOCK && errno != EAGAIN && errno != EINTR) return -1;
        spin(0.05);
        waited += 0.05;
    }
    return -2;
}

static int has_entry(SFTPBrowser *b, NSString *name, BOOL wantDir, unsigned long long wantSize, BOOL checkSize)
{
    int i;
    for (i = 0; i < [b entryCount]; i++) {
        SFTPEntry *e = [b entryAtIndex:i];
        if ([e->name isEqual:name]) return e->isDir == wantDir && (!checkSize || e->size == wantSize);
    }
    return 0;
}

static int pass, fail;
#define EXPECT(cond, what) do { if (cond) { pass++; printf("  ok   %s\n", what); } else { fail++; printf("  FAIL %s\n", what); } } while (0)

int main(int argc, char *argv[])
{
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    Owner *owner = [[Owner alloc] init];
    SSHSession *s;
    TerminalView *tv;
    NSString *text;

    if (argc < 5) { fprintf(stderr, "usage: session_smoke port user keyfile known_hosts\n"); return 2; }
    ssh_rng_seed_system();
    [NSApplication sharedApplication];

    s = [[SSHSession alloc] initWithHost:@"127.0.0.1" port:atoi(argv[1])
                                    user:[NSString stringWithCString:argv[2]]
                                 keyPath:[NSString stringWithCString:argv[3]]
                          knownHostsPath:[NSString stringWithCString:argv[4]]
                                   owner:owner];
    [s start];
    tv = find_terminal([s window]);
    EXPECT(tv != nil, "session built a window with a terminal view");
    if (!tv) return 1;

    EXPECT(wait_for(tv, @"Connected. Negotiating", 5), "non-blocking connect completes");
    EXPECT(wait_for(tv, @"Trying public key", 10), "key exchange finished and public-key auth started");
    /* the shell prompt/motd is unpredictable; once auth succeeds the session becomes active */
    { double w = 0; while (![s isActive] && w < 5) { spin(0.05); w += 0.05; } }
    spin(1.0);

    /* type a command exactly as TerminalView would deliver it */
    [s terminalView:tv sendBytes:(const unsigned char *)"echo SMOKE_$((6*7))\r" length:20];
    EXPECT(wait_for(tv, @"SMOKE_42", 10), "typed command runs on the server and its output reaches the screen");

    /* a big burst of output: exercises flow control, scrollback and the poll loop */
    [s terminalView:tv sendBytes:(const unsigned char *)"seq 1 5000\r" length:11];
    EXPECT(wait_for(tv, @"5000", 15), "5000 lines of output are received");
    EXPECT(vt_scrollback_count([tv terminal]) > 1000, "output went into the scrollback");

    /* resize is forwarded to the server's pty */
    [[s window] setContentSize:NSMakeSize(700, 300)];
    spin(0.5);
    [s terminalView:tv sendBytes:(const unsigned char *)"stty size\r" length:10];
    {
        vt *t = [tv terminal];
        char want[32];
        sprintf(want, "%d %d", t->rows, t->cols);
        EXPECT(wait_for(tv, [NSString stringWithCString:want], 10), "window resize reaches the remote pty (stty size matches)");
    }

    /* ---- file browser over the same connection ---- */
    {
        SFTPBrowser *b;
        NSString *work = argc > 5 ? [NSString stringWithCString:argv[5]] : @"/tmp";
        NSString *dir = [work stringByAppendingPathComponent:@"browse"];
        NSString *big = [work stringByAppendingPathComponent:@"big.bin"];
        NSString *back = [work stringByAppendingPathComponent:@"back.bin"];
        NSMutableData *blob = [NSMutableData dataWithLength:3000000];
        unsigned char *bp = (unsigned char *)[blob mutableBytes];
        int i;
        for (i = 0; i < 3000000; i++) bp[i] = (unsigned char)((i * 7 + (i >> 9)) & 0xff);
        [blob writeToFile:big atomically:NO];

        [s openFileBrowser];
        b = [s fileBrowser];
        EXPECT(b != nil, "opening the browser creates it");
        EXPECT(wait_idle(b, 10), "the SFTP channel opens and the first listing arrives");
        EXPECT([[b currentPath] length] > 0 && [b entryCount] > 0, "the home directory is listed");

        [b queueMkdir:dir];
        EXPECT(wait_idle(b, 10) && [[NSFileManager defaultManager] fileExistsAtPath:dir], "New Folder creates a directory on the server");
        [b goTo:dir];
        EXPECT(wait_idle(b, 10) && [[b currentPath] hasSuffix:@"browse"] && [b entryCount] == 0, "navigating into it lists an empty directory");

        [b queueUploadOfLocal:big toRemote:[dir stringByAppendingPathComponent:@"up.bin"]];
        EXPECT(wait_idle(b, 60), "an upload runs to completion");
        EXPECT([[NSData dataWithContentsOfFile:[dir stringByAppendingPathComponent:@"up.bin"]] isEqualToData:blob],
               "the uploaded 3 MB file is byte-for-byte identical");
        EXPECT(has_entry(b, @"up.bin", NO, 3000000, YES), "the listing refreshes and shows it with the right size");

        [b queueMkdir:[dir stringByAppendingPathComponent:@"zdir"]];
        wait_idle(b, 10);
        EXPECT([[[b entryAtIndex:0] valueForKey:@"name"] isEqual:@"zdir"] || ((SFTPEntry *)[b entryAtIndex:0])->isDir,
               "folders sort before files");

        [b queueDownloadOfRemote:[dir stringByAppendingPathComponent:@"up.bin"] toLocal:back size:3000000];
        EXPECT(wait_idle(b, 60), "a download runs to completion");
        EXPECT([[NSData dataWithContentsOfFile:back] isEqualToData:blob], "the downloaded 3 MB file is byte-for-byte identical");

        [b queueRename:[dir stringByAppendingPathComponent:@"up.bin"] to:[dir stringByAppendingPathComponent:@"renamed.bin"]];

        /* ---- recursive transfer: upload a small local tree, then download it back ---- */
        {
            NSString *upTree = [work stringByAppendingPathComponent:@"walk_up"];
            NSString *upSub = [upTree stringByAppendingPathComponent:@"sub"];
            NSString *upEmpty = [upSub stringByAppendingPathComponent:@"empty"];
            NSString *remoteTree = [dir stringByAppendingPathComponent:@"tree"];
            NSString *remoteSub = [remoteTree stringByAppendingPathComponent:@"sub"];
            NSString *downTree = [work stringByAppendingPathComponent:@"walk_down"];
            NSData *aData = [@"file a, at the top" dataUsingEncoding:NSASCIIStringEncoding];
            NSData *bData = [@"file b, one folder down" dataUsingEncoding:NSASCIIStringEncoding];

            rmdir([upEmpty cString]); rmdir([upSub cString]); rmdir([upTree cString]);   /* a previous failed run */
            mkdir([upTree cString], 0755); mkdir([upSub cString], 0755); mkdir([upEmpty cString], 0755);
            [aData writeToFile:[upTree stringByAppendingPathComponent:@"a.txt"] atomically:NO];
            [bData writeToFile:[upSub stringByAppendingPathComponent:@"b.txt"] atomically:NO];

            [b queueWalkUploadOfLocal:upTree toRemote:remoteTree];
            EXPECT(wait_idle(b, 30), "a recursive upload runs to completion");
            EXPECT([[NSData dataWithContentsOfFile:[remoteTree stringByAppendingPathComponent:@"a.txt"]] isEqualToData:aData],
                   "the top-level file arrived intact");
            EXPECT([[NSData dataWithContentsOfFile:[remoteSub stringByAppendingPathComponent:@"b.txt"]] isEqualToData:bData],
                   "the file one folder down arrived intact");
            {
                BOOL isDir = NO;
                EXPECT([[NSFileManager defaultManager] fileExistsAtPath:[remoteSub stringByAppendingPathComponent:@"empty"]
                                                              isDirectory:&isDir] && isDir,
                       "an empty subdirectory was created too, not just the ones holding files");
            }

            [b queueWalkDownloadOfRemote:remoteTree toLocal:downTree];
            EXPECT(wait_idle(b, 30), "a recursive download runs to completion");
            EXPECT([[NSData dataWithContentsOfFile:[downTree stringByAppendingPathComponent:@"a.txt"]] isEqualToData:aData],
                   "downloaded: the top-level file matches");
            EXPECT([[NSData dataWithContentsOfFile:[[downTree stringByAppendingPathComponent:@"sub"]
                                                      stringByAppendingPathComponent:@"b.txt"]] isEqualToData:bData],
                   "downloaded: the file one folder down matches");
            {
                BOOL isDir = NO;
                EXPECT([[NSFileManager defaultManager] fileExistsAtPath:[[downTree stringByAppendingPathComponent:@"sub"]
                                                                    stringByAppendingPathComponent:@"empty"]
                                                              isDirectory:&isDir] && isDir,
                       "downloaded: the empty subdirectory came back too");
            }

            [b queueRemove:[remoteTree stringByAppendingPathComponent:@"a.txt"] directory:NO];
            [b queueRemove:[remoteSub stringByAppendingPathComponent:@"b.txt"] directory:NO];
            [b queueRemove:[remoteSub stringByAppendingPathComponent:@"empty"] directory:YES];
            [b queueRemove:remoteSub directory:YES];
            [b queueRemove:remoteTree directory:YES];
            EXPECT(wait_idle(b, 10), "the uploaded tree can be torn back down file by file");

            [[NSFileManager defaultManager] removeFileAtPath:upTree handler:nil];
            [[NSFileManager defaultManager] removeFileAtPath:downTree handler:nil];
        }

        wait_idle(b, 10);
        EXPECT(has_entry(b, @"renamed.bin", NO, 3000000, YES) && !has_entry(b, @"up.bin", NO, 0, NO), "rename is reflected in the listing");
        [b queueRemove:[dir stringByAppendingPathComponent:@"renamed.bin"] directory:NO];
        [b queueRemove:[dir stringByAppendingPathComponent:@"zdir"] directory:YES];
        EXPECT(wait_idle(b, 10) && [b entryCount] == 0, "delete (file and folder) empties the directory");

        /* ---- dropping files/folders from Workspace: droppedFiles: is what a real drop's
         * -performDragOperation: calls; the NSDraggingInfo/pasteboard side of an actual drag cannot
         * be simulated here, so this exercises everything downstream of reading the dropped paths. */
        {
            NSString *dropFile = [work stringByAppendingPathComponent:@"dropped.txt"];
            NSString *dropDir = [work stringByAppendingPathComponent:@"dropped_dir"];
            NSData *fileData = [@"dropped via droppedFiles:" dataUsingEncoding:NSASCIIStringEncoding];
            NSData *innerData = [@"inside the dropped folder" dataUsingEncoding:NSASCIIStringEncoding];

            [fileData writeToFile:dropFile atomically:NO];
            mkdir([dropDir cString], 0755);
            [innerData writeToFile:[dropDir stringByAppendingPathComponent:@"inner.txt"] atomically:NO];

            [b droppedFiles:[NSArray arrayWithObjects:dropFile, dropDir, nil]];
            EXPECT(wait_idle(b, 20), "a drop (one file, one folder) runs to completion");
            EXPECT([[NSData dataWithContentsOfFile:[dir stringByAppendingPathComponent:@"dropped.txt"]] isEqualToData:fileData],
                   "the dropped file arrived intact");
            EXPECT([[NSData dataWithContentsOfFile:[[dir stringByAppendingPathComponent:@"dropped_dir"]
                                                      stringByAppendingPathComponent:@"inner.txt"]] isEqualToData:innerData],
                   "the dropped folder was uploaded recursively");

            [b queueRemove:[dir stringByAppendingPathComponent:@"dropped.txt"] directory:NO];
            [b queueRemove:[[dir stringByAppendingPathComponent:@"dropped_dir"] stringByAppendingPathComponent:@"inner.txt"] directory:NO];
            [b queueRemove:[dir stringByAppendingPathComponent:@"dropped_dir"] directory:YES];
            wait_idle(b, 10);
            [[NSFileManager defaultManager] removeFileAtPath:dropFile handler:nil];
            [[NSFileManager defaultManager] removeFileAtPath:dropDir handler:nil];
        }

        [b queueRemove:dir directory:YES];
        wait_idle(b, 10);

        /* closing the browser must leave the shell working */
        [[b window] close];
        spin(0.5);
        EXPECT([s fileBrowser] == nil, "closing the browser window releases it");
        [s terminalView:tv sendBytes:(const unsigned char *)"echo AFTER_$((5*5))\r" length:20];
        EXPECT(wait_for(tv, @"AFTER_25", 10), "the terminal still works after the browser's channel closed");
        [s openFileBrowser];
        b = [s fileBrowser];
        EXPECT(b != nil && wait_idle(b, 10) && [b entryCount] > 0, "the browser can be opened again on the same connection");
        [[b window] close];
        spin(0.5);
        remove([big cString]); remove([back cString]);
    }

    /* ---- port forwarding: forward a local port back to the SAME sshd's own listening port, and
     * confirm the tunnel really round-trips through it -- if it does, connecting to the forwarded
     * local port hands back that sshd's own SSH banner, a signal nothing here fabricates. ---- */
    {
        int sshdPort = atoi(argv[1]);
        int lport = sshdPort + 1000;
        PortForward *pf = [s addForwardWithLocalPort:lport remoteHost:@"127.0.0.1" remotePort:sshdPort];
        int cfd, flags, n;
        struct sockaddr_in a;
        char buf[256];
        double waited;

        EXPECT(pf != nil, "a port forward can be added and starts listening");
        EXPECT([[s portForwards] count] == 1, "it shows up in the session's list of forwards");

        cfd = socket(AF_INET, SOCK_STREAM, 0);
        flags = fcntl(cfd, F_GETFL, 0);
        fcntl(cfd, F_SETFL, flags | O_NONBLOCK);
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = htons((unsigned short)lport);
        connect(cfd, (struct sockaddr *)&a, sizeof(a));      /* non-blocking: EINPROGRESS is normal, not an error */

        n = wait_for_bytes(cfd, buf, sizeof(buf), 10);
        EXPECT(n > 0 && !strncmp(buf, "SSH-2.0-", 8),
               "connecting to the forwarded port yields the real sshd's own banner, through the tunnel");

        close(cfd);
        waited = 0;
        while ((int)[pf->tunnels count] > 0 && waited < 10) { spin(0.05); waited += 0.05; }
        EXPECT((int)[pf->tunnels count] == 0, "closing the local side is noticed and the tunnel is cleaned up");

        [s removeForward:pf];
        EXPECT([[s portForwards] count] == 0, "removing a forward drops it from the session's list");
        {
            int cfd2 = socket(AF_INET, SOCK_STREAM, 0);
            int rc = connect(cfd2, (struct sockaddr *)&a, sizeof(a));   /* same address: still port lport */
            EXPECT(rc != 0, "and the local port is no longer listening at all");
            close(cfd2);
        }

        /* a forward to a port nothing listens on: the server's own connect() fails, which must reach
         * us as CHAN_OPEN_FAILED and close our local side cleanly rather than hang it open */
        {
            PortForward *pf2 = [s addForwardWithLocalPort:lport remoteHost:@"127.0.0.1" remotePort:(sshdPort + 2000)];
            int cfd3 = socket(AF_INET, SOCK_STREAM, 0);
            fcntl(cfd3, F_SETFL, fcntl(cfd3, F_GETFL, 0) | O_NONBLOCK);
            connect(cfd3, (struct sockaddr *)&a, sizeof(a));
            n = wait_for_bytes(cfd3, buf, sizeof(buf), 10);
            EXPECT(n == 0, "a forward to a port nothing answers on gets its local connection closed, not hung");
            close(cfd3);
            [s removeForward:pf2];
        }
    }

    /* ---- verbose logging: a second, independent connection with setVerbose:YES before -start ---- */
    {
        Owner *vowner = [[Owner alloc] init];
        SSHSession *vs = [[SSHSession alloc] initWithHost:@"127.0.0.1" port:atoi(argv[1])
                                                       user:[NSString stringWithCString:argv[2]]
                                                    keyPath:[NSString stringWithCString:argv[3]]
                                             knownHostsPath:[NSString stringWithCString:argv[4]]
                                                      owner:vowner];
        TerminalView *vtv;
        DebugLogController *dlc;
        NSString *log;

        [vs setVerbose:YES];
        [vs start];
        vtv = find_terminal([vs window]);
        EXPECT(vtv != nil, "a verbose session also builds a terminal window");

        dlc = [vs debugLogController];
        EXPECT(dlc != nil, "setVerbose:YES before -start creates the debug log window right away");

        EXPECT(wait_for(vtv, @"Trying public key", 10), "a verbose session authenticates too");
        { double w = 0; while (![vs isActive] && w < 5) { spin(0.05); w += 0.05; } }
        spin(0.5);

        log = [dlc logText];
        EXPECT([log rangeOfString:@"Connecting to 127.0.0.1"].length > 0, "debug log records the initial connect line");
        EXPECT([log rangeOfString:@"Host key:"].length > 0, "debug log records the host key");
        EXPECT([log rangeOfString:@"Auth methods offered:"].length > 0, "debug log records the auth methods offered");
        EXPECT([log rangeOfString:@"Authenticated. kex="].length > 0, "debug log records the negotiated algorithms");

        [vs terminalView:vtv sendBytes:(const unsigned char *)"exit\r" length:5];
        EXPECT(wait_for(vtv, @"Connection closed", 10), "a verbose session's remote exit is reported too");
        log = [dlc logText];
        EXPECT([log rangeOfString:@"Ended: Connection closed"].length > 0, "debug log records how the session ended");

        [[vs window] close];
        spin(0.2);
        EXPECT([dlc window] != nil && [[dlc window] isVisible], "the debug log window stays open after the session's own window closes");
        [[dlc window] close];
        spin(0.2);
        EXPECT([vs debugLogController] == nil, "closing the debug log window releases it");
        [vs release];
        [vowner release];
    }

    /* orderly exit */
    [s terminalView:tv sendBytes:(const unsigned char *)"exit\r" length:5];
    EXPECT(wait_for(tv, @"Connection closed", 10), "remote exit is reported and the session ends");
    EXPECT(![s isActive], "session is no longer active");
    [[s window] close];
    spin(0.2);
    EXPECT([owner ended], "closing the window notifies the owner");

    printf("session smoke: %d passed, %d failed\n", pass, fail);
    [pool release];
    return fail ? 1 : 0;
}
