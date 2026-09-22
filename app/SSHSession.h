#import "Compat.h"
#import "TerminalView.h"
#include "ssh.h"
#include "wire.h"
#include "sftp.h"

@class SFTPBrowser;
@class PortForward;
@class PortForwardController;

enum { SESS_CONNECTING = 1, SESS_HANDSHAKE, SESS_ACTIVE, SESS_ENDED };

/* One SSH connection: socket + protocol engine + terminal window.
 * Single-threaded; a 20 ms NSTimer polls the socket. */
@interface SSHSession : NSObject
{
    NSString      *host;
    int            port;
    NSString      *user;
    NSString      *keyPath;
    NSString      *knownHostsPath;
    id             owner;

    ssh_session   *ssh;
    ssh_key        key;
    int            haveKey;
    int            fd;
    int            state;
    int            channel;
    int            triedKey, passwordTries, kbdTries;
    int            inTick;
    int            exitStatus;
    unsigned       ticks;
    unsigned       connectDeadline, keepaliveAt;
    NSTimer       *timer;
    sbuf           pendingIn;

    NSWindow      *window;
    TerminalView  *termView;
    NSScroller    *scroller;

    /* file browser: a second channel on the same connection */
    int            sftpChannel;          /* -1 = none */
    int            sftpClosing;
    sftp          *sftpCore;
    SFTPBrowser   *browser;
    int            openBrowserOnLogin;

    /* local port forwarding ("ssh -L"): any number of further channels, one per tunneled connection */
    NSMutableArray        *forwards;     /* PortForward* */
    PortForwardController *forwardController;
}
- (id)initWithHost:(NSString *)h port:(int)p user:(NSString *)u keyPath:(NSString *)k
    knownHostsPath:(NSString *)kh owner:(id)o;
- (void)start;
- (BOOL)isActive;
- (void)shutdown;
- (NSWindow *)window;

/* file browser */
- (void)setOpensBrowserOnLogin:(BOOL)flag;
- (void)openFileBrowser;
- (SFTPBrowser *)fileBrowser;
- (sftp *)sftpCore;
- (void)sftpKick;                          /* push queued SFTP bytes out on the wire now */
- (void)browserClosed:(id)aBrowser;

/* port forwarding */
- (void)openPortForwarding;
- (PortForwardController *)portForwardController;
- (NSArray *)portForwards;                                                              /* read-only, for the UI */
- (PortForward *)addForwardWithLocalPort:(int)lp remoteHost:(NSString *)rh remotePort:(int)rp;  /* nil on failure */
- (void)removeForward:(PortForward *)pf;
- (void)portForwardControllerClosed:(id)pfc;
@end

@interface NSObject (SSHSessionOwner)
- (void)sessionDidEnd:(SSHSession *)session;
@end
