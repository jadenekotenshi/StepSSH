#import "Compat.h"
#import "TerminalView.h"
#include "ssh.h"
#include "wire.h"
#include "sftp.h"

@class SFTPBrowser;
@class PortForward;
@class PortForwardController;
@class DebugLogController;
@class X11Tunnel;

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

    /* X11 forwarding: set (once, before -start takes effect) by -setX11Enabled:.... Every
     * server-initiated "x11" channel that arrives after that becomes its own X11Tunnel, relayed
     * to x11DisplayHost:x11DisplayPort the same way -L's own tunnels are relayed, just dialed
     * outbound instead of accepted. */
    BOOL            x11Enabled;
    NSString       *x11DisplayHost;
    int             x11DisplayPort;
    NSData         *x11RealCookie;       /* nil: forward no authentication data to the display */
    NSMutableArray *x11Tunnels;          /* X11Tunnel* */

    /* verbose/troubleshooting log: a window of connection diagnostics, shown automatically when
     * verbose is set before -start (see the New Connection panel's "Verbose logging" checkbox) */
    int                 verbose;
    DebugLogController *debugLog;
}
- (id)initWithHost:(NSString *)h port:(int)p user:(NSString *)u keyPath:(NSString *)k
    knownHostsPath:(NSString *)kh owner:(id)o;
- (void)start;
- (BOOL)isActive;
- (void)shutdown;
- (NSWindow *)window;

/* verbose/troubleshooting log: call before -start (the New Connection panel does, from its
 * "Verbose logging" checkbox) -- has no effect once the session is already connecting. */
- (void)setVerbose:(BOOL)flag;
- (DebugLogController *)debugLogController;
- (void)debugLogControllerClosed:(id)dlc;

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

/* X11 forwarding: call before -start (the New Connection panel does, from its "Forward X11"
 * checkbox) -- has no effect once the session is already connecting. `cookieHex` is the real
 * cookie to present to the local display, as hex text (32 hex characters == 16 bytes), or nil/
 * empty for "forward no authentication data at all." */
- (void)setX11Enabled:(BOOL)flag displayHost:(NSString *)h displayPort:(int)p cookieHex:(NSString *)cookieHex;
- (NSArray *)x11Tunnels;                                                                /* read-only, for tests */
@end

@interface NSObject (SSHSessionOwner)
- (void)sessionDidEnd:(SSHSession *)session;
@end
