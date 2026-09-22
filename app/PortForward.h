#import "Compat.h"
#include "wire.h"

/* One tunneled connection: a local socket accepted on a PortForward's listener, paired with a
 * direct-tcpip channel on the SSH connection.  Data flowing channel -> local is buffered here
 * (outToLocal) whenever the local socket's own send buffer is momentarily full; local -> channel
 * needs no buffer of its own, since ssh_channel_write() already keeps one per channel. */
@interface PortTunnel : NSObject
{
@public
    int  localFD;                  /* -1 once closed */
    int  channel;                  /* -1 until the CHANNEL_OPEN_CONFIRMATION arrives, or once it is gone */
    BOOL channelOpen;
    BOOL localClosed, remoteClosed;
    sbuf outToLocal;
}
@end

/* One configured "forward this local port to host:port on the other side of the connection" rule,
 * and the listening socket that implements it.  Every connection accepted on that socket becomes its
 * own PortTunnel; several can be open on one rule at once (e.g. several browser tabs through the same
 * forwarded HTTP port). */
@interface PortForward : NSObject
{
@public
    int             localPort;
    NSString       *remoteHost;
    int             remotePort;
    int             listenFD;      /* -1: not listening -- see error */
    NSString       *error;
    NSMutableArray *tunnels;       /* PortTunnel* */
}
- (id)initWithLocalPort:(int)lp remoteHost:(NSString *)rh remotePort:(int)rp;
/* Binds and listens on 127.0.0.1:localPort.  Returns NO (and sets `error`) on failure -- a forward is
 * never exposed to the network: OpenSSH's own default (no GatewayPorts) is followed unconditionally,
 * since nothing in this app lets the user ask for anything else. */
- (BOOL)startListening;
- (void)stopListening;             /* closes the listener and every active tunnel's local socket */
@end
