#import "Compat.h"
#include "wire.h"

/* One forwarded X11 connection: a real local socket dialed out to the configured X display,
 * paired with an already-open "x11" SSH channel (the server opened it -- see SSH_EV_X11_OPEN).
 * The mirror image of PortForward.h's PortTunnel: there the channel starts CH_OPENING while a
 * local socket has already been accepted; here the channel is already open and it's the local
 * socket's own non-blocking connect() that is still in flight. Data flowing channel -> local is
 * buffered here (outToLocal) whenever the local socket's own send buffer is momentarily full;
 * local -> channel needs no buffer of its own, since ssh_channel_write() already keeps one per
 * channel. A separate class (not folded into PortForward.h, and not private inside
 * SSHSession.m) so a future test can inspect its public ivars the same way tests/session_smoke.m
 * already does with PortTunnel. */
@interface X11Tunnel : NSObject
{
@public
    int      localFD;              /* -1 once closed */
    int      channel;              /* the already-open x11 channel id; -1 once gone */
    BOOL     connecting;           /* non-blocking local connect() in flight (EINPROGRESS) */
    BOOL     localOpen;            /* local connect() succeeded; ok to relay */
    BOOL     localClosed, remoteClosed;
    unsigned connectDeadline;      /* in the owning session's own `ticks` units */
    sbuf     outToLocal;
}
@end
