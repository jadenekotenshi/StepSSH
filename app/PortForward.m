#import "PortForward.h"
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "oscompat.h"

@implementation PortTunnel
- (id)init
{
    self = [super init];
    if (!self) return nil;
    localFD = -1;
    channel = -1;
    sb_init(&outToLocal);
    return self;
}
- (void)dealloc
{
    sb_free(&outToLocal);
    [super dealloc];
}
@end

@implementation PortForward

- (id)initWithLocalPort:(int)lp remoteHost:(NSString *)rh remotePort:(int)rp
{
    self = [super init];
    if (!self) return nil;
    localPort = lp;
    remoteHost = [rh copy];
    remotePort = rp;
    listenFD = -1;
    tunnels = [[NSMutableArray alloc] init];
    return self;
}

- (void)dealloc
{
    [self stopListening];
    [remoteHost release];
    [error release];
    [tunnels release];
    [super dealloc];
}

- (BOOL)startListening
{
    struct sockaddr_in sa;
    int fd, one = 1, flags;

    [error release]; error = nil;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { error = [[NSString stringWithFormat:@"cannot create a socket: %s", strerror(errno)] retain]; return NO; }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(one));

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);      /* never on the network: OpenSSH's own default (no GatewayPorts) */
    sa.sin_port = htons((unsigned short)localPort);
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        error = [[NSString stringWithFormat:@"cannot bind to port %d: %s", localPort, strerror(errno)] retain];
        close(fd);
        return NO;
    }
    if (listen(fd, 8) != 0) {
        error = [[NSString stringWithFormat:@"listen failed: %s", strerror(errno)] retain];
        close(fd);
        return NO;
    }
    flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    listenFD = fd;
    return YES;
}

- (void)stopListening
{
    int i;
    if (listenFD >= 0) { close(listenFD); listenFD = -1; }
    for (i = 0; i < (int)[tunnels count]; i++) {
        PortTunnel *t = [tunnels objectAtIndex:i];
        if (t->localFD >= 0) { close(t->localFD); t->localFD = -1; }
    }
    [tunnels removeAllObjects];
}

@end
