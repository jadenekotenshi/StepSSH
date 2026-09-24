#import "X11Tunnel.h"

@implementation X11Tunnel
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
