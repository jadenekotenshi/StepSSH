#import "Compat.h"

@class SSHSession;

/* Manages the local port forwards ("ssh -L") on one connection: a table of rules, each a listening
 * socket on this machine that relays to a host:port reachable from the server, plus Add/Remove.
 * Borrows the SSH connection of its SSHSession, the same way SFTPBrowser does. */
@interface PortForwardController : NSObject
{
    SSHSession  *session;              /* not retained: the session owns us */
    NSWindow    *window;
    NSTableView *table;
    NSButton    *addBtn, *removeBtn;
}
- (id)initWithSession:(SSHSession *)s;
- (void)show;
- (void)closeWindow;
- (NSWindow *)window;
- (void)reload;                        /* call after a rule's connection count or error changes */
@end
