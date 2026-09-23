#import "Compat.h"

@class SSHSession;

/* A scrolling, read-only log of connection diagnostics for one session -- host key info, auth
 * methods offered/tried, negotiated algorithms, channel/disconnect events, and (in verbose mode)
 * the server's own SSH_MSG_DEBUG text. Shown automatically when "Verbose logging" is checked in
 * the New Connection panel; borrows nothing from the connection itself, so it can stay open (and
 * keep showing what happened) after the session ends. */
@interface DebugLogController : NSObject
{
    SSHSession   *session;             /* not retained: the session owns us */
    NSWindow     *window;
    NSTextView   *text;
}
- (id)initWithSession:(SSHSession *)s;
- (void)show;
- (void)closeWindow;
- (NSWindow *)window;
- (void)appendLine:(NSString *)line;
- (NSString *)logText;                     /* everything appended so far, for tests */
@end
