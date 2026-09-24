#import "Compat.h"

/* The "New Connection" panel, with saved hosts kept in NSUserDefaults. */
@interface ConnectController : NSObject
{
    id                owner;
    NSPanel          *panel;
    NSTextField      *hostField, *portField, *userField, *keyField;
    NSButton         *useKeyBox, *saveBox, *browserBox, *verboseBox;
    NSButton         *x11Box;
    NSTextField      *x11HostField, *x11PortField, *x11CookieField;
    NSPopUpButton    *savedPopup;
    NSMutableArray   *profiles;                /* array of NSDictionary: host, port, user, key,
                                                   x11, x11Host, x11Port, x11Cookie */
}
- (id)initWithOwner:(id)anOwner;
- (void)showPanel;
- (void)connect:(id)sender;
- (void)cancel:(id)sender;
- (void)savedChosen:(id)sender;
- (void)deleteSaved:(id)sender;
- (void)useKeyAtPath:(NSString *)path;      /* select a key file and tick "Log in with a key file" */
@end

@interface NSObject (ConnectOwner)
- (void)openSessionWithHost:(NSString *)host port:(int)port user:(NSString *)user keyPath:(NSString *)key
                 openBrowser:(BOOL)browser verbose:(BOOL)verbose
                  x11Enabled:(BOOL)x11 x11DisplayHost:(NSString *)x11Host x11DisplayPort:(int)x11Port
                   x11Cookie:(NSString *)x11Cookie;
@end
