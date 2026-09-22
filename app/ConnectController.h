#import "Compat.h"

/* The "New Connection" panel, with saved hosts kept in NSUserDefaults. */
@interface ConnectController : NSObject
{
    id                owner;
    NSPanel          *panel;
    NSTextField      *hostField, *portField, *userField, *keyField;
    NSButton         *useKeyBox, *saveBox, *browserBox;
    NSPopUpButton    *savedPopup;
    NSMutableArray   *profiles;                /* array of NSDictionary: host, port, user, key */
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
- (void)openSessionWithHost:(NSString *)host port:(int)port user:(NSString *)user keyPath:(NSString *)key openBrowser:(BOOL)browser;
@end
