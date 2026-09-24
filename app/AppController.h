#import "Compat.h"
#import "SSHSession.h"

@class ConnectController;
@class KeyGenController;

@interface AppController : NSObject
{
    NSMutableArray    *sessions;
    ConnectController *connectController;
    KeyGenController  *keyGenController;
    NSString          *sshDir;                 /* ~/.ssh */
    NSString          *knownHostsPath;
    NSString          *seedPath;
    NSPanel           *entropyPanel;
    id                 entropyMeter;
    BOOL               launched;
}
- (void)buildMenu;
- (void)newConnection:(id)sender;
- (void)showAbout:(id)sender;
- (void)generateKey:(id)sender;
- (void)keyGenerated:(NSString *)privateKeyPath;
- (void)openSessionWithHost:(NSString *)host port:(int)port user:(NSString *)user keyPath:(NSString *)key
                 openBrowser:(BOOL)browser verbose:(BOOL)verbose
                  x11Enabled:(BOOL)x11 x11DisplayHost:(NSString *)x11Host x11DisplayPort:(int)x11Port
                   x11Cookie:(NSString *)x11Cookie;
- (void)openFileBrowser:(id)sender;
- (void)openPortForwarding:(id)sender;
- (void)sessionDidEnd:(SSHSession *)session;
- (void)entropyReady;
@end
