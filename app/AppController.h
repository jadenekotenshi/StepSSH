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
- (void)openSessionWithHost:(NSString *)host port:(int)port user:(NSString *)user keyPath:(NSString *)key openBrowser:(BOOL)browser;
- (void)openFileBrowser:(id)sender;
- (void)sessionDidEnd:(SSHSession *)session;
- (void)entropyReady;
@end
