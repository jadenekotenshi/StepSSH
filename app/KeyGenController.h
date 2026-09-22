#import "Compat.h"
#import "SecretField.h"

/* "Generate Key..." -- creates an ed25519 key pair on this machine, so the private key
 * never has to travel.  Files are written mode 0600 (private) / 0644 (.pub) and an
 * existing file is never overwritten. */
@interface KeyGenController : NSObject
{
    id            owner;
    NSPanel      *panel, *resultPanel;
    NSTextField  *pathField, *commentField, *statusLabel, *resultText, *installText;
    SecretField  *passField, *againField;
    NSString     *lastPath, *lastPublicLine, *lastFingerprint;
}
- (id)initWithOwner:(id)anOwner;
- (void)showPanel;
- (void)generate:(id)sender;
- (void)cancel:(id)sender;
- (void)copyPublicKey:(id)sender;
- (void)copyInstallCommand:(id)sender;
- (void)useKey:(id)sender;
- (void)done:(id)sender;
/* The whole job, without any UI: returns nil on success or a message describing what is wrong. */
- (NSString *)generateToPath:(NSString *)path comment:(NSString *)comment passphrase:(const char *)pass;
- (NSString *)lastPath;
- (NSString *)lastPublicLine;
- (NSString *)lastFingerprint;
- (NSString *)installCommand;
@end

@interface NSObject (KeyGenOwner)
- (void)keyGenerated:(NSString *)privateKeyPath;
@end
