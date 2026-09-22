#import "KeyGenController.h"
#import "UIHelpers.h"
#include "ssh_key.h"
#include "rng.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "oscompat.h"

@interface KeyGenController (Private)
- (void)buildPanel;
- (void)showResult;
- (NSString *)defaultPath;
- (NSString *)defaultComment;
- (void)copyString:(NSString *)s;
@end

/* Refuse anything that could break out of the shell command we offer to copy. */
static BOOL comment_is_safe(NSString *c)
{
    unsigned i, n = [c length];
    for (i = 0; i < n; i++) {
        unichar ch = [c characterAtIndex:i];
        BOOL ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
                  ch == '@' || ch == '.' || ch == '_' || ch == '-' || ch == '+' || ch == ' ';
        if (!ok) return NO;
    }
    return YES;
}

static int write_file(const char *path, const sbuf *b, int mode)
{
    FILE *f = fopen(path, "wb");
    int rc;
    if (!f) return -1;
    chmod(path, mode);                      /* before any secret is written */
    rc = (fwrite(b->p, 1, b->len, f) == b->len) ? 0 : -1;
    if (fclose(f) != 0) rc = -1;
    return rc;
}

@implementation KeyGenController

- (id)initWithOwner:(id)anOwner
{
    self = [super init];
    owner = anOwner;
    return self;
}

- (void)dealloc
{
    [panel release]; [resultPanel release];
    [lastPath release]; [lastPublicLine release]; [lastFingerprint release];
    [super dealloc];
}

- (NSString *)lastPath { return lastPath; }
- (NSString *)lastPublicLine { return lastPublicLine; }
- (NSString *)lastFingerprint { return lastFingerprint; }

/* ---------------------------------------------------------------- */
/* the job                                                          */

- (NSString *)generateToPath:(NSString *)path comment:(NSString *)comment passphrase:(const char *)pass
{
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *full = [path stringByExpandingTildeInPath];
    NSString *dir = [full stringByDeletingLastPathComponent];
    NSString *pubPath = [full stringByAppendingString:@".pub"];
    ssh_key k;
    sbuf priv, pub, blob;
    char fp[64];
    NSString *err = nil;

    if ([full length] == 0) return @"Enter a file name for the key.";
    if (!comment_is_safe(comment))
        return @"The comment may only contain letters, digits, spaces and the characters @ . _ - +";
    if ([fm fileExistsAtPath:full] || [fm fileExistsAtPath:pubPath])
        return [NSString stringWithFormat:@"%@ already exists. Choose another name; existing keys are never overwritten.", full];
    if (![fm fileExistsAtPath:dir]) {
        if (mkdir([dir cString], 0700) != 0)
            return [NSString stringWithFormat:@"The folder %@ does not exist and could not be created.", dir];
    }
    if (!ssh_rng_ready()) return @"Not enough random data has been collected yet.";

    sb_init(&priv); sb_init(&pub); sb_init(&blob);
    if (ssh_key_generate_ed25519(&k, [comment cString]) != 0) {
        err = @"Key generation failed (random number generator).";
    } else if (ssh_key_write_private(&k, pass, 16, &priv) != 0 || ssh_key_write_public_line(&k, &pub) != 0) {
        err = @"Could not encode the key.";
    } else if (write_file([full cString], &priv, 0600) != 0) {
        err = [NSString stringWithFormat:@"Could not write %@.", full];
        remove([full cString]);
    } else if (write_file([pubPath cString], &pub, 0644) != 0) {
        err = [NSString stringWithFormat:@"Could not write %@.", pubPath];
        remove([full cString]);
        remove([pubPath cString]);
    } else {
        ssh_key_public_blob(&k, &blob);
        ssh_fingerprint_sha256(blob.p, blob.len, fp, sizeof(fp));
        [lastPath release]; [lastPublicLine release]; [lastFingerprint release];
        lastPath = [full retain];
        lastPublicLine = [[NSString stringWithCString:(const char *)pub.p length:pub.len - 1] retain];   /* no newline */
        lastFingerprint = [[NSString stringWithCString:fp] retain];
    }
    ssh_key_wipe(&k);
    sb_free(&priv); sb_free(&pub); sb_free(&blob);
    return err;
}

- (NSString *)installCommand
{
    return [NSString stringWithFormat:
        @"mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '%@' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys",
        lastPublicLine];
}

/* ---------------------------------------------------------------- */
/* the form                                                         */

- (NSString *)defaultPath
{
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *base = [NSHomeDirectory() stringByAppendingPathComponent:@".ssh/id_ed25519"];
    NSString *p = base;
    int n = 2;
    while ([fm fileExistsAtPath:p] || [fm fileExistsAtPath:[p stringByAppendingString:@".pub"]]) {
        p = [NSString stringWithFormat:@"%@_%d", base, n++];
        if (n > 99) break;
    }
    return p;
}

- (NSString *)defaultComment
{
    return [NSString stringWithFormat:@"%@@%@", NSUserName(), [[NSProcessInfo processInfo] hostName]];
}

- (void)buildPanel
{
    NSView *c;
    panel = [[NSPanel alloc] initWithContentRect:NSMakeRect(0, 0, 460, 296)
                                       styleMask:(NSTitledWindowMask | NSClosableWindowMask)
                                         backing:NSBackingStoreBuffered
                                           defer:NO];
    [panel setTitle:@"Generate Key"];
    [panel setReleasedWhenClosed:NO];
    [panel setHidesOnDeactivate:NO];
    c = [panel contentView];

    [c addSubview:ui_wrapping_label(@"Creates a new ed25519 key pair on this computer. The private key stays here; you copy only the public key to servers.",
                                    NSMakeRect(14, 232, 432, 50), NO)];
    [c addSubview:ui_label(@"Save as:", NSMakeRect(14, 202, 90, 20))];
    pathField = ui_field(NSMakeRect(110, 200, 336, 22));
    [c addSubview:pathField];
    [c addSubview:ui_label(@"Comment:", NSMakeRect(14, 168, 90, 20))];
    commentField = ui_field(NSMakeRect(110, 166, 336, 22));
    [c addSubview:commentField];
    [c addSubview:ui_label(@"Passphrase:", NSMakeRect(14, 134, 90, 20))];
    passField = [[[SecretField alloc] initWithFrame:NSMakeRect(110, 132, 336, 24)] autorelease];
    [c addSubview:passField];
    [c addSubview:ui_label(@"Again:", NSMakeRect(14, 100, 90, 20))];
    againField = [[[SecretField alloc] initWithFrame:NSMakeRect(110, 98, 336, 24)] autorelease];
    [c addSubview:againField];
    [c addSubview:ui_wrapping_label(@"A passphrase protects the key if this computer is ever copied or stolen. Unlocking it takes a few seconds here.",
                                    NSMakeRect(14, 52, 432, 34), NO)];
    statusLabel = ui_label(@"", NSMakeRect(14, 20, 200, 20));
    [c addSubview:statusLabel];
    [c addSubview:ui_button(@"Cancel", NSMakeRect(268, 14, 82, 30), self, @selector(cancel:))];
    {
        NSButton *g = ui_button(@"Generate", NSMakeRect(364, 14, 82, 30), self, @selector(generate:));
        [g setKeyEquivalent:@"\r"];
        [c addSubview:g];
    }
    [pathField setNextKeyView:commentField];
    [commentField setNextKeyView:passField];
    [passField setNextKeyView:againField];
    [againField setNextKeyView:pathField];
    [panel setInitialFirstResponder:pathField];
    [panel center];
}

- (void)showPanel
{
    if (!panel) [self buildPanel];
    [pathField setStringValue:[self defaultPath]];
    [commentField setStringValue:[self defaultComment]];
    [passField wipe];
    [againField wipe];
    [statusLabel setStringValue:@""];
    [panel makeKeyAndOrderFront:nil];
    [panel makeFirstResponder:pathField];
}

- (void)cancel:(id)sender
{
    [passField wipe];
    [againField wipe];
    [panel orderOut:nil];
}

- (void)generate:(id)sender
{
    char *p1 = [passField copySecret], *p2 = [againField copySecret];
    NSString *err = nil;
    BOOL empty;

    if (!p1 || !p2) { free(p1); free(p2); return; }
    if (strcmp(p1, p2) != 0) {
        err = @"The two passphrases do not match.";
    } else if (p1[0] == '\0') {
        empty = (NSRunAlertPanel(@"No passphrase",
                    @"Anyone who obtains the key file can use it. Create the key without a passphrase?",
                    @"Cancel", @"No passphrase", nil) == NSAlertAlternateReturn);
        if (!empty) { memset(p1, 0, strlen(p1)); memset(p2, 0, strlen(p2)); free(p1); free(p2); return; }
    }
    if (!err) {
        [statusLabel setStringValue:@"Generating ..."];
        [panel displayIfNeeded];                       /* the encryption step can take seconds */
        err = [self generateToPath:ui_trim([pathField stringValue])
                           comment:ui_trim([commentField stringValue])
                        passphrase:p1];
    }
    memset(p1, 0, strlen(p1)); memset(p2, 0, strlen(p2));
    free(p1); free(p2);
    if (err) {
        [statusLabel setStringValue:@""];
        NSRunAlertPanel(@"Cannot create key", @"%@", @"OK", nil, nil, err);
        return;
    }
    [passField wipe];
    [againField wipe];
    [panel orderOut:nil];
    [self showResult];
}

/* ---------------------------------------------------------------- */
/* the result                                                       */

- (void)showResult
{
    NSView *c;
    NSString *summary = [NSString stringWithFormat:@"Saved %@ (private) and %@.pub.\n\nFingerprint: %@",
                         lastPath, lastPath, lastFingerprint];
    if (!resultPanel) {
        resultPanel = [[NSPanel alloc] initWithContentRect:NSMakeRect(0, 0, 560, 330)
                                                 styleMask:(NSTitledWindowMask | NSClosableWindowMask)
                                                   backing:NSBackingStoreBuffered
                                                     defer:NO];
        [resultPanel setTitle:@"Key Created"];
        [resultPanel setReleasedWhenClosed:NO];
        [resultPanel setHidesOnDeactivate:NO];
        c = [resultPanel contentView];
        resultText = ui_wrapping_label(@"", NSMakeRect(14, 226, 532, 90), YES);
        [c addSubview:resultText];
        [c addSubview:ui_label(@"Public key -- add this line to ~/.ssh/authorized_keys on the server:", NSMakeRect(14, 200, 532, 18))];
        installText = ui_wrapping_label(@"", NSMakeRect(14, 118, 532, 76), YES);
        [installText setBezeled:YES];
        [installText setDrawsBackground:YES];
        [c addSubview:installText];
        [c addSubview:ui_wrapping_label(@"Tip: log in to the server with a password, choose Copy Install Command, and paste it into that session.",
                                        NSMakeRect(14, 70, 532, 36), NO)];
        [c addSubview:ui_button(@"Copy Public Key", NSMakeRect(14, 14, 130, 30), self, @selector(copyPublicKey:))];
        [c addSubview:ui_button(@"Copy Install Command", NSMakeRect(150, 14, 160, 30), self, @selector(copyInstallCommand:))];
        [c addSubview:ui_button(@"Use This Key", NSMakeRect(316, 14, 110, 30), self, @selector(useKey:))];
        [c addSubview:ui_button(@"Done", NSMakeRect(464, 14, 82, 30), self, @selector(done:))];
        [resultPanel center];
    }
    [resultText setStringValue:summary];
    [installText setStringValue:lastPublicLine];
    [resultPanel makeKeyAndOrderFront:nil];
}

- (void)copyString:(NSString *)s
{
    NSPasteboard *pb = [NSPasteboard generalPasteboard];
    [pb declareTypes:[NSArray arrayWithObject:NSStringPboardType] owner:nil];
    [pb setString:s forType:NSStringPboardType];
}

- (void)copyPublicKey:(id)sender { [self copyString:lastPublicLine]; }
- (void)copyInstallCommand:(id)sender { [self copyString:[self installCommand]]; }

- (void)useKey:(id)sender
{
    [owner keyGenerated:lastPath];
    [resultPanel orderOut:nil];
}

- (void)done:(id)sender { [resultPanel orderOut:nil]; }

@end
