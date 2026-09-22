#import "AppController.h"
#import "ConnectController.h"
#import "KeyGenController.h"
#import "SFTPBrowser.h"
#import "UIHelpers.h"
#include "rng.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "oscompat.h"

/* ---------------------------------------------------------------- */
/* Entropy meter: a small panel that turns mouse and key timing into
 * credited random bits.  Needed only when no /dev/urandom and no seed
 * file exist, i.e. the first run on a fresh OPENSTEP install.       */

@interface EntropyMeter : NSView
{
    id   target;
    int  lastX, lastY;
}
- (void)setTarget:(id)t;
@end

@implementation EntropyMeter
- (void)setTarget:(id)t { target = t; }
- (BOOL)acceptsFirstResponder { return YES; }
- (BOOL)acceptsFirstMouse:(NSEvent *)e { return YES; }
- (BOOL)isOpaque { return YES; }

- (void)feed:(NSEvent *)e
{
    NSPoint p = [e locationInWindow];
    int x = (int)p.x, y = (int)p.y;
    if (x == lastX && y == lastY) return;              /* only movement counts */
    lastX = x; lastY = y;
    ssh_rng_add(&p, sizeof(p), 0);
    ssh_rng_add_timing(1);                             /* conservative: one bit per event */
    [self setNeedsDisplay:YES];
    if (ssh_rng_ready()) [target entropyReady];
}
- (void)mouseMoved:(NSEvent *)e   { [self feed:e]; }
- (void)mouseDragged:(NSEvent *)e { [self feed:e]; }
- (void)mouseDown:(NSEvent *)e    { [self feed:e]; }
- (void)keyDown:(NSEvent *)e      { ssh_rng_add_timing(1); [self setNeedsDisplay:YES]; if (ssh_rng_ready()) [target entropyReady]; }

- (void)drawRect:(NSRect)rect
{
    NSRect b = [self bounds], bar;
    float frac = (float)ssh_rng_credited() / (float)SSH_RNG_MIN_BITS;
    if (frac > 1.0) frac = 1.0;
    [[NSColor whiteColor] set];
    NSRectFill(b);
    [[NSColor blackColor] set];
    NSFrameRect(NSInsetRect(b, 1, 1));
    bar = NSInsetRect(b, 4, 4);
    bar.size.width *= frac;
    [[NSColor darkGrayColor] set];
    NSRectFill(bar);
}
@end

/* ---------------------------------------------------------------- */

@implementation AppController

- (id)init
{
    self = [super init];
    if (!self) return nil;
    sessions = [[NSMutableArray alloc] init];
    sshDir = [[NSHomeDirectory() stringByAppendingPathComponent:@".ssh"] retain];
    knownHostsPath = [[sshDir stringByAppendingPathComponent:@"known_hosts"] retain];
    seedPath = [[sshDir stringByAppendingPathComponent:@"random_seed"] retain];
    connectController = [[ConnectController alloc] initWithOwner:self];
    keyGenController = [[KeyGenController alloc] initWithOwner:self];
    return self;
}

- (void)dealloc
{
    [sessions release]; [sshDir release]; [knownHostsPath release]; [seedPath release];
    [connectController release];
    [keyGenController release];
    [super dealloc];
}

/* ---------------------------------------------------------------- */
/* menus                                                            */

- (void)addItem:(NSString *)title action:(SEL)action key:(NSString *)key
         target:(id)target toMenu:(NSMenu *)menu
{
    id item = [menu addItemWithTitle:title action:action keyEquivalent:key];
    if (target) [item setTarget:target];
}

- (NSMenu *)submenuNamed:(NSString *)title inMenu:(NSMenu *)parent
{
    NSMenu *sub = [[NSMenu alloc] initWithTitle:title];
    id item = [parent addItemWithTitle:title action:NULL keyEquivalent:@""];
    [parent setSubmenu:sub forItem:item];
    return [sub autorelease];
}

- (void)buildMenu
{
    NSMenu *main = [[[NSMenu alloc] initWithTitle:@"Secure Shell"] autorelease];
    NSMenu *m;

    m = [self submenuNamed:@"Info" inMenu:main];
    [self addItem:@"Info Panel..." action:@selector(showAbout:) key:@"" target:self toMenu:m];

    m = [self submenuNamed:@"Connection" inMenu:main];
    [self addItem:@"New Connection..." action:@selector(newConnection:) key:@"n" target:self toMenu:m];
    [self addItem:@"Open File Browser" action:@selector(openFileBrowser:) key:@"b" target:self toMenu:m];
    [self addItem:@"Generate Key..." action:@selector(generateKey:) key:@"g" target:self toMenu:m];
    [self addItem:@"Close Window" action:@selector(performClose:) key:@"w" target:nil toMenu:m];

    m = [self submenuNamed:@"Edit" inMenu:main];
    [self addItem:@"Copy" action:@selector(copy:) key:@"c" target:nil toMenu:m];
    [self addItem:@"Paste" action:@selector(paste:) key:@"v" target:nil toMenu:m];
    [self addItem:@"Select All" action:@selector(selectAll:) key:@"a" target:nil toMenu:m];
    [self addItem:@"Clear Scrollback" action:@selector(clearScrollback:) key:@"k" target:nil toMenu:m];

    m = [self submenuNamed:@"Windows" inMenu:main];
    [self addItem:@"Arrange in Front" action:@selector(arrangeInFront:) key:@"" target:nil toMenu:m];
    [self addItem:@"Miniaturize Window" action:@selector(performMiniaturize:) key:@"m" target:nil toMenu:m];
    [NSApp setWindowsMenu:m];

    m = [self submenuNamed:@"Services" inMenu:main];
    [NSApp setServicesMenu:m];

    [self addItem:@"Hide" action:@selector(hide:) key:@"h" target:NSApp toMenu:main];
    [self addItem:@"Quit" action:@selector(terminate:) key:@"q" target:NSApp toMenu:main];

    [NSApp setMainMenu:main];
}

- (void)showAbout:(id)sender
{
    NSRunAlertPanel(@"Secure Shell",
                    @"An SSH-2 client for OPENSTEP.\n\nCiphers: chacha20-poly1305, aes-ctr\nKey exchange: curve25519-sha256\nHost/user keys: ssh-ed25519",
                    @"OK", nil, nil);
}

/* ---------------------------------------------------------------- */
/* startup                                                          */

- (void)prepareSecurityDirectory
{
    struct stat st;
    const char *d = [sshDir cString];
    if (stat(d, &st) != 0) mkdir(d, 0700);
}

- (void)applicationDidFinishLaunching:(NSNotification *)notification
{
    launched = YES;
    NSLog(@"SecureShell: applicationDidFinishLaunching");
    SSTrace("applicationDidFinishLaunching");
    [self prepareSecurityDirectory];
    ssh_rng_seed_system();                              /* /dev/urandom, if this system has one */
    ssh_rng_load_seed([seedPath cString]);              /* and last run's seed (replaced immediately) */
    NSLog(@"SecureShell: random pool holds %d of %d bits", ssh_rng_credited(), SSH_RNG_MIN_BITS);
    SSTrace("random pool holds %d of %d bits", ssh_rng_credited(), SSH_RNG_MIN_BITS);
    if (ssh_rng_ready()) {
        ssh_rng_save_seed([seedPath cString]);
        [self newConnection:nil];
        return;
    }
    NSLog(@"SecureShell: not enough entropy; showing the seeding panel");
    /* Not enough entropy yet: ask the user to wiggle the mouse. */
    {
        NSTextField *label;
        entropyPanel = [[NSPanel alloc] initWithContentRect:NSMakeRect(0, 0, 360, 130)
                                                  styleMask:NSTitledWindowMask
                                                    backing:NSBackingStoreBuffered
                                                      defer:NO];
        [entropyPanel setTitle:@"Seeding random number generator"];
        [entropyPanel setHidesOnDeactivate:NO];
        [entropyPanel setAcceptsMouseMovedEvents:YES];
        label = [[[NSTextField alloc] initWithFrame:NSMakeRect(16, 74, 328, 44)] autorelease];
        [label setStringValue:@"This computer has no built-in source of randomness. Move the mouse around inside this window until the bar is full."];
        [label setEditable:NO]; [label setSelectable:NO]; [label setBezeled:NO];
        [label setBordered:NO]; [label setDrawsBackground:NO];
        entropyMeter = [[EntropyMeter alloc] initWithFrame:NSMakeRect(16, 24, 328, 26)];
        [entropyMeter setTarget:self];
        [[entropyPanel contentView] addSubview:label];
        [[entropyPanel contentView] addSubview:entropyMeter];
        [entropyPanel center];
        [entropyPanel makeKeyAndOrderFront:nil];
        [entropyPanel makeFirstResponder:entropyMeter];
    }
}

- (void)entropyReady
{
    if (!entropyPanel) return;
    ssh_rng_save_seed([seedPath cString]);              /* remember it: next launch needs no wiggling */
    [entropyPanel orderOut:nil];
    [entropyMeter release]; entropyMeter = nil;
    [entropyPanel release]; entropyPanel = nil;
    [self newConnection:nil];
}

- (void)newConnection:(id)sender
{
    if (!ssh_rng_ready()) return;
    NSLog(@"SecureShell: showing the New Connection panel");
    [connectController showPanel];
}

- (void)generateKey:(id)sender
{
    if (!ssh_rng_ready()) return;
    [keyGenController showPanel];
}

/* "Use This Key" in the result panel: prefill the connection panel with it. */
- (void)keyGenerated:(NSString *)privateKeyPath
{
    [connectController useKeyAtPath:privateKeyPath];
    [self newConnection:nil];
}

- (void)openSessionWithHost:(NSString *)host port:(int)port user:(NSString *)user keyPath:(NSString *)key openBrowser:(BOOL)browser
{
    SSHSession *s = [[SSHSession alloc] initWithHost:host port:port user:user keyPath:key
                                      knownHostsPath:knownHostsPath owner:self];
    [s setOpensBrowserOnLogin:browser];
    [sessions addObject:s];
    [s release];
    [s start];
}

/* "Open File Browser": use the session whose terminal or browser window is in front. */
- (void)openFileBrowser:(id)sender
{
    NSWindow *key = [NSApp keyWindow];
    SSHSession *target = nil;
    int i, active = 0;
    for (i = 0; i < (int)[sessions count]; i++) {
        SSHSession *s = [sessions objectAtIndex:i];
        if ([s isActive]) { active++; if (!target) target = s; }
        if ([s window] == key || [[s fileBrowser] window] == key) { target = s; active = 1; break; }
    }
    if (!target || active == 0) {
        NSRunAlertPanel(@"File browser", @"Connect to a server first; the file browser uses that connection.", @"OK", nil, nil);
        return;
    }
    [target openFileBrowser];
}

- (void)sessionDidEnd:(SSHSession *)session
{
    [[session retain] autorelease];                     /* it is still on the stack in windowWillClose: */
    [sessions removeObject:session];
}

- (BOOL)applicationShouldTerminate:(id)sender
{
    int i, active = 0;
    for (i = 0; i < (int)[sessions count]; i++)
        if ([[sessions objectAtIndex:i] isActive]) active++;
    if (active == 0) return YES;
    return NSRunAlertPanel(@"Quit Secure Shell?",
                           @"%d connection(s) are still open and will be disconnected.",
                           @"Quit", @"Cancel", nil, active) == NSAlertDefaultReturn;
}

@end
