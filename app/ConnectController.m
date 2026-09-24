#import "ConnectController.h"
#import "UIHelpers.h"
#include "wire.h"

#define DEFAULTS_KEY @"SavedHosts"

/* gcc 2.7.2 does not look ahead within an @implementation, so anything called
 * before its definition must be declared here. */
@interface ConnectController (Private)
- (void)buildPanel;
- (void)reloadSaved;
@end

@implementation ConnectController

- (id)initWithOwner:(id)anOwner
{
    NSArray *saved;
    self = [super init];
    if (!self) return nil;
    owner = anOwner;
    saved = [[NSUserDefaults standardUserDefaults] arrayForKey:DEFAULTS_KEY];
    profiles = saved ? [[NSMutableArray alloc] initWithArray:saved] : [[NSMutableArray alloc] init];
    return self;
}

- (void)dealloc
{
    [panel release];
    [profiles release];
    [super dealloc];
}

- (void)buildPanel
{
    NSView *c;
    NSButton *connectBtn, *cancelBtn, *delBtn;
    NSString *defKey = [NSHomeDirectory() stringByAppendingPathComponent:@".ssh/id_ed25519"];
    BOOL haveDefKey = [[NSFileManager defaultManager] fileExistsAtPath:defKey];
    /* Column plan: labels 14..94, fields 100..406.  Every row is 34 high. The three X11 rows sit
     * right above the button row (their own labels/fields following the same column plan, except
     * the "Cookie" label, which needs more width than 80 for its longer text); every other row
     * is the original layout shifted up 102 (three rows' worth) to make room. */

    panel = [[NSPanel alloc] initWithContentRect:NSMakeRect(0, 0, 420, 422)
                                       styleMask:(NSTitledWindowMask | NSClosableWindowMask)
                                         backing:NSBackingStoreBuffered
                                           defer:NO];
    [panel setTitle:@"New Connection"];
    [panel setReleasedWhenClosed:NO];
    [panel setHidesOnDeactivate:NO];          /* an NSPanel otherwise hides while another app is active */
    c = [panel contentView];

    [c addSubview:ui_label(@"Saved:", NSMakeRect(14, 384, 80, 20))];
    savedPopup = [[NSPopUpButton alloc] initWithFrame:NSMakeRect(100, 382, 222, 24) pullsDown:NO];
    [savedPopup setTarget:self];
    [savedPopup setAction:@selector(savedChosen:)];
    [c addSubview:savedPopup];
    delBtn = [[[NSButton alloc] initWithFrame:NSMakeRect(330, 380, 76, 26)] autorelease];
    [delBtn setTitle:@"Delete"];
    [delBtn setTarget:self];
    [delBtn setAction:@selector(deleteSaved:)];
    [c addSubview:delBtn];

    [c addSubview:ui_label(@"Host:", NSMakeRect(14, 348, 80, 20))];
    hostField = ui_field(NSMakeRect(100, 346, 196, 22));
    [c addSubview:hostField];
    [c addSubview:ui_label(@"Port:", NSMakeRect(304, 348, 36, 20))];
    portField = ui_field(NSMakeRect(342, 346, 64, 22));
    [portField setStringValue:@"22"];
    [c addSubview:portField];

    [c addSubview:ui_label(@"User:", NSMakeRect(14, 314, 80, 20))];
    userField = ui_field(NSMakeRect(100, 312, 306, 22));
    [userField setStringValue:NSUserName()];
    [c addSubview:userField];

    useKeyBox = ui_switch(@"Log in with a key file", NSMakeRect(14, 278, 392, 22));
    [useKeyBox retain];
    [useKeyBox setState:haveDefKey ? 1 : 0];
    [c addSubview:useKeyBox];

    [c addSubview:ui_label(@"Key file:", NSMakeRect(14, 246, 80, 20))];
    keyField = ui_field(NSMakeRect(100, 244, 306, 22));
    [keyField setStringValue:haveDefKey ? defKey : @""];
    [c addSubview:keyField];

    saveBox = ui_switch(@"Remember this host", NSMakeRect(14, 212, 392, 22));
    [saveBox retain];
    [c addSubview:saveBox];

    browserBox = ui_switch(@"Open the file browser after logging in", NSMakeRect(14, 182, 392, 22));
    [browserBox retain];
    [c addSubview:browserBox];

    verboseBox = ui_switch(@"Verbose logging (for troubleshooting)", NSMakeRect(14, 152, 392, 22));
    [verboseBox retain];
    [c addSubview:verboseBox];

    x11Box = ui_switch(@"Forward X11", NSMakeRect(14, 118, 392, 22));
    [x11Box retain];
    [c addSubview:x11Box];

    [c addSubview:ui_label(@"Display:", NSMakeRect(14, 84, 80, 20))];
    x11HostField = ui_field(NSMakeRect(100, 82, 196, 22));
    [x11HostField setStringValue:@"127.0.0.1"];
    [c addSubview:x11HostField];
    [c addSubview:ui_label(@"Port:", NSMakeRect(304, 84, 36, 20))];
    x11PortField = ui_field(NSMakeRect(342, 82, 64, 22));
    [x11PortField setStringValue:@"6000"];
    [c addSubview:x11PortField];

    [c addSubview:ui_label(@"Cookie (hex, optional):", NSMakeRect(14, 50, 180, 20))];
    x11CookieField = ui_field(NSMakeRect(200, 48, 206, 22));
    [c addSubview:x11CookieField];

    connectBtn = [[[NSButton alloc] initWithFrame:NSMakeRect(328, 16, 78, 30)] autorelease];
    [connectBtn setTitle:@"Connect"];
    [connectBtn setTarget:self];
    [connectBtn setAction:@selector(connect:)];
    [connectBtn setKeyEquivalent:@"\r"];
    [c addSubview:connectBtn];
    cancelBtn = [[[NSButton alloc] initWithFrame:NSMakeRect(242, 16, 78, 30)] autorelease];
    [cancelBtn setTitle:@"Cancel"];
    [cancelBtn setTarget:self];
    [cancelBtn setAction:@selector(cancel:)];
    [c addSubview:cancelBtn];

    [hostField setNextKeyView:portField];
    [portField setNextKeyView:userField];
    [userField setNextKeyView:keyField];
    [keyField setNextKeyView:hostField];
    [panel setInitialFirstResponder:hostField];
    [panel center];
    [self reloadSaved];
}

- (void)reloadSaved
{
    int i;
    [savedPopup removeAllItems];
    [savedPopup addItemWithTitle:@"(new connection)"];
    for (i = 0; i < (int)[profiles count]; i++) {
        NSDictionary *d = [profiles objectAtIndex:i];
        [savedPopup addItemWithTitle:[NSString stringWithFormat:@"%@@%@",
                                      [d objectForKey:@"user"], [d objectForKey:@"host"]]];
    }
}

- (void)showPanel
{
    if (!panel) [self buildPanel];
    [panel makeKeyAndOrderFront:nil];
    NSLog(@"StepSSH: New Connection panel ordered front (visible: %d)", (int)[panel isVisible]);
    [panel makeFirstResponder:hostField];
}

- (void)savedChosen:(id)sender
{
    int i = [savedPopup indexOfSelectedItem] - 1;
    NSDictionary *d;
    NSString *k, *xh, *xp, *xc;
    if (i < 0 || i >= (int)[profiles count]) return;
    d = [profiles objectAtIndex:i];
    [hostField setStringValue:[d objectForKey:@"host"]];
    [portField setStringValue:[d objectForKey:@"port"]];
    [userField setStringValue:[d objectForKey:@"user"]];
    k = [d objectForKey:@"key"];
    [keyField setStringValue:k ? k : @""];
    [useKeyBox setState:(k && [k length]) ? 1 : 0];

    /* An older saved profile (from before X11 forwarding existed) simply has none of these keys
     * -- [d objectForKey:@"x11"] and friends come back nil, and every field below falls back to
     * its own ordinary default rather than misbehaving. */
    [x11Box setState:[[d objectForKey:@"x11"] isEqual:@"1"] ? 1 : 0];
    xh = [d objectForKey:@"x11Host"];
    [x11HostField setStringValue:(xh && [xh length]) ? xh : @"127.0.0.1"];
    xp = [d objectForKey:@"x11Port"];
    [x11PortField setStringValue:(xp && [xp length]) ? xp : @"6000"];
    xc = [d objectForKey:@"x11Cookie"];
    [x11CookieField setStringValue:xc ? xc : @""];
}

- (void)deleteSaved:(id)sender
{
    int i = [savedPopup indexOfSelectedItem] - 1;
    if (i < 0 || i >= (int)[profiles count]) return;
    [profiles removeObjectAtIndex:i];
    [[NSUserDefaults standardUserDefaults] setObject:profiles forKey:DEFAULTS_KEY];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [self reloadSaved];
}

- (void)cancel:(id)sender { [panel orderOut:nil]; }

- (void)useKeyAtPath:(NSString *)path
{
    if (!panel) [self buildPanel];
    [keyField setStringValue:path];
    [useKeyBox setState:1];
}

- (void)connect:(id)sender
{
    NSString *h = ui_trim([hostField stringValue]);
    NSString *u = ui_trim([userField stringValue]);
    NSString *k = [useKeyBox state] ? [keyField stringValue] : @"";
    int p = [[portField stringValue] intValue];
    BOOL x11 = [x11Box state] ? YES : NO;
    NSString *x11Host = ui_trim([x11HostField stringValue]);
    int x11Port = [[x11PortField stringValue] intValue];
    NSString *x11Cookie = ui_trim([x11CookieField stringValue]);

    if ([h length] == 0 || [u length] == 0) {
        NSRunAlertPanel(@"Missing information", @"Enter a host name and a user name.", @"OK", nil, nil);
        return;
    }
    if (p < 1 || p > 65535) {
        NSRunAlertPanel(@"Bad port", @"The port must be a number from 1 to 65535.", @"OK", nil, nil);
        return;
    }
    if (x11) {
        if (x11Port < 1 || x11Port > 65535) {
            NSRunAlertPanel(@"Bad X11 display port", @"The X11 display port must be a number from 1 to 65535.",
                            @"OK", nil, nil);
            return;
        }
        if ([x11Cookie length] != 0 && [x11Cookie length] != 32) {
            NSRunAlertPanel(@"Bad X11 cookie",
                            @"The X11 cookie must be exactly 32 hex characters (16 bytes), or left empty.",
                            @"OK", nil, nil);
            return;
        }
        if ([x11Cookie length] == 32) {
            u8 raw[16];
            if (hex_decode([x11Cookie cString], 32, raw, sizeof(raw)) != 16) {
                NSRunAlertPanel(@"Bad X11 cookie", @"The X11 cookie must be 32 valid hex characters.",
                                @"OK", nil, nil);
                return;
            }
        }
    }
    if ([saveBox state]) {
        NSDictionary *d = [NSDictionary dictionaryWithObjectsAndKeys:
            h, @"host", [NSString stringWithFormat:@"%d", p], @"port", u, @"user", k, @"key",
            (x11 ? @"1" : @"0"), @"x11", x11Host, @"x11Host",
            [NSString stringWithFormat:@"%d", x11Port], @"x11Port", x11Cookie, @"x11Cookie", nil];
        int i;
        for (i = 0; i < (int)[profiles count]; i++) {                 /* replace an existing entry */
            NSDictionary *o = [profiles objectAtIndex:i];
            if ([[o objectForKey:@"host"] isEqual:h] && [[o objectForKey:@"user"] isEqual:u]) {
                [profiles removeObjectAtIndex:i];
                break;
            }
        }
        [profiles addObject:d];
        [[NSUserDefaults standardUserDefaults] setObject:profiles forKey:DEFAULTS_KEY];
        [[NSUserDefaults standardUserDefaults] synchronize];
        [self reloadSaved];
    }
    [panel orderOut:nil];
    [owner openSessionWithHost:h port:p user:u keyPath:k
                    openBrowser:([browserBox state] ? YES : NO)
                        verbose:([verboseBox state] ? YES : NO)
                     x11Enabled:x11 x11DisplayHost:x11Host x11DisplayPort:x11Port x11Cookie:x11Cookie];
}

@end
