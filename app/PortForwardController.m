#import "PortForwardController.h"
#import "PortForward.h"
#import "SSHSession.h"
#import "UIHelpers.h"
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/* "Add..." panel: local port, remote host, remote port -- more fields than PromptPanel offers, so   */
/* built here directly, the same way PromptPanel itself builds a modal panel and runs it.            */

@interface AddForwardRunner : NSObject
- (void)ok:(id)sender;
- (void)cancel:(id)sender;
@end
@implementation AddForwardRunner
- (void)ok:(id)sender     { [NSApp stopModalWithCode:1]; }
- (void)cancel:(id)sender { [NSApp stopModalWithCode:0]; }
@end

/* Returns YES and fills lp/rh/rp if the user filled in a valid rule; NO if they cancelled or
 * clicked OK with something invalid (which also shows the specific alert). */
static BOOL run_add_panel(int *lp, NSString **rh, int *rp)
{
    AddForwardRunner *runner = [[AddForwardRunner alloc] init];
    NSPanel *panel = [[NSPanel alloc] initWithContentRect:NSMakeRect(0, 0, 360, 190)
                                                styleMask:NSTitledWindowMask
                                                  backing:NSBackingStoreBuffered
                                                    defer:NO];
    NSTextField *lpLabel = ui_label(@"Local port:", NSMakeRect(16, 148, 100, 20));
    NSTextField *lpField = ui_field(NSMakeRect(120, 146, 100, 22));
    NSTextField *rhLabel = ui_label(@"Forward to host:", NSMakeRect(16, 112, 100, 20));
    NSTextField *rhField = ui_field(NSMakeRect(120, 110, 224, 22));
    NSTextField *rpLabel = ui_label(@"... and port:", NSMakeRect(16, 76, 100, 20));
    NSTextField *rpField = ui_field(NSMakeRect(120, 74, 100, 22));
    NSButton *ok = ui_button(@"OK", NSMakeRect(266, 12, 78, 30), runner, @selector(ok:));
    NSButton *cancel = ui_button(@"Cancel", NSMakeRect(180, 12, 78, 30), runner, @selector(cancel:));
    BOOL result = NO;
    int code, lport = 0, rport = 0;
    NSString *rhost;

    [panel setTitle:@"Add Port Forward"];
    [panel setHidesOnDeactivate:NO];
    [ok setKeyEquivalent:@"\r"];
    [rhField setStringValue:@"localhost"];
    { NSView *c = [panel contentView];
      [c addSubview:lpLabel]; [c addSubview:lpField]; [c addSubview:rhLabel]; [c addSubview:rhField];
      [c addSubview:rpLabel]; [c addSubview:rpField]; [c addSubview:ok]; [c addSubview:cancel]; }
    [panel center];
    [panel makeKeyAndOrderFront:nil];
    [panel makeFirstResponder:lpField];

    code = [NSApp runModalForWindow:panel];
    [panel orderOut:nil];
    if (code == 1) {
        lport = [ui_trim([lpField stringValue]) intValue];
        rhost = ui_trim([rhField stringValue]);
        rport = [ui_trim([rpField stringValue]) intValue];
        if (lport < 1 || lport > 65535) {
            NSRunAlertPanel(@"Add Port Forward", @"The local port must be between 1 and 65535.", @"OK", nil, nil);
        } else if ([rhost length] == 0) {
            NSRunAlertPanel(@"Add Port Forward", @"Enter a host to forward to.", @"OK", nil, nil);
        } else if (rport < 1 || rport > 65535) {
            NSRunAlertPanel(@"Add Port Forward", @"The remote port must be between 1 and 65535.", @"OK", nil, nil);
        } else {
            *lp = lport; *rh = rhost; *rp = rport;
            result = YES;
        }
    }
    [panel release];
    [runner release];
    return result;
}

/* ------------------------------------------------------------------ */

@interface PortForwardController (Private)
- (void)buildWindow;
@end

@implementation PortForwardController

- (id)initWithSession:(SSHSession *)s
{
    self = [super init];
    if (!self) return nil;
    session = s;
    [self buildWindow];
    return self;
}

- (void)dealloc
{
    [window setDelegate:nil];
    [window release];
    [super dealloc];
}

- (NSWindow *)window { return window; }

- (void)buildWindow
{
    static float offset = 0.0;
    NSView *c;
    NSScrollView *scroll;
    NSTableColumn *col;
    NSRect scr = [[NSScreen mainScreen] frame];
    NSString *colIdent[3], *colTitle[3];
    float colWidth[3];
    int i;

    colIdent[0] = @"local";  colTitle[0] = @"Local Port";      colWidth[0] = 90;
    colIdent[1] = @"remote"; colTitle[1] = @"Forwards To";     colWidth[1] = 240;
    colIdent[2] = @"count";  colTitle[2] = @"Connections";     colWidth[2] = 100;

    window = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 460, 300)
                                         styleMask:(NSTitledWindowMask | NSClosableWindowMask |
                                                    NSMiniaturizableWindowMask | NSResizableWindowMask)
                                           backing:NSBackingStoreBuffered
                                             defer:NO];
    [window setReleasedWhenClosed:NO];
    [window setDelegate:(id)self];
    [window setMinSize:NSMakeSize(360, 200)];
    [window setTitle:[NSString stringWithFormat:@"Port Forwarding - %@", [session window] ? [[session window] title] : @""]];
    c = [window contentView];

    table = [[[NSTableView alloc] initWithFrame:NSMakeRect(0, 0, 440, 220)] autorelease];
    for (i = 0; i < 3; i++) {
        col = [[[NSTableColumn alloc] initWithIdentifier:colIdent[i]] autorelease];
        [[col headerCell] setStringValue:colTitle[i]];
        [col setWidth:colWidth[i]];
        [col setEditable:NO];
        if (i == 2) [[col dataCell] setAlignment:NSRightTextAlignment];
        [table addTableColumn:col];
    }
    [table setDataSource:(id)self];
    [table setAllowsMultipleSelection:NO];
    scroll = [[[NSScrollView alloc] initWithFrame:NSMakeRect(8, 48, 444, 244)] autorelease];
    [scroll setHasVerticalScroller:YES];
    [scroll setBorderType:NSBezelBorder];
    [scroll setDocumentView:table];
    [scroll setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];
    [c addSubview:scroll];

    addBtn = ui_button(@"Add...", NSMakeRect(8, 8, 90, 26), self, @selector(add:));
    removeBtn = ui_button(@"Remove", NSMakeRect(104, 8, 90, 26), self, @selector(remove:));
    [addBtn setAutoresizingMask:NSViewMaxYMargin];
    [removeBtn setAutoresizingMask:NSViewMaxYMargin];
    [c addSubview:addBtn]; [c addSubview:removeBtn];

    [window setFrameTopLeftPoint:NSMakePoint(scr.origin.x + 160 + offset, NSMaxY(scr) - 120 - offset)];
    offset += 24.0;
    if (offset > 240.0) offset = 0.0;
}

- (void)show { [window makeKeyAndOrderFront:nil]; [table reloadData]; }
- (void)closeWindow { [window setDelegate:nil]; [window orderOut:nil]; }
- (void)reload { [table reloadData]; }

- (void)add:(id)sender
{
    int lp, rp;
    NSString *rh;
    PortForward *pf;
    if (![session isActive]) return;
    if (!run_add_panel(&lp, &rh, &rp)) return;
    pf = [session addForwardWithLocalPort:lp remoteHost:rh remotePort:rp];
    if (!pf) {
        NSRunAlertPanel(@"Add Port Forward", @"Could not start listening on port %d.", @"OK", nil, nil, lp);
        return;
    }
    [table reloadData];
}

- (void)remove:(id)sender
{
    int row = [table selectedRow];
    NSArray *fwds;
    if (row < 0) { NSRunAlertPanel(@"Remove", @"Select a forward to remove.", @"OK", nil, nil); return; }
    fwds = [session portForwards];
    if (row >= (int)[fwds count]) return;
    [session removeForward:[fwds objectAtIndex:row]];
    [table reloadData];
}

/* ---------------------------------------------------------------- */
/* table data source                                                */

- (int)numberOfRowsInTableView:(NSTableView *)tv { return (int)[[session portForwards] count]; }

- (id)tableView:(NSTableView *)tv objectValueForTableColumn:(NSTableColumn *)col row:(int)row
{
    NSArray *fwds = [session portForwards];
    PortForward *pf;
    NSString *ident = [col identifier];
    if (row < 0 || row >= (int)[fwds count]) return @"";
    pf = [fwds objectAtIndex:row];
    if ([ident isEqual:@"local"]) return [NSString stringWithFormat:@"%d", pf->localPort];
    if ([ident isEqual:@"remote"]) return [NSString stringWithFormat:@"%@:%d", pf->remoteHost, pf->remotePort];
    if ([ident isEqual:@"count"]) return [NSString stringWithFormat:@"%d", (int)[pf->tunnels count]];
    return @"";
}

/* ---------------------------------------------------------------- */
/* window delegate                                                  */

- (void)windowWillClose:(NSNotification *)notification
{
    [window setDelegate:nil];
    [session portForwardControllerClosed:self];
}

@end
