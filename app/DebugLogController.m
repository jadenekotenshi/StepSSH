#import "DebugLogController.h"
#import "SSHSession.h"

/* gcc 2.7.2 does not look ahead within an @implementation, so anything called
 * before its definition must be declared here. */
@interface DebugLogController (Private)
- (void)buildWindow;
@end

@implementation DebugLogController

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
    NSScrollView *scroll;
    NSRect scr = [[NSScreen mainScreen] frame];

    window = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 520, 320)
                                         styleMask:(NSTitledWindowMask | NSClosableWindowMask |
                                                    NSMiniaturizableWindowMask | NSResizableWindowMask)
                                           backing:NSBackingStoreBuffered
                                             defer:NO];
    [window setReleasedWhenClosed:NO];
    [window setDelegate:(id)self];
    [window setMinSize:NSMakeSize(320, 160)];
    [window setTitle:[NSString stringWithFormat:@"Debug Log - %@", [session window] ? [[session window] title] : @""]];

    scroll = [[NSScrollView alloc] initWithFrame:[[window contentView] frame]];
    [scroll setHasVerticalScroller:YES];
    [scroll setBorderType:NSBezelBorder];
    [scroll setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];

    text = [[NSTextView alloc] initWithFrame:[[scroll contentView] frame]];
    [text setEditable:NO];
    [text setSelectable:YES];
    [text setRichText:NO];
    [text setFont:[NSFont userFixedPitchFontOfSize:11.0]];
    [text setVerticallyResizable:YES];
    [text setHorizontallyResizable:NO];
    [text setAutoresizingMask:NSViewWidthSizable];
    [text setMinSize:NSMakeSize(0, 0)];
    [text setMaxSize:NSMakeSize(1.0e7, 1.0e7)];
    [[text textContainer] setWidthTracksTextView:YES];

    [scroll setDocumentView:text];
    [text release];
    [[window contentView] addSubview:scroll];
    [scroll release];

    [window setFrameTopLeftPoint:NSMakePoint(scr.origin.x + 220 + offset, NSMaxY(scr) - 160 - offset)];
    offset += 24.0;
    if (offset > 240.0) offset = 0.0;
}

- (void)show { [window makeKeyAndOrderFront:nil]; }
- (void)closeWindow { [window setDelegate:nil]; [window orderOut:nil]; }

- (void)appendLine:(NSString *)line
{
    NSString *withNL = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    unsigned len = [[text textStorage] length];
    [text replaceCharactersInRange:NSMakeRange(len, 0) withString:withNL];
    [text scrollRangeToVisible:NSMakeRange([[text textStorage] length], 0)];
}

- (NSString *)logText { return [text string]; }

/* ---------------------------------------------------------------- */
/* window delegate                                                  */

- (void)windowWillClose:(NSNotification *)notification
{
    [window setDelegate:nil];
    [session debugLogControllerClosed:self];
}

@end
