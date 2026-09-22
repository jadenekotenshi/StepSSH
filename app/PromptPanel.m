#import "PromptPanel.h"
#import "SecretField.h"
#include <string.h>
#include <stdlib.h>
#include "rng.h"

@interface PromptRunner : NSObject
- (void)ok:(id)sender;
- (void)cancel:(id)sender;
@end

@implementation PromptRunner
- (void)ok:(id)sender     { [NSApp stopModalWithCode:1]; }
- (void)cancel:(id)sender { [NSApp stopModalWithCode:0]; }
@end

@implementation PromptPanel

+ (NSPanel *)panelWithTitle:(NSString *)title prompt:(NSString *)prompt
                      field:(NSView *)field runner:(PromptRunner *)runner
{
    NSPanel *panel = [[NSPanel alloc] initWithContentRect:NSMakeRect(0, 0, 380, 132)
                                                styleMask:NSTitledWindowMask
                                                  backing:NSBackingStoreBuffered
                                                    defer:NO];
    NSTextField *label = [[NSTextField alloc] initWithFrame:NSMakeRect(16, 88, 348, 30)];
    NSButton *ok = [[NSButton alloc] initWithFrame:NSMakeRect(286, 12, 78, 30)];
    NSButton *cancel = [[NSButton alloc] initWithFrame:NSMakeRect(200, 12, 78, 30)];

    [panel setTitle:title];
    [panel setHidesOnDeactivate:NO];
    [label setStringValue:prompt];
    [label setEditable:NO];
    [label setSelectable:NO];
    [label setBezeled:NO];
    [label setBordered:NO];
    [label setDrawsBackground:NO];
    [field setFrame:NSMakeRect(16, 56, 348, 24)];
    [ok setTitle:@"OK"];
    [ok setTarget:runner];
    [ok setAction:@selector(ok:)];
    [ok setKeyEquivalent:@"\r"];
    [cancel setTitle:@"Cancel"];
    [cancel setTarget:runner];
    [cancel setAction:@selector(cancel:)];
    [[panel contentView] addSubview:label];
    [[panel contentView] addSubview:field];
    [[panel contentView] addSubview:ok];
    [[panel contentView] addSubview:cancel];
    [label release]; [ok release]; [cancel release];
    [panel center];
    return [panel autorelease];
}

+ (char *)askSecret:(NSString *)prompt title:(NSString *)title
{
    PromptRunner *runner = [[PromptRunner alloc] init];
    SecretField *field = [[SecretField alloc] initWithFrame:NSMakeRect(0, 0, 10, 10)];
    NSPanel *panel = [self panelWithTitle:title prompt:prompt field:field runner:runner];
    char *result = NULL;
    int code;

    [field setEnterTarget:runner action:@selector(ok:)];
    [field setCancelTarget:runner action:@selector(cancel:)];

    [panel makeKeyAndOrderFront:nil];
    [panel makeFirstResponder:field];
    code = [NSApp runModalForWindow:panel];
    [panel orderOut:nil];
    if (code == 1) result = [field takeSecret];
    [field wipe];
    [field release];
    [runner release];
    return result;
}

+ (NSString *)askText:(NSString *)prompt title:(NSString *)title
{
    return [self askText:prompt title:title initial:@""];
}

+ (NSString *)askText:(NSString *)prompt title:(NSString *)title initial:(NSString *)initial
{
    PromptRunner *runner = [[PromptRunner alloc] init];
    NSTextField *field = [[NSTextField alloc] initWithFrame:NSMakeRect(0, 0, 10, 10)];
    NSPanel *panel = [self panelWithTitle:title prompt:prompt field:field runner:runner];
    NSString *result = nil;
    int code;

    [field setTarget:runner];
    [field setAction:@selector(ok:)];
    [field setStringValue:initial ? initial : @""];
    [panel makeKeyAndOrderFront:nil];
    [panel makeFirstResponder:field];
    [field selectText:nil];
    code = [NSApp runModalForWindow:panel];
    [panel orderOut:nil];
    if (code == 1) result = [[[field stringValue] copy] autorelease];
    [field release];
    [runner release];
    return result;
}

@end
