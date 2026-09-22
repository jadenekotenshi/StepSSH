/*
 * ui_smoke.m -- runs the Objective-C UI setup code on the development Mac (modern
 * AppKit, PostScript calls stubbed).  It cannot prove OPENSTEP behaviour, but it
 * does execute code the syntax check only parses: menu construction, panel
 * construction, the terminal view's geometry, drawing and selection.
 * Nothing is ordered on screen and the clipboard is not touched.
 */
#import "Compat.h"
#import "AppController.h"
#import "ConnectController.h"
#import "TerminalView.h"
#import "KeyGenController.h"
#import "UIHelpers.h"
#include "ssh_key.h"
#include "rng.h"
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>

/* ---- host stand-ins for OPENSTEP-only calls ---- */
static char shown[64][128];
static float shown_x[64], shown_y[64];
static int n_shown;
static float pen_x, pen_y;
void PSmoveto(float x, float y) { pen_x = x; pen_y = y; }
void PSshow(const char *s)
{
    if (n_shown < 64) { strncpy(shown[n_shown], s, 127); shown[n_shown][127] = 0; shown_x[n_shown] = pen_x; shown_y[n_shown] = pen_y; n_shown++; }
}
@implementation NSFont (OpenStepHostStub)
- (float)widthOfString:(NSString *)s { return [self maximumAdvancement].width; }
@end

@interface ConnectController (SmokePrivate) - (void)buildPanel; @end

static int pass, fail;

static void trace_to(NSString *path, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    SSTraceV(path, fmt, ap);
    va_end(ap);
}
#define EXPECT(cond, what) do { if (cond) pass++; else { fail++; printf("  FAIL: %s\n", what); } } while (0)

static int shown_contains(const char *text)
{
    int i;
    for (i = 0; i < n_shown; i++) if (strstr(shown[i], text)) return 1;
    return 0;
}

int main(int argc, char *argv[])
{
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    AppController *app;
    ConnectController *cc;
    TerminalView *tv;
    NSImage *img;
    vt *t;
    NSString *sel;
    NSSize sz;
    KeyGenController *kg;

    ssh_rng_seed_system();

    NS_DURING
        [NSApplication sharedApplication];

        /* 1. menus */
        app = [[AppController alloc] init];
        [app buildMenu];
        EXPECT([NSApp mainMenu] != nil && [[NSApp mainMenu] numberOfItems] >= 6, "main menu built with its items");
        EXPECT([NSApp windowsMenu] != nil, "Windows menu registered");
        EXPECT([[NSApp mainMenu] itemWithTitle:@"Edit"] != nil, "Edit menu present");

        /* 2. connection panel (built, never shown) */
        cc = [[ConnectController alloc] initWithOwner:app];
        [cc buildPanel];
        EXPECT(1, "connection panel built");
        {   /* layout: no two controls overlap, and each label/button is big enough for its own text */
            NSPanel *panel = [cc valueForKey:@"panel"];
            NSArray *subs = [[panel contentView] subviews];
            int i, j, overlaps = 0, cramped = 0;
            for (i = 0; i < (int)[subs count]; i++) {
                NSView *a = [subs objectAtIndex:i];
                NSRect fa = [a frame];
                for (j = i + 1; j < (int)[subs count]; j++)
                    if (NSIntersectsRect(fa, [[subs objectAtIndex:j] frame])) {
                        overlaps++;
                        printf("    overlap: %s vs %s\n", [[a description] cString], [[[subs objectAtIndex:j] description] cString]);
                    }
                if ([a isKindOfClass:[NSButton class]] ||
                    ([a isKindOfClass:[NSTextField class]] && ![(NSTextField *)a isEditable])) {
                    NSSize need = [[(NSControl *)a cell] cellSize];
                    if (need.width > fa.size.width + 2.0 || need.height > fa.size.height + 2.0) {
                        cramped++;
                        printf("    too small for its text: %s (needs %.0fx%.0f, has %.0fx%.0f)\n",
                               [[(NSControl *)a stringValue] cString], need.width, need.height,
                               fa.size.width, fa.size.height);
                    }
                }
                EXPECT(NSMinX(fa) >= 0 && NSMaxX(fa) <= [[panel contentView] bounds].size.width &&
                       NSMinY(fa) >= 0 && NSMaxY(fa) <= [[panel contentView] bounds].size.height,
                       "every control lies inside the panel");
            }
            EXPECT(overlaps == 0, "no two controls in the connection panel overlap");
            EXPECT(cramped == 0, "every label and button is large enough for its text");
            EXPECT([subs count] >= 14, "the panel has all of its controls");
        }

        /* 2b. key generation: the real code path, without the dialogs */
        kg = [[KeyGenController alloc] initWithOwner:app];
        {
            NSString *dir = [NSString stringWithCString:(argc > 1 ? argv[1] : "/tmp")];
            NSString *path = [dir stringByAppendingPathComponent:@"ui_smoke_key"];
            NSString *err;
            NSData *raw;
            struct stat st;
            ssh_key k;
            const char *perr;

            remove([path cString]); remove([[path stringByAppendingString:@".pub"] cString]);
            err = [kg generateToPath:path comment:@"smoke@test" passphrase:"smoke phrase"];
            EXPECT(err == nil, "a key is generated and written");
            EXPECT(stat([path cString], &st) == 0 && (st.st_mode & 077) == 0, "private key is not readable by others (0600)");
            EXPECT(stat([[path stringByAppendingString:@".pub"] cString], &st) == 0, "public key file written");
            raw = [NSData dataWithContentsOfFile:path];
            EXPECT(raw != nil && ssh_key_parse_private((const char *)[raw bytes], [raw length], "smoke phrase", &k, &perr) == 0,
                   "the written private key decrypts with the passphrase");
            EXPECT(ssh_key_parse_private((const char *)[raw bytes], [raw length], "wrong", &k, &perr) == -3, "and not with another");
            EXPECT([[kg lastPublicLine] hasPrefix:@"ssh-ed25519 "] && [[kg lastPublicLine] hasSuffix:@"smoke@test"],
                   "public line has the type and comment");
            EXPECT([[kg lastFingerprint] hasPrefix:@"SHA256:"], "fingerprint reported");
            EXPECT([[kg installCommand] rangeOfString:@"authorized_keys"].length > 0 &&
                   [[kg installCommand] rangeOfString:[kg lastPublicLine]].length > 0, "install command embeds the public key");
            err = [kg generateToPath:path comment:@"x" passphrase:""];
            EXPECT(err != nil && [err rangeOfString:@"already exists"].length > 0, "an existing key is never overwritten");
            err = [kg generateToPath:[dir stringByAppendingPathComponent:@"ui_smoke_key2"] comment:@"bad'; rm -rf ~; '" passphrase:""];
            EXPECT(err != nil, "a comment that could inject shell syntax is refused");
            remove([path cString]); remove([[path stringByAppendingString:@".pub"] cString]);
        }

        /* 2c. startup trace: opt-in by the existence of the trace file (SSTraceV is SSTrace with a chosen path) */
        {
            NSString *dir = [NSString stringWithCString:(argc > 1 ? argv[1] : "/tmp")];
            NSString *tr = [dir stringByAppendingPathComponent:@"ui_smoke.trace"];
            NSString *text;
            struct stat st;

            remove([tr cString]);
            trace_to(tr, "must not be written: %d", 1);
            EXPECT(stat([tr cString], &st) != 0, "the trace does nothing, and creates nothing, when the trace file is absent");
            fclose(fopen([tr cString], "w"));                          /* the user runs: touch ~/.SecureShell.trace */
            trace_to(tr, "first %s %d", "line", 7);
            trace_to(tr, "second");
            text = [NSString stringWithContentsOfFile:tr];
            EXPECT([text isEqualToString:@"first line 7\nsecond\n"], "the trace appends one line per call to an existing file");
            EXPECT(strcmp(SSCS(nil), "(nil)") == 0 && strcmp(SSCS(@"x"), "x") == 0, "SSCS is nil-safe");
            remove([tr cString]);
        }

        /* 3. terminal view: geometry */
        tv = [[TerminalView alloc] initWithFrame:NSMakeRect(0, 0, 100, 100)];
        sz = [tv contentSizeForCols:80 rows:24];
        [tv setFrame:NSMakeRect(0, 0, sz.width, sz.height)];
        t = [tv terminal];
        EXPECT(t->cols == 80 && t->rows == 24, "80x24 terminal from a 80x24-cell frame");
        [tv setFrame:NSMakeRect(0, 0, sz.width * 1.5, sz.height * 0.5)];
        EXPECT(t->cols > 80 && t->rows < 24, "resizing the view resizes the terminal");
        [tv setFrame:NSMakeRect(0, 0, sz.width, sz.height)];
        EXPECT(t->cols == 80 && t->rows == 24, "and back again");

        /* 4. terminal view: feed output, draw offscreen, check what would be painted */
        [tv writeBytes:(const unsigned char *)"hello\r\n\033[1;31mred\033[0m \033[4mul\033[0m\r\n\033[7mrev\033[0m" length:44];
        img = [[NSImage alloc] initWithSize:sz];
        [img lockFocus];
        n_shown = 0;
        [tv drawRect:[tv bounds]];
        [img unlockFocus];
        EXPECT(shown_contains("hello"), "row 0 text reaches PSshow");
        EXPECT(shown_contains("red"), "coloured text drawn");
        EXPECT(shown_contains("rev"), "reverse-video text drawn");
        {   /* row 0 must be above row 1 on screen (non-flipped view: larger y = higher) */
            float y0 = -1, y1 = -1; int i;
            for (i = 0; i < n_shown; i++) {
                if (!strcmp(shown[i], "hello")) y0 = shown_y[i];
                if (strstr(shown[i], "red")) y1 = shown_y[i];
            }
            EXPECT(y0 > y1 && y1 > 0, "rows are laid out top to bottom");
        }
        EXPECT(n_shown < 60, "drawing a mostly empty screen issues few text calls (runs, not cells)");

        /* 5. selection */
        [tv selectAll:nil];
        sel = [tv selectedText];
        EXPECT(sel != nil && [sel hasPrefix:@"hello\nred ul\nrev"], "select-all yields the visible text");

        /* 6. scrollback bookkeeping while output continues */
        {
            int i;
            for (i = 0; i < 100; i++) [tv writeBytes:(const unsigned char *)"line\r\n" length:6];
            EXPECT(vt_scrollback_count(t) > 70, "output scrolls into the scrollback");
            img = [[NSImage alloc] initWithSize:sz];
            [img lockFocus]; [tv drawRect:[tv bounds]]; [img unlockFocus];
            EXPECT(1, "drawing with scrollback present does not crash");
        }
    NS_HANDLER
        printf("  FAIL: uncaught exception: %s -- %s\n", [[localException name] cString], [[localException reason] cString]);
        fail++;
    NS_ENDHANDLER

    printf("ui smoke: %d passed, %d failed\n", pass, fail);
    [pool release];
    return fail ? 1 : 0;
}
