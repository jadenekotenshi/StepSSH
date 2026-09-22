#import "Compat.h"
#include "vt.h"

/* Informal protocol implemented by whoever owns the terminal (SSHSession). */
@interface NSObject (TerminalViewDelegate)
- (void)terminalView:(id)tv sendBytes:(const unsigned char *)bytes length:(int)n;
- (void)terminalView:(id)tv resizedToCols:(int)cols rows:(int)rows;
@end

@interface TerminalView : NSView
{
    vt        *term;
    id         delegate;
    NSScroller *scroller;
    NSFont    *font;
    float      cellW, cellH, baseline;
    int        cols, rows;
    int        scrollBack;                 /* lines back from the live screen; 0 = live */
    int        selActive;
    int        selAnchorLine, selAnchorCol, selEndLine, selEndCol;
    int        lastCx, lastCy, lastSb;
    int        deleteSendsBackspace;       /* 1: Delete key sends ^H, 0: sends DEL */
    int        altSendsEscape;
    BOOL           pendingEsc;             /* diagnostic only: a lone, unmodified ESC keyDown just
                                             * happened; the very next keyDown logs how long after */
    NSTimeInterval pendingEscTime;
    NSColor   *defaultFg, *defaultBg;
    NSColor   *palette[256];
}
- (id)initWithFrame:(NSRect)frame;
- (void)setDelegate:(id)anObject;
- (void)setScroller:(NSScroller *)aScroller;
- (vt *)terminal;
- (NSSize)contentSizeForCols:(int)c rows:(int)r;
- (void)writeBytes:(const unsigned char *)bytes length:(int)n;
- (void)fitToFrame;                        /* recompute cols/rows after the view was resized */
- (void)scrollerMoved:(id)sender;
- (void)setUTF8:(BOOL)flag;
- (void)copy:(id)sender;
- (void)paste:(id)sender;
- (void)selectAll:(id)sender;
- (void)clearScrollback:(id)sender;
- (NSString *)selectedText;
@end
