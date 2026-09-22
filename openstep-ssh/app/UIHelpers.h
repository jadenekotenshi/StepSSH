#import "Compat.h"

/* Small control factories shared by the hand-built panels.  All return autoreleased objects. */
NSTextField *ui_label(NSString *text, NSRect frame);
NSTextField *ui_wrapping_label(NSString *text, NSRect frame, BOOL selectable);
NSTextField *ui_field(NSRect frame);
NSButton    *ui_switch(NSString *title, NSRect frame);
NSButton    *ui_button(NSString *title, NSRect frame, id target, SEL action);
NSString    *ui_trim(NSString *s);          /* OpenStep has no NSString trimming method, so this is hand-written */

/* Remote names are UTF-8 bytes.  NSString +stringWithCString: would read them as NeXTSTEP text,
 * so decode by hand (invalid bytes fall back to Latin-1) and encode with NUL termination. */
NSString *ui_string_from_utf8(const char *bytes);
NSData   *ui_utf8_cstring(NSString *s);              /* bytes of s in UTF-8 plus a trailing NUL */
#define UI_CPATH(s) ((const char *)[ui_utf8_cstring(s) bytes])

NSString *ui_format_size(unsigned long long n);       /* "1.5 MB" */
NSString *ui_format_time(unsigned secs_since_1970);   /* "2026-09-21 15:04" in local time */
NSString *ui_format_mode(unsigned perms);             /* "drwxr-xr-x" */
