/*
 * vt.h -- VT100/xterm-subset terminal emulator core.
 *
 * Pure C89, no I/O, no AppKit: feed it bytes from the SSH channel with
 * vt_write(), read the screen through vt_cell()/vt_line_at(), and collect
 * anything it wants to say back to the host (DSR/DA replies) with
 * vt_take_output().  Rows that changed since the last vt_clear_dirty() are
 * flagged so a slow machine can redraw only what it must.
 */
#ifndef VT_H
#define VT_H

#include <stddef.h>

typedef unsigned char  vt_u8;
typedef unsigned short vt_u16;
typedef unsigned int   vt_u32;

#define VT_BOLD      0x01
#define VT_UNDERLINE 0x02
#define VT_REVERSE   0x04
#define VT_BLINK     0x08
#define VT_DIM       0x10
#define VT_ITALIC    0x20
#define VT_DEFFG     0x40      /* foreground is the terminal default (fg index ignored) */
#define VT_DEFBG     0x80      /* background is the terminal default */

typedef struct {
    vt_u16 ch;                 /* Unicode BMP code point (0x20 for blank) */
    vt_u8  fg, bg;             /* xterm 256-colour palette index */
    vt_u8  attr;
} vt_cell;

#define VT_MAXPARAMS 16
#define VT_OUTBUF    256
#define VT_TITLEMAX  128

typedef struct vt_pen { vt_u8 fg, bg, attr; } vt_pen;
typedef struct { int cx, cy, wrap_pending, origin, g0, g1, shift; vt_pen pen; } vt_saved;

typedef struct vt {
    int cols, rows;

    vt_cell **line;            /* visible screen: rows row pointers */
    vt_cell **main_line, **alt_line;
    int in_alt;
    vt_u8 *dirty;              /* per visible row */
    int all_dirty;

    int cx, cy;                /* cursor, 0-based */
    int wrap_pending;
    int top, bottom;           /* scroll region, inclusive, 0-based */
    vt_pen pen;
    vt_u8 *tabs;

    /* modes */
    int autowrap, origin, insert, newline_mode;
    int cursor_visible, reverse_screen;
    int app_cursor, app_keypad, bracketed_paste;
    int utf8;

    /* saved cursor (DECSC) and the one used by mode 1049 */
    vt_saved saved, saved_alt;

    /* character sets */
    int g0, g1, shift;         /* 0 = ASCII, 1 = DEC special graphics; shift 0 = G0, 1 = G1 */

    /* parser */
    int state;
    int params[VT_MAXPARAMS];
    int nparams;
    int have_param;
    int priv;                  /* private marker: '?', '>', '=', or 0 */
    int inter;                 /* first intermediate byte */
    vt_u32 utf8_cp;
    int utf8_left;
    char osc[VT_TITLEMAX + 8];
    int osc_len;

    /* scrollback ring (main screen only) */
    vt_cell **sb;
    int *sb_w;
    int sb_max, sb_count, sb_head;

    /* output to the host */
    vt_u8 out[VT_OUTBUF];
    int out_len;

    /* window title (OSC 0/2), and a flag so the UI knows to re-read it */
    char title[VT_TITLEMAX];
    int title_changed;
    int bell;                  /* set by BEL; UI clears it */
} vt;

vt  *vt_new(int cols, int rows, int scrollback_lines);
void vt_free(vt *t);
void vt_resize(vt *t, int cols, int rows);
void vt_reset(vt *t);
void vt_write(vt *t, const unsigned char *data, size_t len);

/* Row access.  idx >= 0 is a visible row; idx < 0 reaches into scrollback
 * (-1 = the line most recently scrolled off).  Returns NULL if out of range;
 * *width is the number of valid cells in the returned line. */
const vt_cell *vt_line_at(const vt *t, int idx, int *width);
int  vt_scrollback_count(const vt *t);
void vt_clear_dirty(vt *t);
void vt_mark_all_dirty(vt *t);

/* Bytes the terminal wants sent to the host; copies up to max and consumes them. */
int  vt_take_output(vt *t, unsigned char *buf, int max);

/* Keyboard */
enum {
    VT_KEY_UP = 1, VT_KEY_DOWN, VT_KEY_RIGHT, VT_KEY_LEFT, VT_KEY_HOME, VT_KEY_END,
    VT_KEY_PGUP, VT_KEY_PGDN, VT_KEY_INSERT, VT_KEY_DELETE, VT_KEY_BACKTAB,
    VT_KEY_F1 = 32   /* F1..F12 = 32..43 */
};
#define VT_MOD_SHIFT 1
#define VT_MOD_ALT   2
#define VT_MOD_CTRL  4
int  vt_encode_key(const vt *t, int key, int mods, unsigned char *out);   /* returns byte count */

/* Display helpers */
vt_u16 vt_fallback_char(vt_u16 cp);     /* map box drawing/graphics to plain ASCII */
void   vt_palette_rgb(int index, vt_u8 *r, vt_u8 *g, vt_u8 *b);

#endif
