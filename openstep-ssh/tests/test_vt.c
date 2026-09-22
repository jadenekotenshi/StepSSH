#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../term/vt.h"
#include "../term/nsenc.h"
#include "test.h"

static void feed(vt *t, const char *s) { vt_write(t, (const unsigned char *)s, strlen(s)); }

/* Visible row as text with trailing blanks trimmed. */
static const char *row(vt *t, int r)
{
    static char buf[4][512];
    static int k;
    char *b = buf[k++ & 3];
    int i, w, n = 0;
    const vt_cell *l = vt_line_at(t, r, &w);
    if (!l) { strcpy(b, "<none>"); return b; }
    for (i = 0; i < w && n < 500; i++) b[n++] = (char)(l[i].ch < 0x80 ? l[i].ch : '?');
    while (n > 0 && b[n - 1] == ' ') n--;
    b[n] = '\0';
    return b;
}
#define ROW_IS(t, r, s) do { if (strcmp(row((t), (r)), (s)) == 0) t_pass++; else { t_fail++; \
    printf("  FAIL %s:%d: row %d is \"%s\", want \"%s\"\n", __FILE__, __LINE__, (r), row((t), (r)), (s)); } } while (0)
/* b = prefix + decimal(i) + suffix (C89 has no snprintf) */
static void mkline(char *b, const char *prefix, int i, const char *suffix)
{
    char d[12];
    int n = 0, k;
    if (i == 0) d[n++] = '0';
    while (i > 0) { d[n++] = (char)('0' + i % 10); i /= 10; }
    strcpy(b, prefix);
    for (k = n - 1; k >= 0; k--) { size_t l = strlen(b); b[l] = d[k]; b[l + 1] = '\0'; }
    strcat(b, suffix);
}
static vt_cell cell(vt *t, int r, int c) { int w; return vt_line_at(t, r, &w)[c]; }

static void test_basic(void)
{
    vt *t = vt_new(80, 24, 100);
    feed(t, "hello\r\nworld");
    ROW_IS(t, 0, "hello"); ROW_IS(t, 1, "world");
    CHECK(t->cx == 5 && t->cy == 1);
    feed(t, "\033[5;10Hx");
    CHECK(cell(t, 4, 9).ch == 'x');
    feed(t, "\033[H\033[2J");
    ROW_IS(t, 0, ""); ROW_IS(t, 1, "");
    feed(t, "abc\b\bX");                                    /* backspace overwrites */
    ROW_IS(t, 0, "aXc");
    feed(t, "\r\033[K");
    ROW_IS(t, 0, "");
    vt_free(t);
}

static void test_wrap(void)
{
    int i;
    vt *t = vt_new(10, 4, 10);
    for (i = 0; i < 10; i++) feed(t, "a");
    CHECK(t->cx == 9 && t->wrap_pending);                    /* pending wrap, not yet wrapped */
    feed(t, "b");
    ROW_IS(t, 0, "aaaaaaaaaa"); ROW_IS(t, 1, "b");
    feed(t, "\033[?7l\033[1;1H");                            /* autowrap off: overwrite last col */
    feed(t, "0123456789XYZ");
    ROW_IS(t, 0, "012345678Z");
    vt_free(t);
}

static void test_erase_edit(void)
{
    vt *t = vt_new(10, 5, 0);
    feed(t, "0123456789");
    feed(t, "\033[1;5H\033[K");         ROW_IS(t, 0, "0123");
    feed(t, "\033[1;3H\033[1K");        ROW_IS(t, 0, "   3");                  /* EL 1: erase through the cursor column */
    feed(t, "\033[1;1Habcdef\033[1;3H\033[2@");                                 /* ICH */
    ROW_IS(t, 0, "ab  cdef");
    feed(t, "\033[2P");                 ROW_IS(t, 0, "abcdef");                  /* DCH */
    feed(t, "\033[3X");                 ROW_IS(t, 0, "ab   f");                  /* ECH */
    feed(t, "\033[1;1H\033[2J\033[1;1Hone\r\ntwo\r\nthree");
    feed(t, "\033[2;1H\033[L");         ROW_IS(t, 1, ""); ROW_IS(t, 2, "two");   /* IL */
    feed(t, "\033[M");                  ROW_IS(t, 1, "two"); ROW_IS(t, 2, "three");   /* DL */
    feed(t, "\033[4h\033[1;1HXY");      ROW_IS(t, 0, "XYone");                  /* insert mode */
    vt_free(t);
}

static void test_sgr(void)
{
    vt *t = vt_new(20, 3, 0);
    vt_cell c;
    feed(t, "\033[1;31mR\033[0mN\033[38;5;208mO\033[48;2;255;0;0mP\033[4;7;39;49mQ");
    c = cell(t, 0, 0);
    CHECK((c.attr & VT_BOLD) && !(c.attr & VT_DEFFG) && c.fg == 1);
    c = cell(t, 0, 1);
    CHECK((c.attr & VT_DEFFG) && (c.attr & VT_DEFBG) && !(c.attr & VT_BOLD));
    c = cell(t, 0, 2);
    CHECK(c.fg == 208 && !(c.attr & VT_DEFFG));
    c = cell(t, 0, 3);
    CHECK(c.bg == 196 && !(c.attr & VT_DEFBG));              /* truecolor red -> cube (5,0,0) */
    c = cell(t, 0, 4);
    CHECK((c.attr & VT_UNDERLINE) && (c.attr & VT_REVERSE) && (c.attr & VT_DEFFG) && (c.attr & VT_DEFBG));
    feed(t, "\033[91mB\033[102mG");
    CHECK(cell(t, 0, 5).fg == 9);
    CHECK(cell(t, 0, 6).bg == 10);
    vt_free(t);
}

static void test_scroll(void)
{
    int i, w;
    char b[16];
    vt *t = vt_new(10, 5, 100);
    for (i = 0; i < 9; i++) { mkline(b, "L", i, i < 8 ? "\r\n" : ""); feed(t, b); }
    CHECK(vt_scrollback_count(t) == 4);
    ROW_IS(t, 0, "L4"); ROW_IS(t, 4, "L8");
    ROW_IS(t, -1, "L3"); ROW_IS(t, -4, "L0");
    CHECK(vt_line_at(t, -5, &w) == NULL);
    /* scroll region: text outside must not move and nothing enters scrollback */
    feed(t, "\033[2;4r\033[4;1H\n\n");
    CHECK(vt_scrollback_count(t) == 4);
    ROW_IS(t, 0, "L4"); ROW_IS(t, 4, "L8");
    ROW_IS(t, 1, "L7"); ROW_IS(t, 2, ""); ROW_IS(t, 3, "");     /* region 2..4 scrolled twice */
    /* reverse index at the top of the region scrolls down */
    feed(t, "\033[r\033[1;1H\033[2J\033[2;4r\033[2;1Ha\r\nb\r\nc\033[2;1H\033[M\033[2;1H\033[L");
    feed(t, "\033[2;1H\033M");
    ROW_IS(t, 1, "");
    vt_free(t);
    /* ring reuse: overflow the scrollback and check the newest/oldest */
    t = vt_new(10, 3, 5);
    for (i = 0; i < 20; i++) { mkline(b, "n", i, "\r\n"); feed(t, b); }
    CHECK(vt_scrollback_count(t) == 5);
    ROW_IS(t, -1, "n17"); ROW_IS(t, -5, "n13");
    vt_free(t);
}

static void test_alt_screen(void)
{
    vt *t = vt_new(10, 4, 10);
    feed(t, "main\033[2;3H");
    feed(t, "\033[?1049h");
    ROW_IS(t, 0, "");
    CHECK(t->cx == 2 && t->cy == 1);                        /* 1049 does not move the cursor */
    feed(t, "\033[H" "alt");
    ROW_IS(t, 0, "alt");
    feed(t, "\033[?1049l");
    ROW_IS(t, 0, "main");
    CHECK(t->cx == 2 && t->cy == 1);                        /* cursor restored */
    vt_free(t);
}

static void test_tabs_modes(void)
{
    vt *t = vt_new(40, 4, 0);
    feed(t, "a\tb");
    CHECK(cell(t, 0, 8).ch == 'b');
    feed(t, "\r\033[3g\033[1;5H\033H\r\tc");                /* clear all, set one at col 4 */
    CHECK(cell(t, 0, 4).ch == 'c');
    feed(t, "\033[2J\033[1;1H\033[?6h\033[2;3r");            /* origin mode: (1,1) is region top */
    feed(t, "\033[1;1HO");
    CHECK(cell(t, 1, 0).ch == 'O');
    feed(t, "\033[?6l\033[?25l");
    CHECK(!t->cursor_visible && !t->origin);
    feed(t, "\033[?1h\033=\033[?2004h");
    CHECK(t->app_cursor && t->app_keypad && t->bracketed_paste);
    feed(t, "\033c");                                       /* RIS */
    CHECK(!t->app_cursor && !t->bracketed_paste && t->cursor_visible);
    vt_free(t);
}

static void test_replies_title(void)
{
    unsigned char b[64];
    int n;
    vt *t = vt_new(80, 24, 0);
    feed(t, "\033[3;5H\033[6n");
    n = vt_take_output(t, b, sizeof(b)); b[n] = 0;
    CHECK(strcmp((char *)b, "\033[3;5R") == 0);
    feed(t, "\033[5n");
    n = vt_take_output(t, b, sizeof(b)); b[n] = 0;
    CHECK(strcmp((char *)b, "\033[0n") == 0);
    feed(t, "\033[c");
    n = vt_take_output(t, b, sizeof(b)); b[n] = 0;
    CHECK(strcmp((char *)b, "\033[?1;2c") == 0);
    feed(t, "\033[>c");                                     /* secondary DA: deliberately unanswered */
    CHECK(vt_take_output(t, b, sizeof(b)) == 0);
    feed(t, "\033]0;bell title\007");
    CHECK(t->title_changed && strcmp(t->title, "bell title") == 0);
    feed(t, "\033[H\033]2;st title\033\\x");
    CHECK(strcmp(t->title, "st title") == 0);
    ROW_IS(t, 0, "x");
    feed(t, "\007");
    CHECK(t->bell);
    vt_free(t);
}

static void test_utf8_charsets(void)
{
    vt *t = vt_new(20, 3, 0);
    feed(t, "\xc3\xa9\xe2\x82\xac");
    CHECK(cell(t, 0, 0).ch == 0xe9 && cell(t, 0, 1).ch == 0x20ac);
    vt_write(t, (const unsigned char *)"\xe2\x82", 2);      /* sequence split across writes */
    vt_write(t, (const unsigned char *)"\xac", 1);
    CHECK(cell(t, 0, 2).ch == 0x20ac);
    feed(t, "\xff\x80");                                    /* invalid bytes -> U+FFFD, no crash */
    CHECK(cell(t, 0, 3).ch == 0xfffd && cell(t, 0, 4).ch == 0xfffd);
    feed(t, "\xe2\x82" "A");                                /* truncated sequence then ASCII */
    CHECK(cell(t, 0, 5).ch == 0xfffd && cell(t, 0, 6).ch == 'A');
    feed(t, "\033[2J\033[H\033(0lqk\033(Bq");
    CHECK(cell(t, 0, 0).ch == 0x250c && cell(t, 0, 1).ch == 0x2500 && cell(t, 0, 2).ch == 0x2510);
    CHECK(cell(t, 0, 3).ch == 'q');
    CHECK(vt_fallback_char(0x250c) == '+' && vt_fallback_char(0x2500) == '-' && vt_fallback_char(0x2502) == '|');
    feed(t, "\033[2J\033[H\033)0\016q\017q");               /* SO/SI with G1 = graphics */
    CHECK(cell(t, 0, 0).ch == 0x2500 && cell(t, 0, 1).ch == 'q');
    vt_free(t);
}

static void test_nsenc(void)
{
    int b, n = 0;
    vt *t = vt_new(20, 3, 0);
    CHECK(nsenc_decode('A') == 'A' && nsenc_decode(0xa0) == 0x00a9 && nsenc_decode(0xdd) == 0x00e9);
    CHECK(nsenc_encode(0x00e9) == 0xdd && nsenc_encode('z') == 'z' && nsenc_encode(0x20ac) == -1);
    CHECK(nsenc_decode(0xfe) == 0xfffd && nsenc_encode(0xfffd) == -1);
    for (b = 0x80; b < 0x100; b++)                       /* every assigned byte round-trips */
        if (nsenc_decode((unsigned char)b) != 0xfffd) { CHECK(nsenc_encode(nsenc_decode((unsigned char)b)) == b); n++; }
    CHECK(n == 126);
    vt_write(t, (const unsigned char *)"\033%@\xdd\xa0", 5);   /* UTF-8 off: bytes are NeXTSTEP */
    CHECK(cell(t, 0, 0).ch == 0xe9 && cell(t, 0, 1).ch == 0xa9);
    vt_free(t);
}

static void test_resize(void)
{
    vt *t = vt_new(10, 4, 20);
    feed(t, "one\r\ntwo\r\nthree\r\nfour");
    vt_resize(t, 20, 6);
    ROW_IS(t, 0, "one"); ROW_IS(t, 3, "four");
    CHECK(t->cols == 20 && t->rows == 6 && t->cy == 3);
    vt_resize(t, 8, 2);                                     /* cursor was on row 3: top rows scroll away */
    CHECK(t->cy == 1 && t->rows == 2);
    ROW_IS(t, 0, "three"); ROW_IS(t, 1, "four");
    ROW_IS(t, -1, "two"); ROW_IS(t, -2, "one");
    vt_resize(t, 1, 1);                                     /* degenerate sizes must not crash */
    feed(t, "abc\r\n\r\n");
    vt_resize(t, 5, 5);
    vt_free(t);
}

static void test_keys_dirty(void)
{
    unsigned char b[16];
    int n;
    vt *t = vt_new(10, 4, 0);
    n = vt_encode_key(t, VT_KEY_UP, 0, b); b[n] = 0;               CHECK(strcmp((char *)b, "\033[A") == 0);
    t->app_cursor = 1;
    n = vt_encode_key(t, VT_KEY_UP, 0, b); b[n] = 0;               CHECK(strcmp((char *)b, "\033OA") == 0);
    n = vt_encode_key(t, VT_KEY_UP, VT_MOD_CTRL, b); b[n] = 0;     CHECK(strcmp((char *)b, "\033[1;5A") == 0);
    n = vt_encode_key(t, VT_KEY_F1, 0, b); b[n] = 0;               CHECK(strcmp((char *)b, "\033OP") == 0);
    n = vt_encode_key(t, VT_KEY_F1 + 4, 0, b); b[n] = 0;           CHECK(strcmp((char *)b, "\033[15~") == 0);
    n = vt_encode_key(t, VT_KEY_DELETE, 0, b); b[n] = 0;           CHECK(strcmp((char *)b, "\033[3~") == 0);
    n = vt_encode_key(t, VT_KEY_PGDN, VT_MOD_SHIFT, b); b[n] = 0;  CHECK(strcmp((char *)b, "\033[6;2~") == 0);
    n = vt_encode_key(t, VT_KEY_BACKTAB, 0, b); b[n] = 0;          CHECK(strcmp((char *)b, "\033[Z") == 0);
    CHECK(vt_encode_key(t, 999, 0, b) == 0);

    vt_clear_dirty(t);
    CHECK(!t->dirty[0] && !t->dirty[2] && !t->all_dirty);
    feed(t, "\033[3;1Hx");
    CHECK(!t->dirty[0] && !t->dirty[1] && t->dirty[2] && !t->dirty[3]);
    vt_free(t);
}

static void test_fuzz(void)
{
    /* Hostile/garbage input must never crash, hang or corrupt memory (run under ASan). */
    unsigned char buf[4096];
    int iter, i, k;
    unsigned seed = 12345;
    vt *t = vt_new(37, 11, 50);
    static const char *frag[] = { "\033[", "\033]", "\033P", "\033(", ";", "?", "99999", "\033[38;2;", "m", "H", "r",
                                  "\033[?1049h", "\033[?1049l", "\033[9999999999", "\033[L", "\033[M", "\033[@", "\033[P" };
    for (iter = 0; iter < 400; iter++) {
        for (i = 0; i < (int)sizeof(buf); ) {
            seed = seed * 1103515245u + 12345u;
            if ((seed >> 16) % 4 == 0) {
                const char *f = frag[(seed >> 8) % (sizeof(frag) / sizeof(frag[0]))];
                for (k = 0; f[k] && i < (int)sizeof(buf); k++) buf[i++] = (unsigned char)f[k];
            } else {
                buf[i++] = (unsigned char)(seed >> 20);
            }
        }
        vt_write(t, buf, sizeof(buf));
        if (iter % 50 == 0) vt_resize(t, 1 + (int)((seed >> 4) % 90), 1 + (int)((seed >> 12) % 40));
        vt_take_output(t, buf, 64);
    }
    CHECK(t->cx >= 0 && t->cx < t->cols && t->cy >= 0 && t->cy < t->rows);
    vt_free(t);
}

int main(void)
{
    test_basic(); test_wrap(); test_erase_edit(); test_sgr(); test_scroll();
    test_alt_screen(); test_tabs_modes(); test_replies_title(); test_utf8_charsets();
    test_nsenc(); test_resize(); test_keys_dirty(); test_fuzz();
    TEST_DONE("vt");
}
