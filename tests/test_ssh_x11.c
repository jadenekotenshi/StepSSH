/*
 * test_ssh_x11.c -- exercises core/ssh_chan.c's X11 forwarding wiring through the PUBLIC ssh.h
 * API (ssh_new/ssh_input/ssh_output/ssh_next_event), the way any real caller would, rather than
 * calling ssh_chan_dispatch() directly. This is possible without a real handshake because a
 * freshly ssh_new()'d session's tx/rx ciphers default to CIPHER_NONE, under which
 * send_packet_now()/read_packet() frame packets in plaintext (4-byte length + 1-byte padlen +
 * payload + pad, no MAC) -- and handle_packet()'s dispatcher routes message types 80-100 straight
 * to ssh_chan_dispatch() with no session-state gate above it. So: feed a synthetic version line to
 * satisfy the have_version gate, hand-set auth_ok (bypassing the handshake/auth state machine on
 * purpose -- this file is scoped to the channel layer), and the rest is real, wire-format-correct
 * traffic in both directions.
 *
 * Reaches into ssh_priv.h (not just the public ssh.h) to set up that bootstrap state and to
 * manufacture channels directly -- a whitebox test, same idea as test_bignum.c/test_ecc.c reaching
 * into bn's own fields.
 */
#include <stdlib.h>
#include <string.h>
#include "../core/ssh_priv.h"
#include "../core/rng.h"
#include "test.h"

static void seed_rng(void)
{
    if (ssh_rng_ready()) return;
    if (ssh_rng_seed_system() == 0) ssh_rng_add("test_ssh_x11", 12, 256);
}

static ssh_session *bootstrap(void)
{
    ssh_session *s = ssh_new("tester");
    static const u8 verline[] = "SSH-2.0-test\r\n";
    CHECK(ssh_input(s, verline, sizeof(verline) - 1) == 0);
    CHECK(s->have_version);
    s->auth_ok = 1;
    /* handle_packet()'s very first check requires the session's first-ever received packet to be
     * M_KEXINIT unless first_kex_done is already set -- bypassed here for the same reason auth_ok
     * is hand-set above: this file is scoped to the channel layer, not the handshake. */
    s->first_kex_done = 1;
    return s;
}

/* Wraps `payload` as one CIPHER_NONE plaintext packet (RFC 4253 s.6): 4-byte BE length, 1-byte
 * padlen (the RFC minimum, 4 -- read_packet() only requires >=4, no block-alignment check applies
 * to CIPHER_NONE on the receive side), the payload, then `pad` zero bytes. Returns the total
 * length written to `out`. */
static size_t build_packet(u8 *out, const u8 *payload, size_t plen)
{
    size_t pad = 4, pktlen = 1 + plen + pad;
    STORE32_BE(out, (u32)pktlen);
    out[4] = (u8)pad;
    memcpy(out + 5, payload, plen);
    memset(out + 5 + plen, 0, pad);
    return 4 + pktlen;
}

/* The inverse: given raw bytes ssh_output() produced, returns a pointer to the payload of the
 * FIRST packet in them and its length; NULL if there isn't a complete one. */
static const u8 *parse_packet(const u8 *buf, size_t len, size_t *plen)
{
    u32 pktlen;
    u8 padlen;
    if (len < 5) return NULL;
    pktlen = LOAD32_BE(buf);
    if (4 + (size_t)pktlen > len) return NULL;
    padlen = buf[4];
    if ((size_t)padlen + 1 >= pktlen) return NULL;
    *plen = pktlen - padlen - 1;
    return buf + 5;
}

static void feed(ssh_session *s, const u8 *payload, size_t plen)
{
    u8 pkt[512];
    size_t n = build_packet(pkt, payload, plen);
    CHECK(ssh_input(s, pkt, n) == 0);
}

/* Manufactures one channel directly into CH_OPEN, bypassing the OPENING/CONFIRM round trip --
 * this file is testing ssh_channel_request_x11()/the CHANNEL_OPEN accept path, not the ordinary
 * client-initiated open flow (already covered by ssh_channel_open_session() itself elsewhere). */
static int make_open_chan(ssh_session *s, u32 remote_id)
{
    int i;
    for (i = 0; i < SSH_MAX_CHANNELS && s->chan[i].state != CH_FREE; i++) ;
    CHECK(i < SSH_MAX_CHANNELS);
    memset(&s->chan[i], 0, sizeof(s->chan[i]));
    s->chan[i].state = CH_OPEN;
    s->chan[i].remote_id = remote_id;
    s->chan[i].remote_window = 1 << 20;
    s->chan[i].remote_maxpkt = 32768;
    s->chan[i].local_window = 1 << 20;
    sb_init(&s->chan[i].out);
    sb_init(&s->chan[i].x11_pending);
    return i;
}

static void fill16(u8 *p, int base) { int i; for (i = 0; i < 16; i++) p[i] = (u8)(base + i); }

/* -------------------------- outbound: x11-req field order -------------------------- */

static void test_outbound_field_order(void)
{
    ssh_session *s = bootstrap();
    int ch = make_open_chan(s, 7);
    const u8 *out, *payload;
    size_t outlen, plen;
    sreader r;
    u8 want_bool;
    size_t sl;
    const u8 *sp;
    u32 want_screen;

    CHECK(ssh_channel_request_x11(s, ch, 0, NULL, 0, 3) == 0);
    CHECK(s->x11_active);

    out = ssh_output(s, &outlen);
    payload = parse_packet(out, outlen, &plen);
    CHECK(payload != NULL);

    sr_init(&r, payload, plen);
    CHECK(sr_u8(&r) == M_CHAN_REQUEST);
    CHECK(sr_u32(&r) == 7);                              /* recipient channel = remote_id */
    sp = sr_str(&r, &sl);
    CHECK(sl == 7 && memcmp(sp, "x11-req", 7) == 0);
    CHECK(sr_u8(&r) == 1);                                /* want reply */
    want_bool = sr_u8(&r);
    CHECK(want_bool == 0);                                /* single_connection, as passed */
    sp = sr_str(&r, &sl);
    CHECK(sl == 18 && memcmp(sp, "MIT-MAGIC-COOKIE-1", 18) == 0);
    sp = sr_str(&r, &sl);
    CHECK(sl == 32);                                      /* the fake cookie, hex-encoded */
    {
        char want_hex[33];
        hex_encode(s->x11_fake_cookie, 16, want_hex, sizeof(want_hex));
        CHECK(memcmp(sp, want_hex, 32) == 0);
    }
    want_screen = sr_u32(&r);
    CHECK(want_screen == 3);
    CHECK(!r.err);
    CHECK(sr_left(&r) == 0);                              /* nothing left over */

    ssh_output_done(s, outlen);
    ssh_free(s);
}

static void test_outbound_rejects_bad_cookie_length(void)
{
    ssh_session *s = bootstrap();
    int ch = make_open_chan(s, 1);
    u8 cookie[8];
    CHECK(ssh_channel_request_x11(s, ch, 0, cookie, sizeof(cookie), 0) == -1);   /* not 0 or 16 */
    CHECK(!s->x11_active);
    ssh_free(s);
}

/* -------------------------- inbound: accept + cookie substitution -------------------------- */

static void test_inbound_accept_and_substitute(void)
{
    ssh_session *s = bootstrap();
    u8 fake[16], real[16];
    sbuf open_msg, data_msg;
    u8 setup[128];
    static const char proto[] = "MIT-MAGIC-COOKIE-1";
    size_t setup_len, o;
    const u8 *out, *payload;
    size_t outlen, plen;
    ssh_event ev;
    int saw_open = 0, saw_data = 0;
    int new_chan_id = -1;

    fill16(fake, 0x10); fill16(real, 0xa0);
    s->x11_active = 1;
    memcpy(s->x11_fake_cookie, fake, 16);
    memcpy(s->x11_real_cookie, real, 16);
    s->x11_real_cookie_len = 16;

    /* Server-initiated CHANNEL_OPEN for "x11", as a real sshd would send once a forwarded X11
     * client connects on the remote side. */
    sb_init(&open_msg);
    sb_put_u8(&open_msg, M_CHAN_OPEN);
    sb_put_cstr(&open_msg, "x11");
    sb_put_u32(&open_msg, 99);                            /* server's own id for this channel */
    sb_put_u32(&open_msg, 1 << 20);
    sb_put_u32(&open_msg, 32768);
    sb_put_cstr(&open_msg, "10.0.0.5");                   /* originator address */
    sb_put_u32(&open_msg, 54321);                          /* originator port */
    feed(s, open_msg.p, open_msg.len);
    sb_free(&open_msg);

    while (ssh_next_event(s, &ev)) {
        if (ev.type == SSH_EV_X11_OPEN) { saw_open = 1; new_chan_id = ev.channel; CHECK(strcmp(ev.text, "10.0.0.5") == 0); }
    }
    CHECK(saw_open);
    CHECK(new_chan_id >= 0);

    out = ssh_output(s, &outlen);
    payload = parse_packet(out, outlen, &plen);
    CHECK(payload != NULL);
    CHECK(payload[0] == M_CHAN_OPEN_CONFIRM);
    ssh_output_done(s, outlen);

    /* Now the remote X client's own ConnectionSetup request arrives as CHANNEL_DATA, carrying the
     * fake cookie -- must come back out as SSH_EV_CHAN_DATA with the REAL cookie substituted. */
    {
        size_t plen = strlen(proto), ppad = (4 - (plen % 4)) % 4;
        size_t header_and_name_len = 12 + plen + ppad;

        o = 0;
        setup[o++] = 0x6c; setup[o++] = 0;                    /* byte-order 'l', pad */
        setup[o++] = 11; setup[o++] = 0;                       /* major */
        setup[o++] = 0;  setup[o++] = 0;                       /* minor */
        setup[o++] = (u8)plen; setup[o++] = 0;                 /* name length */
        setup[o++] = 16; setup[o++] = 0;                       /* data length = 16 */
        setup[o++] = 0;  setup[o++] = 0;                       /* pad */
        memcpy(setup + o, proto, plen); o += plen;
        memset(setup + o, 0, ppad); o += ppad;                 /* name's own pad to a 4-byte boundary */
        memcpy(setup + o, fake, 16); o += 16;
        setup_len = o;

        sb_init(&data_msg);
        sb_put_u8(&data_msg, M_CHAN_DATA);
        sb_put_u32(&data_msg, (u32)new_chan_id);
        sb_put_str(&data_msg, setup, setup_len);
        feed(s, data_msg.p, data_msg.len);
        sb_free(&data_msg);

        while (ssh_next_event(s, &ev)) {
            if (ev.type == SSH_EV_CHAN_DATA) {
                saw_data = 1;
                CHECK(ev.channel == new_chan_id);
                CHECK(ev.len == setup_len);                    /* same length: 16-byte cookie for 16-byte cookie */
                CHECK(memcmp(ev.data, setup, header_and_name_len) == 0);      /* header+name+pad unchanged */
                CHECK(memcmp(ev.data + header_and_name_len, real, 16) == 0);  /* data replaced with the real cookie */
            }
        }
    }
    CHECK(saw_data);
    CHECK(s->chan[new_chan_id].x11_setup_done);

    ssh_free(s);
}

/* -------------------------- refusal preserved for everything else -------------------------- */

static void expect_open_failure(ssh_session *s, const char *chan_type, u32 want_reason)
{
    sbuf open_msg;
    const u8 *out, *payload;
    size_t outlen, plen;
    sreader r;

    sb_init(&open_msg);
    sb_put_u8(&open_msg, M_CHAN_OPEN);
    sb_put_cstr(&open_msg, chan_type);
    sb_put_u32(&open_msg, 55);
    sb_put_u32(&open_msg, 1 << 20);
    sb_put_u32(&open_msg, 32768);
    sb_put_cstr(&open_msg, "10.0.0.9");                    /* originator address/port: only ever
                                                                read when chan_type is "x11" AND
                                                                x11_active, but harmless trailing
                                                                bytes otherwise -- keeps this one
                                                                packet valid for every case below */
    sb_put_u32(&open_msg, 12345);
    feed(s, open_msg.p, open_msg.len);
    sb_free(&open_msg);

    out = ssh_output(s, &outlen);
    payload = parse_packet(out, outlen, &plen);
    CHECK(payload != NULL);
    sr_init(&r, payload, plen);
    CHECK(sr_u8(&r) == M_CHAN_OPEN_FAIL);
    CHECK(sr_u32(&r) == 55);
    CHECK(sr_u32(&r) == want_reason);
    ssh_output_done(s, outlen);
}

static void test_other_types_still_refused(void)
{
    ssh_session *s = bootstrap();
    s->x11_active = 1;                                    /* even with x11 requested ... */
    expect_open_failure(s, "forwarded-tcpip", 1);          /* ... anything else is still refused */
    ssh_free(s);
}

static void test_x11_refused_when_not_requested(void)
{
    ssh_session *s = bootstrap();
    CHECK(!s->x11_active);
    expect_open_failure(s, "x11", 1);
    ssh_free(s);
}

/* -------------------------------- channel exhaustion -------------------------------- */

static void test_exhaustion_gets_resource_shortage(void)
{
    ssh_session *s = bootstrap();
    int i;
    s->x11_active = 1;
    for (i = 0; i < SSH_MAX_CHANNELS; i++) make_open_chan(s, (u32)(1000 + i));
    expect_open_failure(s, "x11", 4);                      /* SSH_OPEN_RESOURCE_SHORTAGE, not 1 */
    ssh_free(s);
}

int main(void)
{
    seed_rng();
    test_outbound_field_order();
    test_outbound_rejects_bad_cookie_length();
    test_inbound_accept_and_substitute();
    test_other_types_still_refused();
    test_x11_refused_when_not_requested();
    test_exhaustion_gets_resource_shortage();
    TEST_DONE("ssh_x11");
}
