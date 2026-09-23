/* ssh_priv.h -- internals shared by the ssh_*.c files.  Not for applications. */
#ifndef SSH_PRIV_H
#define SSH_PRIV_H

#include "ssh.h"
#include "wire.h"
#include "aes.h"
#include "blowfish.h"
#include "des.h"
#include "gcm.h"
#include "chacha.h"
#include "bignum.h"
#include "hmac.h"

#define SSH_MAX_PACKET     262144   /* largest packet_length we accept */
#define SSH_MAX_CHANNELS   32
#define SSH_LOCAL_WINDOW   262144
#define SSH_LOCAL_MAXPKT   32768
#define SSH_MAX_BACKLOG    (512 * 1024)

/* transport / auth / connection message numbers (RFC 4250 section 4.1.2) */
#define M_DISCONNECT       1
#define M_IGNORE           2
#define M_UNIMPLEMENTED    3
#define M_DEBUG            4
#define M_SERVICE_REQUEST  5
#define M_SERVICE_ACCEPT   6
#define M_EXT_INFO         7
#define M_KEXINIT          20
#define M_NEWKEYS          21
#define M_KEX_ECDH_INIT    30      /* also SSH_MSG_KEXDH_INIT */
#define M_KEX_ECDH_REPLY   31      /* also KEXDH_REPLY and KEX_DH_GEX_GROUP */
#define M_KEX_DH_GEX_INIT  32
#define M_KEX_DH_GEX_REPLY 33
#define M_KEX_DH_GEX_REQUEST 34
#define M_USERAUTH_REQUEST 50
#define M_USERAUTH_FAILURE 51
#define M_USERAUTH_SUCCESS 52
#define M_USERAUTH_BANNER  53
#define M_USERAUTH_INFO    60      /* PK_OK / PASSWD_CHANGEREQ / INFO_REQUEST */
#define M_USERAUTH_INFO_RESPONSE 61
#define M_GLOBAL_REQUEST   80
#define M_REQUEST_SUCCESS  81
#define M_REQUEST_FAILURE  82
#define M_CHAN_OPEN        90
#define M_CHAN_OPEN_CONFIRM 91
#define M_CHAN_OPEN_FAIL   92
#define M_CHAN_WINDOW_ADJ  93
#define M_CHAN_DATA        94
#define M_CHAN_EXT_DATA    95
#define M_CHAN_EOF         96
#define M_CHAN_CLOSE       97
#define M_CHAN_REQUEST     98
#define M_CHAN_SUCCESS     99
#define M_CHAN_FAILURE     100

enum { CIPHER_NONE = 0, CIPHER_CHACHAPOLY, CIPHER_AES256CTR, CIPHER_AES128CTR, CIPHER_AES256CBC, CIPHER_AES128CBC,
       CIPHER_AES192CTR, CIPHER_AES192CBC, CIPHER_BLOWFISHCBC, CIPHER_3DESCBC, CIPHER_AES256GCM, CIPHER_AES128GCM };

/* One direction of the encrypted transport. */
typedef struct {
    int  cipher;
    int  block;       /* this cipher's block size in bytes (8 or 16): packet length/padding must align
                        * to it (RFC 4253 s.6). Unused (0) for CIPHER_NONE/CIPHER_CHACHAPOLY, which have
                        * their own fixed alignment rules, hardcoded where they are used. */
    int  mackind;     /* HMAC_SHA256 / HMAC_SHA512 / HMAC_SHA1 / HMAC_MD5 */
    int  cbc;         /* a block cipher chained in CBC mode (IV carried across packets) rather than CTR */
    u8   cbcv[16];    /* the running CBC IV: the first `block` bytes are used */
    int  etm;         /* encrypt-then-MAC */
    int  maclen;      /* the MAC tag appended to each packet: 0 for AEAD / none, else MACS[].len --
                        * may be shorter than mackeylen (the "-96" truncated variants) */
    int  mackeylen;   /* the HMAC key length: always the underlying hash's natural size (MACS[].keylen),
                        * regardless of how much of the tag itself gets used */
    aes_ctr_ctx     aes;
    blf_ctx         bf;         /* CIPHER_BLOWFISHCBC only */
    des3_ctx        des3;       /* CIPHER_3DESCBC only */
    aes_gcm_ctx     gcm;        /* CIPHER_AES256GCM / CIPHER_AES128GCM only */
    chachapoly_ctx  cp;
    u8   mackey[64];
} ssh_dir;

typedef struct ssh_evnode {
    ssh_event ev;
    u8   *data;
    char *text, *text2;
    struct ssh_evnode *next;
} ssh_evnode;

enum { CH_FREE = 0, CH_OPENING, CH_OPEN };

typedef struct {
    int  state;
    u32  remote_id, remote_window, remote_maxpkt;
    u32  local_window;
    int  eof_recv, eof_sent, close_recv, close_sent;
    int  want_eof, want_close;
    sbuf out;                      /* data waiting for window space */
} ssh_chan;

enum { KEX_IDLE = 0, KEX_SENT_INIT, KEX_WAIT_GROUP, KEX_WAIT_REPLY, KEX_WAIT_NEWKEYS };
enum { AUTH_NONE = 0, AUTH_WAIT_HOSTKEY, AUTH_SERVICE_SENT, AUTH_IN_PROGRESS, AUTH_DONE };

struct ssh_session {
    sbuf in, out, deferred;
    char *user;
    char *pref_ciphers, *pref_macs, *pref_kex;

    /* identification */
    int  have_version;
    char client_ver[64], server_ver[256];

    /* packet layer */
    ssh_dir tx, rx, tx_next, rx_next;
    u32  tx_seq, rx_seq, cur_rx_seq;
    int  rx_hdr_done;
    u32  rx_pktlen;
    size_t rx_total;
    int  next_cipher_c2s, next_cipher_s2c;

    /* key exchange */
    int  kex_state;
    int  kex_sent_kexinit, kex_sent_newkeys, kex_got_newkeys;
    int  first_kex_done;
    int  strict_kex;
    int  ignore_next_packet;
    sbuf kexinit_c, kexinit_s;
    int  kex_idx;                  /* negotiated key exchange (index into KEXES) */
    bn   kex_x;                    /* our DH exponent / EC private scalar */
    u8   kex_e[520];               /* our public value as sent: X25519 key, EC point, or DH e */
    size_t kex_elen;
    bn   gex_p, gex_g;             /* the group chosen by a group-exchange server */
    u8   eph_priv[32];             /* X25519 private key */
    u8   session_id[64];           /* = the first exchange hash (its length depends on the kex hash) */
    int  session_id_len;
    sbuf hostkey_blob;
    int  cipher_c2s, cipher_s2c, mac_c2s, mac_s2c;   /* negotiated indices */
    char *server_sig_algs;
    char hostkey_alg[40];          /* negotiated host key signature algorithm */

    /* auth */
    int  auth_state;
    int  hostkey_decided;
    int  hostkey_ok;
    int  auth_ok;
    char auth_pending[16];         /* method of the request in flight */
    int  kbd_n;
    char *kbd_name, *kbd_instr;
    char **kbd_prompts;
    int  *kbd_echo;

    /* connection */
    ssh_chan chan[SSH_MAX_CHANNELS];

    /* events */
    ssh_evnode *ev_head, *ev_tail, *ev_cur;

    int  started, closed, fatal;
    int  verbose;                  /* see ssh_set_verbose() */
};

/* shared helpers (ssh.c) */
void ssh_fail(ssh_session *s, const char *msg);
void ssh_push_event(ssh_session *s, int type, int chan, const u8 *data, size_t len,
                    int ext, int code, const char *text, const char *text2);
int  ssh_send_packet(ssh_session *s, const u8 *payload, size_t len);
int  ssh_kex_locked(const ssh_session *s);

/* channels (ssh_chan.c) */
int  ssh_chan_dispatch(ssh_session *s, u8 type, sreader *r);
void ssh_chan_flush_all(ssh_session *s);
void ssh_chan_reset(ssh_chan *c);

/* auth (ssh_auth.c) */
int  ssh_auth_dispatch(ssh_session *s, u8 type, sreader *r);
void ssh_auth_begin(ssh_session *s);
void ssh_auth_free(ssh_session *s);

#endif
