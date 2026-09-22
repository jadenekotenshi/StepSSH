/*
 * ssh.h -- a sans-I/O SSH-2 client engine.
 *
 * The engine never touches a socket.  The application:
 *   1. feeds bytes it read from the network to ssh_input(),
 *   2. sends whatever ssh_output() exposes, then calls ssh_output_done(),
 *   3. drains events with ssh_next_event() after every call that can
 *      generate them (ssh_input and every ssh_* action).
 * All state lives in the ssh_session, so the same code drives a blocking
 * test tool on the dev host and the run-loop-driven AppKit app on OPENSTEP.
 */
#ifndef SSH_H
#define SSH_H

#include "ssh_types.h"
#include "ssh_key.h"

typedef struct ssh_session ssh_session;

enum {
    SSH_EV_NONE = 0,
    SSH_EV_HOSTKEY,        /* text = "SHA256:..." fingerprint, text2 = key type; data = blob.
                              Reply with ssh_hostkey_accept(). */
    SSH_EV_BANNER,         /* text = pre-auth banner from the server */
    SSH_EV_AUTH_NEEDED,    /* text = comma-separated methods the server will accept */
    SSH_EV_AUTH_FAILED,    /* text = methods that can continue; code = 1 if partial success */
    SSH_EV_AUTH_OK,
    SSH_EV_KBDINT,         /* keyboard-interactive prompts: see ssh_kbdint_*() */
    SSH_EV_CHAN_OPEN,      /* channel confirmed */
    SSH_EV_CHAN_OPEN_FAILED,
    SSH_EV_CHAN_SUCCESS,   /* a channel request (pty, shell, ...) succeeded */
    SSH_EV_CHAN_FAILURE,
    SSH_EV_CHAN_DATA,      /* data/len; ext = 0 stdout, 1 stderr */
    SSH_EV_CHAN_EOF,
    SSH_EV_CHAN_CLOSE,     /* channel fully closed; id is now free */
    SSH_EV_CHAN_EXIT,      /* code = remote exit status (or 128+signal) */
    SSH_EV_DISCONNECT,     /* peer disconnected; text = its message */
    SSH_EV_ERROR           /* fatal local error; text = description. Session is dead. */
};

typedef struct {
    int         type;
    int         channel;
    const u8   *data;      /* valid until the next ssh_next_event() */
    size_t      len;
    int         ext;
    int         code;
    const char *text;
    const char *text2;
} ssh_event;

/* ---- lifecycle ---- */
ssh_session *ssh_new(const char *username);
void         ssh_free(ssh_session *s);
/* Optional: override algorithm preference lists (comma-separated names).
 * NULL keeps the default.  Mainly for testing and for legacy servers. */
void         ssh_set_prefs(ssh_session *s, const char *ciphers, const char *macs);
/* Restrict / reorder the key exchange methods offered (comma-separated). NULL = default. */
void         ssh_set_kex_prefs(ssh_session *s, const char *kex);
/* Queue our identification string and KEXINIT.  Fails if the RNG is not
 * seeded (see rng.h) -- we never proceed on predictable randomness. */
int          ssh_start(ssh_session *s);
/* Feed received bytes.  Returns 0, or -1 if the session died (ERROR event queued). */
int          ssh_input(ssh_session *s, const u8 *data, size_t len);
const u8    *ssh_output(ssh_session *s, size_t *len);
void         ssh_output_done(ssh_session *s, size_t n);
int          ssh_next_event(ssh_session *s, ssh_event *ev);
int          ssh_is_closed(const ssh_session *s);
int          ssh_is_authenticated(const ssh_session *s);
void         ssh_disconnect(ssh_session *s, const char *msg);
/* Send an SSH_MSG_IGNORE (keepalive / traffic padding). */
void         ssh_send_ignore(ssh_session *s);

/* ---- host key ---- */
void         ssh_hostkey_accept(ssh_session *s, int accept);

/* ---- authentication (call after SSH_EV_AUTH_NEEDED / AUTH_FAILED) ---- */
int          ssh_auth_password(ssh_session *s, const char *password);
int          ssh_auth_publickey(ssh_session *s, const ssh_key *key);
int          ssh_auth_kbdint_start(ssh_session *s);
int          ssh_kbdint_count(const ssh_session *s);
const char  *ssh_kbdint_prompt(const ssh_session *s, int i, int *echo);
const char  *ssh_kbdint_name(const ssh_session *s);
const char  *ssh_kbdint_instruction(const ssh_session *s);
int          ssh_auth_kbdint_respond(ssh_session *s, const char **answers, int n);

/* ---- channels ---- */
int          ssh_channel_open_session(ssh_session *s);              /* returns id or -1 */
int          ssh_channel_request_pty(ssh_session *s, int ch, const char *term,
                                     int cols, int rows, int pxw, int pxh);
int          ssh_channel_request_shell(ssh_session *s, int ch);
int          ssh_channel_request_exec(ssh_session *s, int ch, const char *cmd);
int          ssh_channel_request_subsystem(ssh_session *s, int ch, const char *name);
int          ssh_channel_setenv(ssh_session *s, int ch, const char *name, const char *value);
/* Queue data; returns bytes accepted (may be < len if the backlog is full). */
int          ssh_channel_write(ssh_session *s, int ch, const u8 *data, size_t len);
size_t       ssh_channel_backlog(const ssh_session *s, int ch);
int          ssh_channel_window_change(ssh_session *s, int ch, int cols, int rows, int pxw, int pxh);
int          ssh_channel_eof(ssh_session *s, int ch);
int          ssh_channel_close(ssh_session *s, int ch);

/* Negotiated algorithms, for display ("chacha20-poly1305@openssh.com" ...). */
const char  *ssh_cipher_name(const ssh_session *s);
const char  *ssh_kex_name(const ssh_session *s);
const char  *ssh_mac_name(const ssh_session *s);
const char  *ssh_server_version(const ssh_session *s);

#endif
