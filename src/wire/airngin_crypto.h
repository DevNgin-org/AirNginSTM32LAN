#pragma once
/*
 * AirNgin application-layer encryption (CONFIG_AIRNGIN_USE_AES) - canonical contract (sections 19-24):
 *
 *   algorithm   AES-256-GCM (mbedTLS), 256-bit key, 96-bit nonce, 128-bit tag, NO additional authenticated data
 *   key         Base64 text that decodes to EXACTLY 32 bytes (provisioning field "encryptionKey")
 *   envelope    JSON {"nonce":b64(12), "ciphertext":b64, "tag":b64(16), "version":"1.0", "timestamp":<UTC seconds>,
 *                     "deviceSerial":"<serial>", "more":""}
 *   nonce       fresh random per message (esp_fill_random), never reused with a key
 *   receive     parse -> required fields -> version -> clock/timestamp (+-60 s) -> nonce replay -> Base64 ->
 *               authenticate+decrypt -> remember nonce. Plaintext is returned only after every step passed.
 *
 * Pure functions with explicit key, nonce, time and replay cache: the transport supplies randomness and the clock,
 * the host tests supply fixed values (known-answer tests).
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define AIRNGIN_AES_KEY_LEN          32U
#define AIRNGIN_AES_KEY_B64_MAX      44U     /* Base64 of 32 bytes (with padding) */
#define AIRNGIN_AES_NONCE_LEN        12U
#define AIRNGIN_AES_TAG_LEN          16U
#define AIRNGIN_AES_VERSION          "1.0"
#define AIRNGIN_AES_WINDOW_SECONDS   60
#define AIRNGIN_AES_MIN_EPOCH        1700000000LL   /* a clock that was never set is not a timestamp */
#define AIRNGIN_AES_REPLAY_SLOTS     64U
#define AIRNGIN_AES_REPLAY_RETENTION 130LL          /* window on both sides of the clock, plus margin */

/* Largest logical (plaintext) message that is sealed: the existing AirNgin response limit. */
#define AIRNGIN_AES_PLAIN_MAX        4096U
/* Largest complete MQTT payload accepted from the broker (unchanged 4096 limit; in AES mode it is the ENVELOPE). */
#define AIRNGIN_AES_ENVELOPE_IN_MAX  4096U

#define AIRNGIN_B64_LEN(n)           ((((size_t)(n)) + 2U) / 3U * 4U)
/* Exact envelope fixed part: everything except the ciphertext Base64 text, for a serial of up to 14 characters and a
 * 19-digit timestamp: see the worst-case assertion in test_crypto.c. */
#define AIRNGIN_AES_ENVELOPE_FIXED   173U
/* Capacity (including the NUL) needed to seal `n` plaintext bytes. */
#define AIRNGIN_AES_ENVELOPE_CAP(n)  (AIRNGIN_B64_LEN(n) + AIRNGIN_AES_ENVELOPE_FIXED + 1U)
/* Largest plaintext that can arrive inside a 4096-byte envelope (decoded upper bound). */
#define AIRNGIN_AES_PLAIN_IN_MAX     (AIRNGIN_AES_ENVELOPE_IN_MAX / 4U * 3U)

typedef enum {
    AIRNGIN_AES_OK = 0,
    AIRNGIN_AES_BAD_ARG,        /* programming error / empty or oversize plaintext */
    AIRNGIN_AES_NO_CLOCK,       /* clock not trusted: no timestamp */
    AIRNGIN_AES_BAD_ENVELOPE,   /* not JSON / not an object / missing or mistyped field */
    AIRNGIN_AES_BAD_VERSION,
    AIRNGIN_AES_BAD_SERIAL,     /* envelope names another device */
    AIRNGIN_AES_STALE,          /* timestamp outside +-60 s */
    AIRNGIN_AES_REPLAY,         /* nonce already seen inside the window */
    AIRNGIN_AES_REPLAY_FULL,    /* replay cache full: rejects instead of forgetting */
    AIRNGIN_AES_BAD_BASE64,
    AIRNGIN_AES_BAD_LENGTH,     /* nonce/tag size wrong, ciphertext empty or too large */
    AIRNGIN_AES_AUTH_FAIL,      /* tag mismatch (tampering or wrong key) */
    AIRNGIN_AES_NO_MEM,
    AIRNGIN_AES_CRYPTO_FAIL,
    AIRNGIN_AES_TOO_SMALL,      /* output buffer too small */
} airngin_aes_result_t;

const char *airngin_aes_result_name(airngin_aes_result_t r);

/* Optional facts about the envelope that was parsed (for safe diagnostics; never contains key or plaintext). */
typedef struct {
    int64_t timestamp;
    size_t ciphertext_b64_len;
    size_t nonce_len;           /* decoded bytes (0 until decoded) */
    size_t tag_len;
    bool version_ok;
} airngin_aes_info_t;

typedef struct {
    struct { uint8_t nonce[AIRNGIN_AES_NONCE_LEN]; int64_t seen_at; bool used; } slot[AIRNGIN_AES_REPLAY_SLOTS];
} airngin_aes_replay_t;

void airngin_aes_replay_reset(airngin_aes_replay_t *r);

/* Base64 text -> exactly 32 key bytes. false for anything else (empty, too long, wrong length, bad alphabet). */
bool airngin_aes_key_decode(const char *base64, uint8_t key[AIRNGIN_AES_KEY_LEN]);
bool airngin_aes_key_valid(const char *base64);

/* Build the envelope for `plain`. `nonce` is supplied by the caller (random in production). Writes a NUL-terminated string. */
airngin_aes_result_t airngin_aes_seal(const uint8_t key[AIRNGIN_AES_KEY_LEN], const char *serial, int64_t timestamp,
                                      const uint8_t nonce[AIRNGIN_AES_NONCE_LEN], const uint8_t *plain, size_t plain_len,
                                      char *out, size_t out_capacity, size_t *out_len);

/* Validate and open an envelope. On success `plain` holds the message (NUL-terminated) and the nonce is remembered. */
airngin_aes_result_t airngin_aes_open(const uint8_t key[AIRNGIN_AES_KEY_LEN], const char *serial, int64_t now,
                                      airngin_aes_replay_t *replay, const char *envelope, size_t envelope_len,
                                      uint8_t *plain, size_t plain_capacity, size_t *plain_len, airngin_aes_info_t *info);
