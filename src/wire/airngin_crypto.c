#include "airngin_crypto.h"
#include "CryptoPort.h"
#include "cJSON.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Compile-time proof that the largest message AirNgin seals fits its envelope buffer formula. */
_Static_assert(AIRNGIN_AES_ENVELOPE_CAP(AIRNGIN_AES_PLAIN_MAX) == AIRNGIN_B64_LEN(4096U) + 174U, "envelope capacity formula");
_Static_assert(AIRNGIN_AES_PLAIN_IN_MAX == 3072U, "inbound plaintext bound for a 4096-byte envelope");

const char *airngin_aes_result_name(airngin_aes_result_t r)
{
    switch (r) {
    case AIRNGIN_AES_OK:           return "OK";
    case AIRNGIN_AES_BAD_ARG:      return "BAD_ARGUMENT (empty or oversize message)";
    case AIRNGIN_AES_NO_CLOCK:     return "CLOCK_NOT_TRUSTED";
    case AIRNGIN_AES_BAD_ENVELOPE: return "INVALID_ENVELOPE";
    case AIRNGIN_AES_BAD_VERSION:  return "WRONG_VERSION";
    case AIRNGIN_AES_BAD_SERIAL:   return "WRONG_DEVICE_SERIAL";
    case AIRNGIN_AES_STALE:        return "TIMESTAMP_OUTSIDE_WINDOW";
    case AIRNGIN_AES_REPLAY:       return "REPLAYED_NONCE";
    case AIRNGIN_AES_REPLAY_FULL:  return "REPLAY_CACHE_FULL";
    case AIRNGIN_AES_BAD_BASE64:   return "INVALID_BASE64";
    case AIRNGIN_AES_BAD_LENGTH:   return "INVALID_NONCE_TAG_OR_CIPHERTEXT_LENGTH";
    case AIRNGIN_AES_AUTH_FAIL:    return "AUTHENTICATION_FAILED";
    case AIRNGIN_AES_NO_MEM:       return "OUT_OF_MEMORY";
    case AIRNGIN_AES_CRYPTO_FAIL:  return "CRYPTO_FAILURE";
    case AIRNGIN_AES_TOO_SMALL:    return "OUTPUT_BUFFER_TOO_SMALL";
    default:                       return "?";
    }
}

void airngin_aes_replay_reset(airngin_aes_replay_t *r)
{
    if (r) airngin_secure_zero(r, sizeof(*r));
}

bool airngin_aes_key_decode(const char *b64, uint8_t key[AIRNGIN_AES_KEY_LEN])
{
    if (!b64 || !key) return false;
    const size_t len = strnlen(b64, AIRNGIN_AES_KEY_B64_MAX + 2U);
    if (len == 0U || len > AIRNGIN_AES_KEY_B64_MAX) return false;
    uint8_t decoded[AIRNGIN_AES_KEY_LEN + 4U];
    size_t written = 0;
    const bool ok = lan_b64_decode(decoded, sizeof(decoded), &written, (const unsigned char *)b64, len) == 0 &&
                    written == AIRNGIN_AES_KEY_LEN;
    if (ok) memcpy(key, decoded, AIRNGIN_AES_KEY_LEN);
    airngin_secure_zero(decoded, sizeof(decoded));
    return ok;
}

bool airngin_aes_key_valid(const char *b64)
{
    uint8_t key[AIRNGIN_AES_KEY_LEN];
    const bool ok = airngin_aes_key_decode(b64, key);
    airngin_secure_zero(key, sizeof(key));
    return ok;
}

/* Base64 into `out` (capacity includes the NUL). */
static bool b64_encode(const uint8_t *in, size_t n, char *out, size_t cap)
{
    static const char digits[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if (cap < AIRNGIN_B64_LEN(n) + 1U) return false;
    size_t j = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t bits = (uint32_t)in[i] << 16;
        if (i + 1 < n) bits |= (uint32_t)in[i+1] << 8;
        if (i + 2 < n) bits |= in[i+2];
        out[j++] = digits[bits >> 18];
        out[j++] = digits[(bits >> 12) & 63];
        out[j++] = i + 1 < n ? digits[(bits >> 6) & 63] : '=';
        out[j++] = i + 2 < n ? digits[bits & 63] : '=';
    }
    out[j] = 0;
    return true;
}

airngin_aes_result_t airngin_aes_seal(const uint8_t key[AIRNGIN_AES_KEY_LEN], const char *serial, int64_t timestamp,
                                      const uint8_t nonce[AIRNGIN_AES_NONCE_LEN], const uint8_t *plain, size_t plain_len,
                                      char *out, size_t out_capacity, size_t *out_len)
{
    if (!key || !serial || !nonce || !plain || !out || !out_len) return AIRNGIN_AES_BAD_ARG;
    if (plain_len == 0U || plain_len > AIRNGIN_AES_PLAIN_MAX || timestamp < AIRNGIN_AES_MIN_EPOCH) {
        return timestamp < AIRNGIN_AES_MIN_EPOCH ? AIRNGIN_AES_NO_CLOCK : AIRNGIN_AES_BAD_ARG;
    }
    const size_t serial_len = strnlen(serial, 64U);
    if (serial_len == 0U || serial_len > 14U) return AIRNGIN_AES_BAD_ARG;
    for (size_t i = 0; i < serial_len; ++i) {
        const char c = serial[i];
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))) return AIRNGIN_AES_BAD_ARG;
    }
    if (out_capacity < AIRNGIN_AES_ENVELOPE_CAP(plain_len)) return AIRNGIN_AES_TOO_SMALL;

    uint8_t *cipher = malloc(plain_len);
    if (!cipher) return AIRNGIN_AES_NO_MEM;
    uint8_t tag[AIRNGIN_AES_TAG_LEN];
    airngin_aes_result_t result = AIRNGIN_AES_CRYPTO_FAIL;
    if (lan_gcm(true, key, nonce, plain, plain_len, cipher, tag)) {
        char nonce_b64[AIRNGIN_B64_LEN(AIRNGIN_AES_NONCE_LEN) + 1U], tag_b64[AIRNGIN_B64_LEN(AIRNGIN_AES_TAG_LEN) + 1U];
        const size_t cipher_b64_cap = AIRNGIN_B64_LEN(plain_len) + 1U;
        char *cipher_b64 = malloc(cipher_b64_cap);
        if (!cipher_b64) {
            result = AIRNGIN_AES_NO_MEM;
        } else if (!b64_encode(nonce, AIRNGIN_AES_NONCE_LEN, nonce_b64, sizeof(nonce_b64)) ||
                   !b64_encode(tag, sizeof(tag), tag_b64, sizeof(tag_b64)) ||
                   !b64_encode(cipher, plain_len, cipher_b64, cipher_b64_cap)) {
            result = AIRNGIN_AES_CRYPTO_FAIL;
        } else {
            char decimal[21];
            char *digits = decimal+sizeof decimal-1;
            *digits = 0;
            uint64_t epoch = (uint64_t)timestamp;
            do { *--digits = (char)('0'+epoch%10); } while ((epoch/=10) != 0);
            const int n = snprintf(out, out_capacity,
                                   "{\"nonce\":\"%s\",\"ciphertext\":\"%s\",\"tag\":\"%s\",\"version\":\"" AIRNGIN_AES_VERSION
                                   "\",\"timestamp\":%s,\"deviceSerial\":\"%s\",\"more\":\"\"}",
                                   nonce_b64, cipher_b64, tag_b64, digits, serial);
            if (n < 0 || (size_t)n >= out_capacity) {
                result = AIRNGIN_AES_TOO_SMALL;
            } else {
                *out_len = (size_t)n;
                result = AIRNGIN_AES_OK;
            }
        }
        free(cipher_b64);
    }
    airngin_secure_zero(cipher, plain_len);
    free(cipher);
    airngin_secure_zero(tag, sizeof(tag));
    return result;
}

static bool replay_seen(const airngin_aes_replay_t *r, const uint8_t nonce[AIRNGIN_AES_NONCE_LEN], int64_t now)
{
    for (size_t i = 0; i < AIRNGIN_AES_REPLAY_SLOTS; ++i) {
        if (r->slot[i].used && now - r->slot[i].seen_at <= AIRNGIN_AES_REPLAY_RETENTION &&
            !memcmp(r->slot[i].nonce, nonce, AIRNGIN_AES_NONCE_LEN)) {
            return true;
        }
    }
    return false;
}

/* A full cache rejects instead of forgetting a nonce that is still inside the window. */
static bool replay_remember(airngin_aes_replay_t *r, const uint8_t nonce[AIRNGIN_AES_NONCE_LEN], int64_t now)
{
    for (size_t i = 0; i < AIRNGIN_AES_REPLAY_SLOTS; ++i) {
        if (!r->slot[i].used || now - r->slot[i].seen_at > AIRNGIN_AES_REPLAY_RETENTION) {
            memcpy(r->slot[i].nonce, nonce, AIRNGIN_AES_NONCE_LEN);
            r->slot[i].seen_at = now;
            r->slot[i].used = true;
            return true;
        }
    }
    return false;
}

static const char *json_string(const cJSON *object, const char *name)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(object, name);
    return cJSON_IsString(item) ? item->valuestring : NULL;
}

airngin_aes_result_t airngin_aes_open(const uint8_t key[AIRNGIN_AES_KEY_LEN], const char *serial, int64_t now,
                                      airngin_aes_replay_t *replay, const char *envelope, size_t envelope_len,
                                      uint8_t *plain, size_t plain_capacity, size_t *plain_len, airngin_aes_info_t *info)
{
    airngin_aes_info_t scratch;
    if (!info) info = &scratch;
    memset(info, 0, sizeof(*info));
    if (!key || !serial || !replay || !envelope || !plain || !plain_len || plain_capacity == 0U) return AIRNGIN_AES_BAD_ARG;
    *plain_len = 0;
    if (envelope_len == 0U || envelope_len > AIRNGIN_AES_ENVELOPE_IN_MAX || memchr(envelope, 0, envelope_len)) {
        return AIRNGIN_AES_BAD_ENVELOPE;
    }

    /* 1. parse */
    const char *end = NULL;
    cJSON *root = cJSON_ParseWithLengthOpts(envelope, envelope_len, &end, false);
    if (!root) return AIRNGIN_AES_BAD_ENVELOPE;
    while (end < envelope + envelope_len && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) ++end;
    if (end != envelope + envelope_len || !cJSON_IsObject(root)) {
        cJSON_Delete(root);
        return AIRNGIN_AES_BAD_ENVELOPE;
    }

    /* 2. required fields */
    const char *nonce_b64 = json_string(root, "nonce");
    const char *cipher_b64 = json_string(root, "ciphertext");
    const char *tag_b64 = json_string(root, "tag");
    const char *version = json_string(root, "version");
    const cJSON *ts_item = cJSON_GetObjectItemCaseSensitive(root, "timestamp");
    const cJSON *serial_item = cJSON_GetObjectItemCaseSensitive(root, "deviceSerial");
    const cJSON *more_item = cJSON_GetObjectItemCaseSensitive(root, "more");
    airngin_aes_result_t result = AIRNGIN_AES_BAD_ENVELOPE;
    uint8_t *cipher = NULL;
    uint8_t *clear = NULL;
    size_t cipher_cap = 0;

    if (!nonce_b64 || !cipher_b64 || !tag_b64 || !version || !cJSON_IsNumber(ts_item)) goto done;
    if (serial_item && !cJSON_IsNull(serial_item) && !cJSON_IsString(serial_item)) goto done;
    if (more_item && !cJSON_IsNull(more_item) && !cJSON_IsString(more_item)) goto done;

    /* 3. version */
    info->version_ok = strcmp(version, AIRNGIN_AES_VERSION) == 0;
    if (!info->version_ok) { result = AIRNGIN_AES_BAD_VERSION; goto done; }

    /* 3b. addressed to this device (absent/empty = server did not name one) */
    if (cJSON_IsString(serial_item) && serial_item->valuestring[0] != '\0' && strcmp(serial_item->valuestring, serial) != 0) {
        result = AIRNGIN_AES_BAD_SERIAL;
        goto done;
    }

    /* 4. clock and timestamp window */
    if (now < AIRNGIN_AES_MIN_EPOCH) { result = AIRNGIN_AES_NO_CLOCK; goto done; }
    const double ts_d = ts_item->valuedouble;
    info->ciphertext_b64_len = strlen(cipher_b64);
    if (!(ts_d >= 0.0 && ts_d < 4.0e12) || ts_d != floor(ts_d)) goto done;
    info->timestamp = (int64_t)ts_d;
    const int64_t diff = now - info->timestamp;
    if (diff > AIRNGIN_AES_WINDOW_SECONDS || diff < -AIRNGIN_AES_WINDOW_SECONDS) { result = AIRNGIN_AES_STALE; goto done; }

    /* 5. nonce: decode, exact length, replay */
    uint8_t nonce[AIRNGIN_AES_NONCE_LEN + 4U], tag[AIRNGIN_AES_TAG_LEN + 4U];
    size_t nonce_n = 0, tag_n = 0, cipher_n = 0;
    if (strlen(nonce_b64) != AIRNGIN_B64_LEN(AIRNGIN_AES_NONCE_LEN)) { result = AIRNGIN_AES_BAD_LENGTH; goto done; }
    if (lan_b64_decode(nonce, sizeof(nonce), &nonce_n, (const unsigned char *)nonce_b64, strlen(nonce_b64)) != 0) {
        result = AIRNGIN_AES_BAD_BASE64;
        goto done;
    }
    info->nonce_len = nonce_n;
    if (nonce_n != AIRNGIN_AES_NONCE_LEN) { result = AIRNGIN_AES_BAD_LENGTH; goto done; }
    if (replay_seen(replay, nonce, now)) { result = AIRNGIN_AES_REPLAY; goto done; }

    /* 6. Base64 of tag and ciphertext */
    const size_t cipher_text_len = strlen(cipher_b64);
    if (strlen(tag_b64) != AIRNGIN_B64_LEN(AIRNGIN_AES_TAG_LEN)) { result = AIRNGIN_AES_BAD_LENGTH; goto done; }
    if (lan_b64_decode(tag, sizeof(tag), &tag_n, (const unsigned char *)tag_b64, strlen(tag_b64)) != 0) {
        result = AIRNGIN_AES_BAD_BASE64;
        goto done;
    }
    info->tag_len = tag_n;
    if (tag_n != AIRNGIN_AES_TAG_LEN) { result = AIRNGIN_AES_BAD_LENGTH; goto done; }
    if (cipher_text_len == 0U || cipher_text_len > AIRNGIN_AES_ENVELOPE_IN_MAX || cipher_text_len % 4U != 0U) {
        result = cipher_text_len == 0U || cipher_text_len > AIRNGIN_AES_ENVELOPE_IN_MAX ? AIRNGIN_AES_BAD_LENGTH : AIRNGIN_AES_BAD_BASE64;
        goto done;
    }
    cipher_cap = cipher_text_len / 4U * 3U + 3U;
    cipher = malloc(cipher_cap);
    clear = malloc(cipher_cap + 1U);
    if (!cipher || !clear) { result = AIRNGIN_AES_NO_MEM; goto done; }
    if (lan_b64_decode(cipher, cipher_cap, &cipher_n, (const unsigned char *)cipher_b64, cipher_text_len) != 0) {
        result = AIRNGIN_AES_BAD_BASE64;
        goto done;
    }
    if (cipher_n == 0U || cipher_n + 1U > plain_capacity) { result = cipher_n == 0U ? AIRNGIN_AES_BAD_LENGTH : AIRNGIN_AES_TOO_SMALL; goto done; }

    /* 7. authenticate + decrypt */
    {
        if (!lan_gcm(false, key, nonce, cipher, cipher_n, clear, tag)) {
            result = AIRNGIN_AES_AUTH_FAIL;
            goto done;
        }
    }

    /* 8. only now remember the nonce (an unauthenticated message must not fill the cache) */
    if (!replay_remember(replay, nonce, now)) { result = AIRNGIN_AES_REPLAY_FULL; goto done; }

    memcpy(plain, clear, cipher_n);
    plain[cipher_n] = '\0';
    *plain_len = cipher_n;
    result = AIRNGIN_AES_OK;

done:
    if (clear) { airngin_secure_zero(clear, cipher_cap + 1U); free(clear); }
    if (cipher) { airngin_secure_zero(cipher, cipher_cap); free(cipher); }
    cJSON_Delete(root);
    return result;
}
