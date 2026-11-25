/* AirNgin AES-256-GCM envelope: known-answer tests against an INDEPENDENT implementation (Node.js / OpenSSL) and the
 * published NIST/McGrew-Viega GCM test case 15, plus every rejection rule of the canonical receive order. */
#include "airngin_crypto.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SERIAL "VTRA0000000001"
static const uint8_t KEY[32] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31};
static const uint8_t NONCE[12] = {0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab,0xac};
#define KEY_B64 "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
#define PLAIN "[{\"key\":\"output\",\"value\":\"on\"}]"
/* produced by Node.js crypto.createCipheriv('aes-256-gcm') with the key/nonce above, timestamp 1800000000 */
#define FIXTURE "{\"nonce\":\"oaKjpKWmp6ipqqus\",\"ciphertext\":\"fZSlBJEsHFWsEccEJLe4UU61XE4bMDGl2L1YPkZlOg==\"," \
                "\"tag\":\"pfsuFCeiKG+XyG0viatnBA==\",\"version\":\"1.0\",\"timestamp\":1800000000," \
                "\"deviceSerial\":\"" SERIAL "\",\"more\":\"\"}"
#define TS 1800000000LL

static airngin_aes_replay_t replay;
static uint8_t out[AIRNGIN_AES_PLAIN_IN_MAX + 8];
static size_t out_n;

static airngin_aes_result_t open_env(const char *env, int64_t now)
{
    return airngin_aes_open(KEY, SERIAL, now, &replay, env, strlen(env), out, sizeof(out), &out_n, NULL);
}

/* replace the first occurrence of `from` by `to` (same length) */
static void patch(char *s, const char *from, const char *to)
{
    char *p = strstr(s, from);
    assert(p && strlen(from) == strlen(to));
    memcpy(p, to, strlen(to));
}

static void hex2bin(const char *h, uint8_t *o) { for (; h[0]; h += 2) { unsigned v; sscanf(h, "%2x", &v); *o++ = (uint8_t)v; } }

int main(void)
{
    char env[AIRNGIN_AES_ENVELOPE_CAP(AIRNGIN_AES_PLAIN_MAX)];
    size_t n;

    /* ---- key handling ------------------------------------------------------------------------------------------ */
    uint8_t k[32];
    assert(airngin_aes_key_decode(KEY_B64, k) && !memcmp(k, KEY, 32));
    assert(airngin_aes_key_valid(KEY_B64));
    assert(!airngin_aes_key_valid("") && !airngin_aes_key_valid(NULL));
    assert(!airngin_aes_key_valid("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"));             /* 31 bytes (no padding char: 43 chars) */
    assert(!airngin_aes_key_valid("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8AAQ=="));       /* 34 bytes */
    assert(!airngin_aes_key_valid("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")); /* 64 hex chars: not Base64 of 32 bytes */
    assert(!airngin_aes_key_valid("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8*"));
    assert(!airngin_aes_key_valid("not base64 at all, but long enough to be 32 bytes....."));

    /* ---- known answer 1: NIST / McGrew-Viega GCM test case 15 (AES-256, 96-bit IV, no AAD) ------------------------- */
    {
        uint8_t key[32], nonce[12], pt[64];
        hex2bin("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", key);
        hex2bin("cafebabefacedbaddecaf888", nonce);
        hex2bin("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b391aafd255", pt);
        assert(airngin_aes_seal(key, SERIAL, TS, nonce, pt, sizeof(pt), env, sizeof(env), &n) == AIRNGIN_AES_OK);
        assert(strstr(env, "\"nonce\":\"yv66vvrO263eyviI\""));
        assert(strstr(env, "\"ciphertext\":\"Ui3B8JlWfQf0fzejKoRCfWQ6jNy/5cDJdZiivSVV0aqMsI5IWQ27PaewixBWgog4xfYeY5O6egq8yfZiiYAVrQ==\""));
        assert(strstr(env, "\"tag\":\"sJTaxdk0cb3sGlAicOPMbA==\""));
    }

    /* ---- known answer 2: whole AirNgin envelope, byte for byte against the Node.js output ----------------------- */
    assert(airngin_aes_seal(KEY, SERIAL, TS, NONCE, (const uint8_t *)PLAIN, strlen(PLAIN), env, sizeof(env), &n) == AIRNGIN_AES_OK);
    assert(n == strlen(FIXTURE) && !strcmp(env, FIXTURE));                       /* ESP output == backend-style output */
    assert(open_env(FIXTURE, TS) == AIRNGIN_AES_OK);                              /* and ESP accepts the foreign envelope */
    assert(out_n == strlen(PLAIN) && !strcmp((const char *)out, PLAIN));

    /* ---- replay --------------------------------------------------------------------------------------------------- */
    assert(open_env(FIXTURE, TS) == AIRNGIN_AES_REPLAY && out_n == 0);
    assert(open_env(FIXTURE, TS + 129) == AIRNGIN_AES_STALE);                     /* outside the window: stale first */
    airngin_aes_replay_reset(&replay);
    assert(open_env(FIXTURE, TS) == AIRNGIN_AES_OK);

    /* ---- timestamp window ----------------------------------------------------------------------------------------- */
    airngin_aes_replay_reset(&replay); assert(open_env(FIXTURE, TS + 60) == AIRNGIN_AES_OK);
    airngin_aes_replay_reset(&replay); assert(open_env(FIXTURE, TS - 60) == AIRNGIN_AES_OK);
    airngin_aes_replay_reset(&replay); assert(open_env(FIXTURE, TS + 61) == AIRNGIN_AES_STALE);
    airngin_aes_replay_reset(&replay); assert(open_env(FIXTURE, TS - 61) == AIRNGIN_AES_STALE);
    airngin_aes_replay_reset(&replay); assert(open_env(FIXTURE, 1000) == AIRNGIN_AES_NO_CLOCK);   /* clock never set */
    assert(airngin_aes_seal(KEY, SERIAL, 1000, NONCE, (const uint8_t *)PLAIN, strlen(PLAIN), env, sizeof(env), &n) == AIRNGIN_AES_NO_CLOCK);

    /* ---- tampering: nothing is returned, the nonce is NOT consumed ------------------------------------------------- */
    char t[sizeof(FIXTURE) + 8];
    airngin_aes_replay_reset(&replay);
    strcpy(t, FIXTURE); patch(t, "fZSlBJEs", "fZSlBJEt"); assert(open_env(t, TS) == AIRNGIN_AES_AUTH_FAIL && out_n == 0);   /* ciphertext */
    strcpy(t, FIXTURE); patch(t, "pfsuFCei", "pfsuFCej"); assert(open_env(t, TS) == AIRNGIN_AES_AUTH_FAIL);                 /* tag */
    strcpy(t, FIXTURE); patch(t, "oaKjpKWm", "oaKjpKWn"); assert(open_env(t, TS) == AIRNGIN_AES_AUTH_FAIL);                 /* nonce */
    assert(open_env(FIXTURE, TS) == AIRNGIN_AES_OK);                              /* the genuine message still works afterwards */
    {   /* wrong key */
        uint8_t wrong[32]; memcpy(wrong, KEY, 32); wrong[7] ^= 1;
        airngin_aes_replay_reset(&replay);
        assert(airngin_aes_open(wrong, SERIAL, TS, &replay, FIXTURE, strlen(FIXTURE), out, sizeof(out), &out_n, NULL) == AIRNGIN_AES_AUTH_FAIL);
        assert(open_env(FIXTURE, TS) == AIRNGIN_AES_OK);
    }

    /* ---- envelope validation ------------------------------------------------------------------------------------- */
    airngin_aes_replay_reset(&replay);
    assert(open_env("", TS) == AIRNGIN_AES_BAD_ENVELOPE);
    assert(open_env("not json", TS) == AIRNGIN_AES_BAD_ENVELOPE);
    assert(open_env("[]", TS) == AIRNGIN_AES_BAD_ENVELOPE);
    assert(open_env("{}", TS) == AIRNGIN_AES_BAD_ENVELOPE);
    strcpy(t, FIXTURE); strcat(t, "x"); assert(open_env(t, TS) == AIRNGIN_AES_BAD_ENVELOPE);                    /* trailing bytes */
    strcpy(t, FIXTURE); patch(t, "\"1.0\"", "\"2.0\""); assert(open_env(t, TS) == AIRNGIN_AES_BAD_VERSION);
    strcpy(t, FIXTURE); patch(t, "\"version\"", "\"versiom\""); assert(open_env(t, TS) == AIRNGIN_AES_BAD_ENVELOPE);   /* field missing */
    assert(open_env("{\"nonce\":\"oaKjpKWmp6ipqqus\",\"ciphertext\":\"fZSlBJEsHFWsEccEJLe4UU61XE4bMDGl2L1YPkZlOg==\",\"tag\":\"pfsuFCeiKG+XyG0viatnBA==\",\"version\":\"1.0\",\"timestamp\":\"1800000000\"}", TS) == AIRNGIN_AES_BAD_ENVELOPE);
    strcpy(t, FIXTURE); patch(t, SERIAL, "VTRA0000000002"); assert(open_env(t, TS) == AIRNGIN_AES_BAD_SERIAL);
    assert(open_env("{\"nonce\":\"oaKjpKWmp6ipqqus\",\"ciphertext\":\"fZSlBJEsHFWsEccEJLe4UU61XE4bMDGl2L1YPkZlOg==\",\"tag\":\"pfsuFCeiKG+XyG0viatnBA==\",\"version\":\"1.0\",\"timestamp\":1800000000}", TS) == AIRNGIN_AES_OK);   /* serial/more omitted */
    airngin_aes_replay_reset(&replay);
    assert(open_env("{\"nonce\":\"oaKjpKWmp6ipqqus\",\"ciphertext\":\"fZSlBJEsHFWsEccEJLe4UU61XE4bMDGl2L1YPkZlOg==\",\"tag\":\"pfsuFCeiKG+XyG0viatnBA==\",\"version\":\"1.0\",\"timestamp\":1800000000,\"deviceSerial\":null,\"more\":null}", TS) == AIRNGIN_AES_OK);
    airngin_aes_replay_reset(&replay);
    strcpy(t, FIXTURE); patch(t, "oaKjpKWmp6ipqqus", "oaKjpKWmp6ip!!us"); assert(open_env(t, TS) == AIRNGIN_AES_BAD_BASE64);
    assert(open_env("{\"nonce\":\"oaKjpKWm\",\"ciphertext\":\"fZSlBJEsHFWsEccEJLe4UU61XE4bMDGl2L1YPkZlOg==\",\"tag\":\"pfsuFCeiKG+XyG0viatnBA==\",\"version\":\"1.0\",\"timestamp\":1800000000}", TS) == AIRNGIN_AES_BAD_LENGTH);   /* 6-byte nonce */
    assert(open_env("{\"nonce\":\"oaKjpKWmp6ipqqus\",\"ciphertext\":\"fZSlBJEsHFWsEccEJLe4UU61XE4bMDGl2L1YPkZlOg==\",\"tag\":\"pfsuFCei\",\"version\":\"1.0\",\"timestamp\":1800000000}", TS) == AIRNGIN_AES_BAD_LENGTH);        /* 6-byte tag */
    assert(open_env("{\"nonce\":\"oaKjpKWmp6ipqqus\",\"ciphertext\":\"\",\"tag\":\"pfsuFCeiKG+XyG0viatnBA==\",\"version\":\"1.0\",\"timestamp\":1800000000}", TS) == AIRNGIN_AES_BAD_LENGTH);   /* empty ciphertext */
    {   char *big = malloc(AIRNGIN_AES_ENVELOPE_IN_MAX + 64); memset(big, ' ', AIRNGIN_AES_ENVELOPE_IN_MAX + 32); big[AIRNGIN_AES_ENVELOPE_IN_MAX + 32] = 0;
        memcpy(big, FIXTURE, strlen(FIXTURE));
        assert(airngin_aes_open(KEY, SERIAL, TS, &replay, big, AIRNGIN_AES_ENVELOPE_IN_MAX + 32, out, sizeof(out), &out_n, NULL) == AIRNGIN_AES_BAD_ENVELOPE);   /* oversize */
        free(big); }
    {   char nul[sizeof(FIXTURE)]; memcpy(nul, FIXTURE, sizeof(FIXTURE)); nul[10] = 0;
        assert(airngin_aes_open(KEY, SERIAL, TS, &replay, nul, sizeof(FIXTURE) - 1, out, sizeof(out), &out_n, NULL) == AIRNGIN_AES_BAD_ENVELOPE); }  /* embedded NUL */
    assert(airngin_aes_open(KEY, SERIAL, TS, &replay, FIXTURE, strlen(FIXTURE), out, 10, &out_n, NULL) == AIRNGIN_AES_TOO_SMALL);                    /* output buffer too small */
    assert(open_env(FIXTURE, TS) == AIRNGIN_AES_OK);                              /* nothing above consumed the nonce */

    /* ---- sizes: worst case, exact -------------------------------------------------------------------------------- */
    {
        uint8_t *big = malloc(AIRNGIN_AES_PLAIN_MAX + 1U); memset(big, 'a', AIRNGIN_AES_PLAIN_MAX + 1U);
        assert(airngin_aes_seal(KEY, SERIAL, TS, NONCE, big, AIRNGIN_AES_PLAIN_MAX + 1U, env, sizeof(env), &n) == AIRNGIN_AES_BAD_ARG);   /* oversize */
        assert(airngin_aes_seal(KEY, SERIAL, TS, NONCE, big, 0, env, sizeof(env), &n) == AIRNGIN_AES_BAD_ARG);                              /* empty */
        assert(airngin_aes_seal(KEY, SERIAL, 9223372036854775807LL, NONCE, big, AIRNGIN_AES_PLAIN_MAX, env, sizeof(env), &n) == AIRNGIN_AES_OK);
        assert(n == AIRNGIN_B64_LEN(AIRNGIN_AES_PLAIN_MAX) + 167U);               /* 19-digit timestamp, 14-char serial: the true worst case */
        assert(n + 1U <= AIRNGIN_AES_ENVELOPE_CAP(AIRNGIN_AES_PLAIN_MAX) && AIRNGIN_AES_ENVELOPE_FIXED >= 167U);
        assert(airngin_aes_seal(KEY, SERIAL, TS, NONCE, big, 100, env, 100, &n) == AIRNGIN_AES_TOO_SMALL);
        /* what the broker may deliver (4096-byte envelope) carries at most AIRNGIN_AES_PLAIN_IN_MAX plaintext bytes */
        size_t best = 0;
        for (size_t p = 2000; p <= 3100; ++p) {
            assert(airngin_aes_seal(KEY, SERIAL, TS, NONCE, big, p, env, sizeof(env), &n) == AIRNGIN_AES_OK);
            if (n <= AIRNGIN_AES_ENVELOPE_IN_MAX) best = p;
        }
        printf("max plaintext inside a 4096-byte envelope: %zu bytes (decode bound %u)\n", best, (unsigned)AIRNGIN_AES_PLAIN_IN_MAX);
        assert(best > 2800 && best <= AIRNGIN_AES_PLAIN_IN_MAX);
        airngin_aes_replay_reset(&replay);
        assert(airngin_aes_seal(KEY, SERIAL, TS, NONCE, big, best, env, sizeof(env), &n) == AIRNGIN_AES_OK && n <= AIRNGIN_AES_ENVELOPE_IN_MAX);
        assert(open_env(env, TS) == AIRNGIN_AES_OK && out_n == best && !memcmp(out, big, best));       /* round trip at the limit */
        assert(airngin_aes_seal(KEY, SERIAL, TS, NONCE, big, best + 100, env, sizeof(env), &n) == AIRNGIN_AES_OK);
        airngin_aes_replay_reset(&replay);
        assert(open_env(env, TS) == AIRNGIN_AES_BAD_ENVELOPE);                    /* envelope > 4096 is refused before any crypto */
        free(big);
    }

    /* ---- replay cache: full rejects (never forgets), expiry frees slots ------------------------------------------- */
    {
        airngin_aes_replay_reset(&replay);
        uint8_t nonce[12] = {0};
        for (unsigned i = 0; i < AIRNGIN_AES_REPLAY_SLOTS + 1U; ++i) {
            nonce[0] = (uint8_t)i;
            assert(airngin_aes_seal(KEY, SERIAL, TS, nonce, (const uint8_t *)PLAIN, strlen(PLAIN), env, sizeof(env), &n) == AIRNGIN_AES_OK);
            const airngin_aes_result_t r = open_env(env, TS);
            if (i < AIRNGIN_AES_REPLAY_SLOTS) assert(r == AIRNGIN_AES_OK);
            else assert(r == AIRNGIN_AES_REPLAY_FULL && out_n == 0);              /* rejected, and no plaintext leaves */
        }
        nonce[0] = 200;
        assert(airngin_aes_seal(KEY, SERIAL, TS + 140, nonce, (const uint8_t *)PLAIN, strlen(PLAIN), env, sizeof(env), &n) == AIRNGIN_AES_OK);
        assert(open_env(env, TS + 140) == AIRNGIN_AES_OK);                        /* old entries aged out of the retention window */
    }

    puts("AES crypto known-answer and rejection tests passed");
    return 0;
}
