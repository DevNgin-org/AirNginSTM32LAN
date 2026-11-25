#include "CryptoPort.h"
#include <bearssl.h>
#include <string.h>

void airngin_secure_zero(void *data, size_t length) {
    volatile uint8_t *p = data;
    while (length--) *p++ = 0;
}

static int digit(uint8_t c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int lan_b64_decode(uint8_t *out, size_t capacity, size_t *written, const uint8_t *text, size_t length) {
    *written = 0;
    if (!length || length % 4) return -1;
    for (size_t i = 0; i < length; i += 4) {
        const int a = digit(text[i]), b = digit(text[i+1]);
        const bool pad2 = text[i+2] == '=', pad3 = text[i+3] == '=';
        const int c = pad2 ? 0 : digit(text[i+2]), d = pad3 ? 0 : digit(text[i+3]);
        if (a < 0 || b < 0 || c < 0 || d < 0 || (pad2 && !pad3) ||
            ((pad2 || pad3) && i + 4 != length) || (pad2 && (b & 15)) ||
            (pad3 && !pad2 && (c & 3)) || capacity - *written < (size_t)(3 - pad2 - pad3)) return -1;
        out[(*written)++] = (uint8_t)((a << 2) | (b >> 4));
        if (!pad2) out[(*written)++] = (uint8_t)((b << 4) | (c >> 2));
        if (!pad3) out[(*written)++] = (uint8_t)((c << 6) | d);
    }
    return 0;
}

bool lan_gcm(bool encrypt, const uint8_t key[32], const uint8_t nonce[12],
             const uint8_t *input, size_t size, uint8_t *output, uint8_t tag[16]) {
    br_aes_ct_ctr_keys aes;
    br_gcm_context gcm;
    br_aes_ct_ctr_init(&aes, key, 32);
    br_gcm_init(&gcm, &aes.vtable, br_ghash_ctmul32);
    br_gcm_reset(&gcm, nonce, 12);
    br_gcm_flip(&gcm);
    memcpy(output, input, size);
    br_gcm_run(&gcm, encrypt, output, size);
    bool ok = true;
    if (encrypt) br_gcm_get_tag(&gcm, tag);
    else ok = br_gcm_check_tag(&gcm, tag) == 1;
    if (!ok) airngin_secure_zero(output, size);
    airngin_secure_zero(&gcm, sizeof gcm);
    airngin_secure_zero(&aes, sizeof aes);
    return ok;
}
