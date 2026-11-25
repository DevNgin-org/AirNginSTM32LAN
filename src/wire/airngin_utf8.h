#pragma once

#include <stdbool.h>
#include <stddef.h>

/*
 * Strict UTF-8 validation (RFC 3629): rejects overlong forms, surrogates,
 * code points above U+10FFFF and truncated sequences. cJSON does not validate
 * UTF-8, so inbound MQTT payloads are checked here before parsing.
 */
static inline bool airngin_utf8_valid(const unsigned char *s, size_t n)
{
    for (size_t i = 0; i < n;) {
        unsigned c = s[i++];
        unsigned extra, minimum;
        if (c < 0x80U) continue;
        if (c >= 0xc2U && c <= 0xdfU) { extra = 1U; minimum = 0x80U; c &= 0x1fU; }
        else if (c >= 0xe0U && c <= 0xefU) { extra = 2U; minimum = 0x800U; c &= 0x0fU; }
        else if (c >= 0xf0U && c <= 0xf4U) { extra = 3U; minimum = 0x10000U; c &= 0x07U; }
        else return false;
        if (extra > n - i) return false;
        while (extra--) {
            if ((s[i] & 0xc0U) != 0x80U) return false;
            c = (c << 6) | (s[i++] & 0x3fU);
        }
        if (c < minimum || c > 0x10ffffU || (c >= 0xd800U && c <= 0xdfffU)) return false;
    }
    return true;
}
