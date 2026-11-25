#include "airngin_provision_query.h"

#include <string.h>

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool airngin_provision_decode_query(const char *query, size_t query_len,
                                    char *output, size_t output_capacity,
                                    size_t *output_len)
{
    if (!query || !output || !output_len || query_len < 6U ||
        query_len > AIRNGIN_PROVISION_QUERY_MAX || output_capacity == 0U ||
        memcmp(query, "data=", sizeof("data=") - 1U) != 0) {
        return false;
    }

    size_t decoded_len = 0;
    for (size_t i = sizeof("data=") - 1U; i < query_len; ++i) {
        int c = (unsigned char)query[i];
        if (c == '&') return false;
        if (c == '%') {
            if (i + 2U >= query_len) return false;
            int high = hex_value(query[i + 1U]);
            int low = hex_value(query[i + 2U]);
            if (high < 0 || low < 0) return false;
            c = high * 16 + low;
            i += 2U;
        } else if (c == '+') {
            c = ' ';
        }
        if (c == 0 || decoded_len == AIRNGIN_PROVISION_JSON_MAX ||
            decoded_len + 1U >= output_capacity) {
            return false;
        }
        output[decoded_len++] = (char)c;
    }
    output[decoded_len] = '\0';
    *output_len = decoded_len;
    return true;
}
