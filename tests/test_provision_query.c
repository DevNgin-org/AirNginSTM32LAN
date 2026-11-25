#include "airngin_provision_query.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void test_worst_case_boundary(void)
{
    char *query = malloc(AIRNGIN_PROVISION_QUERY_MAX + 1U);
    char *decoded = malloc(AIRNGIN_PROVISION_JSON_MAX + 1U);
    assert(query && decoded);
    memcpy(query, "data=", 5U);
    for (size_t i = 0; i < AIRNGIN_PROVISION_JSON_MAX; ++i) {
        memcpy(query + 5U + i * 3U, "%41", 3U);
    }
    query[AIRNGIN_PROVISION_QUERY_MAX] = '\0';

    size_t decoded_len = 0;
    assert(airngin_provision_decode_query(query, AIRNGIN_PROVISION_QUERY_MAX,
                                          decoded, AIRNGIN_PROVISION_JSON_MAX + 1U,
                                          &decoded_len));
    assert(decoded_len == AIRNGIN_PROVISION_JSON_MAX);
    assert(decoded[0] == 'A' && decoded[decoded_len - 1U] == 'A');
    free(decoded);
    free(query);
}

static void test_rejections(void)
{
    char output[AIRNGIN_PROVISION_JSON_MAX + 1U];
    size_t output_len = 0;
    char *too_long_decoded = malloc(5U + AIRNGIN_PROVISION_JSON_MAX + 1U);
    assert(too_long_decoded);
    memcpy(too_long_decoded, "data=", 5U);
    memset(too_long_decoded + 5U, 'A', AIRNGIN_PROVISION_JSON_MAX + 1U);

    assert(!airngin_provision_decode_query(too_long_decoded,
                                           5U + AIRNGIN_PROVISION_JSON_MAX + 1U,
                                           output, sizeof(output), &output_len));
    assert(!airngin_provision_decode_query("data=%4", 8U, output, sizeof(output), &output_len));
    assert(!airngin_provision_decode_query("data=%GG", 8U, output, sizeof(output), &output_len));
    assert(!airngin_provision_decode_query("data={}&extra=x", 15U, output, sizeof(output), &output_len));
    assert(!airngin_provision_decode_query("data=x", AIRNGIN_PROVISION_QUERY_MAX + 1U,
                                           output, sizeof(output), &output_len));
    free(too_long_decoded);
}

static void test_single_decode_and_plus(void)
{
    char output[AIRNGIN_PROVISION_JSON_MAX + 1U];
    size_t output_len = 0;
    const char query[] = "data=%2520+A";
    assert(airngin_provision_decode_query(query, sizeof(query) - 1U,
                                          output, sizeof(output), &output_len));
    assert(output_len == 5U);
    assert(strcmp(output, "%20 A") == 0);
}

static void test_hash_and_limits(void)
{
    char output[AIRNGIN_PROVISION_JSON_MAX + 1U];
    size_t n = 0;
    /* A raw '#' never reaches the server (clients strip the fragment); %23 is data. Documented
     * behaviour of the decoder, unchanged from the baseline: it passes through as a character. */
    const char raw[] = "data={\"a\":1}#frag";
    assert(airngin_provision_decode_query(raw, sizeof(raw) - 1U, output, sizeof(output), &n));
    const char enc[] = "data=%23";
    assert(airngin_provision_decode_query(enc, sizeof(enc) - 1U, output, sizeof(output), &n) && n == 1U && output[0] == '#');
    /* NUL after decoding, empty payload and short query are rejected */
    assert(!airngin_provision_decode_query("data=%00", 8U, output, sizeof(output), &n));
    assert(!airngin_provision_decode_query("data=", 5U, output, sizeof(output), &n));
    /* exact body/query limits */
    assert(AIRNGIN_PROVISION_JSON_MAX == 4096U);
    char tail[] = "data=%4";
    assert(!airngin_provision_decode_query(tail, sizeof(tail) - 1U, output, sizeof(output), &n));
    /* output buffer too small is refused rather than overrun */
    assert(!airngin_provision_decode_query("data=abcdef", 11U, output, 4U, &n));
}

int main(void)
{
    assert(AIRNGIN_PROVISION_QUERY_MAX == 12293U);
    assert(AIRNGIN_PROVISION_SET_URI_MAX == 12298U);
    test_worst_case_boundary();
    test_rejections();
    test_single_decode_and_plus();
    test_hash_and_limits();
    puts("provision query boundary tests passed");
    return 0;
}
