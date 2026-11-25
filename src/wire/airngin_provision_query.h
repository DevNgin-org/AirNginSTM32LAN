#pragma once

#include <stdbool.h>
#include <stddef.h>

#define AIRNGIN_PROVISION_JSON_MAX 4096U
#define AIRNGIN_PROVISION_ENCODED_JSON_MAX (AIRNGIN_PROVISION_JSON_MAX * 3U)
#define AIRNGIN_PROVISION_QUERY_MAX ((sizeof("data=") - 1U) + AIRNGIN_PROVISION_ENCODED_JSON_MAX)
#define AIRNGIN_PROVISION_SET_URI_MAX ((sizeof("/set?") - 1U) + AIRNGIN_PROVISION_QUERY_MAX)

bool airngin_provision_decode_query(const char *query, size_t query_len,
                                    char *output, size_t output_capacity,
                                    size_t *output_len);
