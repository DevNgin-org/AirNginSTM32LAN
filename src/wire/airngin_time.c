#include "airngin_time.h"
#include "cJSON.h"
#include <math.h>
#include <string.h>

const char *airngin_time_parse_name(airngin_time_parse_t r)
{
    switch (r) {
    case AIRNGIN_TIME_PARSE_OK:               return "OK";
    case AIRNGIN_TIME_PARSE_BAD_ARG:          return "bad argument";
    case AIRNGIN_TIME_PARSE_TOO_LONG:         return "payload too long";
    case AIRNGIN_TIME_PARSE_NOT_JSON_OBJECT:  return "not a JSON object";
    case AIRNGIN_TIME_PARSE_MISSING_FIELD:    return "missing or mistyped field";
    case AIRNGIN_TIME_PARSE_BAD_TIME:         return "invalid time";
    case AIRNGIN_TIME_PARSE_BAD_DATE:         return "invalid date";
    case AIRNGIN_TIME_PARSE_BAD_NUMBER:       return "invalid number";
    case AIRNGIN_TIME_PARSE_OUT_OF_RANGE:     return "value out of range";
    default:                                  return "?";
    }
}

int airngin_time_normalize_digits(const char *in, size_t n, char *out, size_t cap)
{
    if (!in || !out || !cap) return -1;
    size_t o = 0;
    for (size_t i = 0; i < n;) {
        const unsigned char c = (unsigned char)in[i];
        char mapped = 0;
        size_t used = 1;
        if (c == 0xDB && i + 1U < n && (unsigned char)in[i + 1U] >= 0xB0 && (unsigned char)in[i + 1U] <= 0xB9) {   /* U+06F0..06F9 */
            mapped = (char)('0' + ((unsigned char)in[i + 1U] - 0xB0));
            used = 2;
        } else if (c == 0xD9 && i + 1U < n && (unsigned char)in[i + 1U] >= 0xA0 && (unsigned char)in[i + 1U] <= 0xA9) { /* U+0660..0669 */
            mapped = (char)('0' + ((unsigned char)in[i + 1U] - 0xA0));
            used = 2;
        }
        if (o + 1U >= cap) return -1;
        out[o++] = mapped ? mapped : (char)c;
        i += used;
    }
    out[o] = '\0';
    return (int)o;
}

/* Non-negative integer from a JSON number or a (normalized) digit string; whitespace around it is ignored. */
static bool field_uint(const cJSON *item, unsigned long *out)
{
    if (cJSON_IsNumber(item)) {
        const double d = item->valuedouble;
        if (!(d >= 0.0 && d < 1.0e9) || d != floor(d)) return false;
        *out = (unsigned long)d;
        return true;
    }
    if (!cJSON_IsString(item)) return false;
    char text[24];
    const int n = airngin_time_normalize_digits(item->valuestring, strnlen(item->valuestring, sizeof(text)), text, sizeof(text));
    if (n < 0) return false;
    const char *p = text;
    while (*p == ' ') ++p;
    if (*p < '0' || *p > '9') return false;
    unsigned long v = 0;
    size_t digits = 0;
    while (*p >= '0' && *p <= '9') {
        v = v * 10UL + (unsigned long)(*p - '0');
        if (++digits > 9U) return false;
        ++p;
    }
    while (*p == ' ') ++p;
    if (*p) return false;
    *out = v;
    return true;
}

/* Parse "A<sep>B[<sep>C]" where sep is one of `seps`; returns number of fields (2 or 3) or 0. Fields are 1-4 digits. */
static int split_numbers(const char *s, const char *seps, unsigned long v[3])
{
    int count = 0;
    while (*s == ' ') ++s;
    for (;;) {
        if (*s < '0' || *s > '9' || count == 3) return 0;
        unsigned long x = 0;
        int digits = 0;
        while (*s >= '0' && *s <= '9') {
            x = x * 10UL + (unsigned long)(*s - '0');
            if (++digits > 4) return 0;
            ++s;
        }
        v[count++] = x;
        if (*s && strchr(seps, *s)) { ++s; continue; }
        break;
    }
    while (*s == ' ') ++s;
    return *s ? 0 : count;
}

airngin_time_parse_t airngin_time_parse(const char *payload, size_t len, airngin_time_source_t source, airngin_time_info_t *out)
{
    if (!payload || !out || len == 0U) return AIRNGIN_TIME_PARSE_BAD_ARG;
    if (len > AIRNGIN_TIME_PAYLOAD_MAX) return AIRNGIN_TIME_PARSE_TOO_LONG;
    if (memchr(payload, 0, len)) return AIRNGIN_TIME_PARSE_NOT_JSON_OBJECT;
    const char *end = NULL;
    cJSON *root = cJSON_ParseWithLengthOpts(payload, len, &end, false);
    if (!root) return AIRNGIN_TIME_PARSE_NOT_JSON_OBJECT;
    while (end < payload + len && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) ++end;
    if (end != payload + len || !cJSON_IsObject(root)) {
        cJSON_Delete(root);
        return AIRNGIN_TIME_PARSE_NOT_JSON_OBJECT;
    }

    airngin_time_parse_t r = AIRNGIN_TIME_PARSE_MISSING_FIELD;
    airngin_time_info_t t;
    memset(&t, 0, sizeof(t));
    t.source = source;
    const cJSON *time_item = cJSON_GetObjectItemCaseSensitive(root, "time");
    const cJSON *date_item = cJSON_GetObjectItemCaseSensitive(root, "date");
    const cJSON *dow_item = cJSON_GetObjectItemCaseSensitive(root, "dayOfWeek");
    const cJSON *doy_item = cJSON_GetObjectItemCaseSensitive(root, "dayOfYear");
    const cJSON *week_item = cJSON_GetObjectItemCaseSensitive(root, "weekNumber");
    unsigned long hms[3] = {0, 0, 0}, ymd[3] = {0, 0, 0}, dow = 0, doy = 0, week = 0;
    char text[40];

    if (!cJSON_IsString(time_item) || !cJSON_IsString(date_item)) goto done;
    if (!dow_item || !doy_item || !week_item) goto done;

    if (airngin_time_normalize_digits(time_item->valuestring, strnlen(time_item->valuestring, sizeof(text)), text, sizeof(text)) < 0) {
        r = AIRNGIN_TIME_PARSE_BAD_TIME;
        goto done;
    }
    {
        const int n = split_numbers(text, ":", hms);
        if (n < 2) { r = AIRNGIN_TIME_PARSE_BAD_TIME; goto done; }   /* H:M or H:M:S */
        if (n == 2) hms[2] = 0;
    }
    if (airngin_time_normalize_digits(date_item->valuestring, strnlen(date_item->valuestring, sizeof(text)), text, sizeof(text)) < 0) {
        r = AIRNGIN_TIME_PARSE_BAD_DATE;
        goto done;
    }
    if (split_numbers(text, "/-", ymd) != 3) { r = AIRNGIN_TIME_PARSE_BAD_DATE; goto done; }
    if (!field_uint(dow_item, &dow) || !field_uint(doy_item, &doy) || !field_uint(week_item, &week)) {
        r = AIRNGIN_TIME_PARSE_BAD_NUMBER;
        goto done;
    }
    if (hms[0] > 23UL || hms[1] > 59UL || hms[2] > 59UL || ymd[0] < 1UL || ymd[0] > 9999UL || ymd[1] < 1UL || ymd[1] > 12UL ||
        ymd[2] < 1UL || ymd[2] > 31UL || dow > 7UL || doy < 1UL || doy > 366UL || week > 54UL) {
        r = AIRNGIN_TIME_PARSE_OUT_OF_RANGE;
        goto done;
    }
    t.hour = (uint8_t)hms[0]; t.minute = (uint8_t)hms[1]; t.second = (uint8_t)hms[2];
    t.year = (uint16_t)ymd[0]; t.month = (uint8_t)ymd[1]; t.day = (uint8_t)ymd[2];
    t.day_of_week = (uint8_t)dow; t.day_of_year = (uint16_t)doy; t.week_number = (uint8_t)week;
    *out = t;
    r = AIRNGIN_TIME_PARSE_OK;
done:
    cJSON_Delete(root);
    return r;
}
