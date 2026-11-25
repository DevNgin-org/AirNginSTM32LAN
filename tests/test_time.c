/* AirNgin time feed payload parser: ASCII / Persian / Arabic-Indic digits, strings or numbers, malformed input, ranges. */
#include "airngin_time.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static airngin_time_parse_t parse(const char *json, airngin_time_info_t *t)
{
    memset(t, 0xAA, sizeof(*t));
    return airngin_time_parse(json, strlen(json), AIRNGIN_TIME_SOURCE_TEHRAN, t);
}
#define P(time, date, dow, doy, wk) "{\"time\":\"" time "\",\"date\":\"" date "\",\"dayOfWeek\":" dow ",\"dayOfYear\":" doy ",\"weekNumber\":" wk "}"

int main(void)
{
    airngin_time_info_t t;

    /* ASCII digits, numeric fields as strings (the documented rendering) */
    assert(parse(P("10:15:30", "2026/11/10", "\"3\"", "\"314\"", "\"46\""), &t) == AIRNGIN_TIME_PARSE_OK);
    assert(t.source == AIRNGIN_TIME_SOURCE_TEHRAN && t.year == 2026 && t.month == 11 && t.day == 10);
    assert(t.hour == 10 && t.minute == 15 && t.second == 30 && t.day_of_week == 3 && t.day_of_year == 314 && t.week_number == 46);
    assert(t.received_at_ms == 0);                                              /* left for the caller */
    /* numeric JSON values are accepted too */
    assert(parse(P("00:00:00", "2026/01/01", "0", "1", "0"), &t) == AIRNGIN_TIME_PARSE_OK && t.day_of_year == 1 && t.hour == 0);
    /* Persian digits U+06F0..06F9 */
    assert(parse(P("\xDB\xB1\xDB\xB0:\xDB\xB1\xDB\xB5:\xDB\xB3\xDB\xB0", "\xDB\xB2\xDB\xB0\xDB\xB2\xDB\xB6/\xDB\xB1\xDB\xB1/\xDB\xB1\xDB\xB0",
                   "\"\xDB\xB3\"", "\"\xDB\xB3\xDB\xB1\xDB\xB4\"", "\"\xDB\xB4\xDB\xB6\""), &t) == AIRNGIN_TIME_PARSE_OK);
    assert(t.year == 2026 && t.month == 11 && t.day == 10 && t.hour == 10 && t.minute == 15 && t.second == 30 && t.day_of_week == 3 && t.day_of_year == 314 && t.week_number == 46);
    /* Arabic-Indic digits U+0660..0669 */
    assert(parse(P("\xD9\xA1\xD9\xA0:\xD9\xA1\xD9\xA5:\xD9\xA3\xD9\xA0", "\xD9\xA2\xD9\xA0\xD9\xA2\xD9\xA6/\xD9\xA1\xD9\xA1/\xD9\xA1\xD9\xA0",
                   "\"\xD9\xA3\"", "\"\xD9\xA3\xD9\xA1\xD9\xA4\"", "\"\xD9\xA4\xD9\xA6\""), &t) == AIRNGIN_TIME_PARSE_OK);
    assert(t.year == 2026 && t.hour == 10 && t.second == 30 && t.day_of_year == 314 && t.week_number == 46);
    /* mixed scripts, H:M without seconds, '-' date separator, single-digit fields */
    assert(parse(P("9:05", "2026-1-5", "\"\xDB\xB3\"", "7", "\"1\""), &t) == AIRNGIN_TIME_PARSE_OK);
    assert(t.hour == 9 && t.minute == 5 && t.second == 0 && t.month == 1 && t.day == 5 && t.day_of_week == 3);
    assert(parse(" \t" P("23:59:59", "9999/12/31", "7", "366", "54") "\n", &t) == AIRNGIN_TIME_PARSE_OK && t.hour == 23 && t.year == 9999);
    /* UTC source is carried through */
    assert(airngin_time_parse(P("10:15:30", "2026/11/10", "3", "314", "46"), strlen(P("10:15:30", "2026/11/10", "3", "314", "46")),
                              AIRNGIN_TIME_SOURCE_UTC, &t) == AIRNGIN_TIME_PARSE_OK && t.source == AIRNGIN_TIME_SOURCE_UTC);

    /* normalization helper */
    { char o[16];
      assert(airngin_time_normalize_digits("\xDB\xB1\xD9\xA2x", 5, o, sizeof(o)) == 3 && !strcmp(o, "12x"));
      assert(airngin_time_normalize_digits("\xDB", 1, o, sizeof(o)) == 1);                          /* truncated lead byte passes through */
      assert(airngin_time_normalize_digits("123456", 6, o, 6) == -1 && airngin_time_normalize_digits("12345", 5, o, 6) == 5); }

    /* malformed JSON / structure */
    assert(parse("", &t) == AIRNGIN_TIME_PARSE_BAD_ARG);
    assert(parse("not json", &t) == AIRNGIN_TIME_PARSE_NOT_JSON_OBJECT);
    assert(parse("[]", &t) == AIRNGIN_TIME_PARSE_NOT_JSON_OBJECT);
    assert(parse(P("10:15:30", "2026/11/10", "3", "314", "46") "x", &t) == AIRNGIN_TIME_PARSE_NOT_JSON_OBJECT);
    assert(parse("{\"time\":\"10:15:30\"", &t) == AIRNGIN_TIME_PARSE_NOT_JSON_OBJECT);
    { char big[AIRNGIN_TIME_PAYLOAD_MAX + 8]; memset(big, ' ', sizeof(big)); big[sizeof(big) - 1] = 0;
      assert(airngin_time_parse(big, strlen(big), AIRNGIN_TIME_SOURCE_UTC, &t) == AIRNGIN_TIME_PARSE_TOO_LONG); }
    { const char nul[] = "{\"time\":\"10:15:30\"\0}"; assert(airngin_time_parse(nul, sizeof(nul) - 1, AIRNGIN_TIME_SOURCE_UTC, &t) == AIRNGIN_TIME_PARSE_NOT_JSON_OBJECT); }
    assert(airngin_time_parse(NULL, 3, AIRNGIN_TIME_SOURCE_UTC, &t) == AIRNGIN_TIME_PARSE_BAD_ARG);

    /* each required field is required, and typed */
    assert(parse("{\"date\":\"2026/11/10\",\"dayOfWeek\":3,\"dayOfYear\":314,\"weekNumber\":46}", &t) == AIRNGIN_TIME_PARSE_MISSING_FIELD);
    assert(parse("{\"time\":\"10:15:30\",\"dayOfWeek\":3,\"dayOfYear\":314,\"weekNumber\":46}", &t) == AIRNGIN_TIME_PARSE_MISSING_FIELD);
    assert(parse("{\"time\":\"10:15:30\",\"date\":\"2026/11/10\",\"dayOfYear\":314,\"weekNumber\":46}", &t) == AIRNGIN_TIME_PARSE_MISSING_FIELD);
    assert(parse("{\"time\":\"10:15:30\",\"date\":\"2026/11/10\",\"dayOfWeek\":3,\"weekNumber\":46}", &t) == AIRNGIN_TIME_PARSE_MISSING_FIELD);
    assert(parse("{\"time\":\"10:15:30\",\"date\":\"2026/11/10\",\"dayOfWeek\":3,\"dayOfYear\":314}", &t) == AIRNGIN_TIME_PARSE_MISSING_FIELD);
    assert(parse("{\"time\":1015,\"date\":\"2026/11/10\",\"dayOfWeek\":3,\"dayOfYear\":314,\"weekNumber\":46}", &t) == AIRNGIN_TIME_PARSE_MISSING_FIELD);

    /* bad time / date text */
    assert(parse(P("abc", "2026/11/10", "3", "314", "46"), &t) == AIRNGIN_TIME_PARSE_BAD_TIME);
    assert(parse(P("10", "2026/11/10", "3", "314", "46"), &t) == AIRNGIN_TIME_PARSE_BAD_TIME);
    assert(parse(P("10:15:30:00", "2026/11/10", "3", "314", "46"), &t) == AIRNGIN_TIME_PARSE_BAD_TIME);
    assert(parse(P("10:15:30", "2026/11", "3", "314", "46"), &t) == AIRNGIN_TIME_PARSE_BAD_DATE);
    assert(parse(P("10:15:30", "26.11.10", "3", "314", "46"), &t) == AIRNGIN_TIME_PARSE_BAD_DATE);
    assert(parse(P("10:15:30", "2026/11/10/1", "3", "314", "46"), &t) == AIRNGIN_TIME_PARSE_BAD_DATE);
    /* bad numbers */
    assert(parse(P("10:15:30", "2026/11/10", "\"x\"", "314", "46"), &t) == AIRNGIN_TIME_PARSE_BAD_NUMBER);
    assert(parse(P("10:15:30", "2026/11/10", "-1", "314", "46"), &t) == AIRNGIN_TIME_PARSE_BAD_NUMBER);
    assert(parse(P("10:15:30", "2026/11/10", "1.5", "314", "46"), &t) == AIRNGIN_TIME_PARSE_BAD_NUMBER);
    assert(parse(P("10:15:30", "2026/11/10", "3", "null", "46"), &t) == AIRNGIN_TIME_PARSE_BAD_NUMBER);
    assert(parse(P("10:15:30", "2026/11/10", "3", "\"3 1\"", "46"), &t) == AIRNGIN_TIME_PARSE_BAD_NUMBER);
    /* structural ranges (boundaries) */
    assert(parse(P("24:00:00", "2026/11/10", "3", "314", "46"), &t) == AIRNGIN_TIME_PARSE_OUT_OF_RANGE);
    assert(parse(P("10:60:00", "2026/11/10", "3", "314", "46"), &t) == AIRNGIN_TIME_PARSE_OUT_OF_RANGE);
    assert(parse(P("10:15:60", "2026/11/10", "3", "314", "46"), &t) == AIRNGIN_TIME_PARSE_OUT_OF_RANGE);
    assert(parse(P("10:15:30", "2026/13/10", "3", "314", "46"), &t) == AIRNGIN_TIME_PARSE_OUT_OF_RANGE);
    assert(parse(P("10:15:30", "2026/00/10", "3", "314", "46"), &t) == AIRNGIN_TIME_PARSE_OUT_OF_RANGE);
    assert(parse(P("10:15:30", "2026/11/32", "3", "314", "46"), &t) == AIRNGIN_TIME_PARSE_OUT_OF_RANGE);
    assert(parse(P("10:15:30", "2026/11/00", "3", "314", "46"), &t) == AIRNGIN_TIME_PARSE_OUT_OF_RANGE);
    assert(parse(P("10:15:30", "0000/11/10", "3", "314", "46"), &t) == AIRNGIN_TIME_PARSE_OUT_OF_RANGE);
    assert(parse(P("10:15:30", "2026/11/10", "8", "314", "46"), &t) == AIRNGIN_TIME_PARSE_OUT_OF_RANGE);
    assert(parse(P("10:15:30", "2026/11/10", "3", "0", "46"), &t) == AIRNGIN_TIME_PARSE_OUT_OF_RANGE);
    assert(parse(P("10:15:30", "2026/11/10", "3", "367", "46"), &t) == AIRNGIN_TIME_PARSE_OUT_OF_RANGE);
    assert(parse(P("10:15:30", "2026/11/10", "3", "314", "55"), &t) == AIRNGIN_TIME_PARSE_OUT_OF_RANGE);
    puts("time parser tests passed");
    return 0;
}
