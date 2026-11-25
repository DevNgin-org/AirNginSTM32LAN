/* Central topic builder: PLAIN and AES layouts. */
#include "airngin_topic.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    char t[64];
    assert(airngin_topic_build(AIRNGIN_TOPIC_DEVICE_TO_SERVER, false, "PRJ123", "VTRA0000000001", t, sizeof(t)) == 21 && !strcmp(t, "PRJ123/DeviceToServer"));
    assert(airngin_topic_build(AIRNGIN_TOPIC_SERVER_TO_DEVICE, false, "PRJ123", "VTRA0000000001", t, sizeof(t)) == 36 &&
           !strcmp(t, "PRJ123/ServerToDevice/VTRA0000000001"));
    assert(airngin_topic_build(AIRNGIN_TOPIC_DEVICE_TO_SERVER, true, "PRJ123", "VTRA0000000001", t, sizeof(t)) > 0 &&
           !strcmp(t, "PRJ123/DeviceToServer/AES"));
    assert(airngin_topic_build(AIRNGIN_TOPIC_SERVER_TO_DEVICE, true, "PRJ123", "VTRA0000000001", t, sizeof(t)) > 0 &&
           !strcmp(t, "PRJ123/ServerToDevice/VTRA0000000001/AES"));
    /* capacity: exact fit works, one byte less fails (never truncates silently) */
    assert(airngin_topic_build(AIRNGIN_TOPIC_DEVICE_TO_SERVER, true, "PRJ123", "S", t, 26) == 25);
    assert(airngin_topic_build(AIRNGIN_TOPIC_DEVICE_TO_SERVER, true, "PRJ123", "S", t, 25) == -1);
    assert(airngin_topic_build(AIRNGIN_TOPIC_SERVER_TO_DEVICE, true, NULL, "S", t, sizeof(t)) == -1);
    assert(airngin_topic_build(AIRNGIN_TOPIC_SERVER_TO_DEVICE, false, "P", NULL, t, sizeof(t)) == -1);
    /* worst-case project (20) and serial (14) fit the transport capacities */
    char p20[21]; memset(p20, 'P', 20); p20[20] = 0;
    char big[96];
    assert(airngin_topic_build(AIRNGIN_TOPIC_SERVER_TO_DEVICE, true, p20, "VTRA0000000001", big, sizeof(big)) == 20 + 16 + 14 + 4);
    assert(airngin_topic_build(AIRNGIN_TOPIC_DEVICE_TO_SERVER, true, p20, "VTRA0000000001", big, sizeof(big)) == 20 + 15 + 4);
    /* 1.5.0 topic families */
    assert(airngin_topic_build(AIRNGIN_TOPIC_TIME_UTC, false, "PRJ123", "S", t, sizeof(t)) > 0 && !strcmp(t, "PRJ123/Time"));
    assert(airngin_topic_build(AIRNGIN_TOPIC_TIME_TEHRAN, false, "PRJ123", "S", t, sizeof(t)) > 0 && !strcmp(t, "PRJ123/Time/Tehran"));
    /* Time is public: NO /AES suffix even in an AES build */
    assert(airngin_topic_build(AIRNGIN_TOPIC_TIME_UTC, true, "PRJ123", "S", t, sizeof(t)) > 0 && !strcmp(t, "PRJ123/Time"));
    assert(airngin_topic_build(AIRNGIN_TOPIC_TIME_TEHRAN, true, "PRJ123", "S", t, sizeof(t)) > 0 && !strcmp(t, "PRJ123/Time/Tehran"));
    assert(airngin_topic_is_public(AIRNGIN_TOPIC_TIME_UTC) && airngin_topic_is_public(AIRNGIN_TOPIC_TIME_TEHRAN));
    assert(!airngin_topic_is_public(AIRNGIN_TOPIC_NOTIFY_USER) && !airngin_topic_is_public(AIRNGIN_TOPIC_DEVICE_TO_SERVER));
    assert(airngin_topic_build(AIRNGIN_TOPIC_NOTIFY_CENTER, false, "PRJ123", NULL, t, sizeof(t)) > 0 && !strcmp(t, "PRJ123/SendNotificationToCenter"));
    assert(airngin_topic_build(AIRNGIN_TOPIC_NOTIFY_USER, false, "PRJ123", NULL, t, sizeof(t)) > 0 && !strcmp(t, "PRJ123/SendNotificationToUser"));
    assert(airngin_topic_build(AIRNGIN_TOPIC_NOTIFY_CENTER, true, "PRJ123", NULL, t, sizeof(t)) > 0 && !strcmp(t, "PRJ123/SendNotificationToCenter/AES"));
    assert(airngin_topic_build(AIRNGIN_TOPIC_NOTIFY_USER, true, "PRJ123", NULL, t, sizeof(t)) > 0 && !strcmp(t, "PRJ123/SendNotificationToUser/AES"));
    assert(airngin_topic_build(AIRNGIN_TOPIC_TIME_TEHRAN, false, "PRJ123", NULL, t, 17) == -1);        /* never truncates */
    assert(airngin_topic_build((airngin_topic_kind_t)99, false, "P", "S", t, sizeof(t)) == -1);
    { char big[96];   /* worst case: 20-char project + longest name + /AES must fit the transport capacity */
      assert(airngin_topic_build(AIRNGIN_TOPIC_NOTIFY_CENTER, true, p20, NULL, big, 20 + AIRNGIN_TOPIC_NAME_MAX + 4 + 1) == (int)(20 + AIRNGIN_TOPIC_NAME_MAX + 4)); }
    puts("topic builder tests passed");
    return 0;
}
