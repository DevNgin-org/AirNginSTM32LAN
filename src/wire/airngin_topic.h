#pragma once
/*
 * The ONLY place that spells AirNgin MQTT topics. Pure C (host tested).
 *   PLAIN: <project>/DeviceToServer              <project>/ServerToDevice/<serial>
 *   AES  : <project>/DeviceToServer/AES          <project>/ServerToDevice/<serial>/AES
 * The mode is a compile-time property of the firmware (CONFIG_AIRNGIN_USE_AES); `aes` is passed explicitly so
 * both layouts can be tested in one binary.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>


/* ESP-IDF leaves an unset bool undefined (not 0): use AIRNGIN_USE_AES wherever the mode is needed as a VALUE. */
#if defined(CONFIG_AIRNGIN_USE_AES) && CONFIG_AIRNGIN_USE_AES
#define AIRNGIN_USE_AES 1
#else
#define AIRNGIN_USE_AES 0
#endif

/* Every AirNgin topic family this SDK uses. Add future documented topics here (and only here). */
typedef enum {
    AIRNGIN_TOPIC_DEVICE_TO_SERVER = 0,   /* <project>/DeviceToServer[/AES]               publish   */
    AIRNGIN_TOPIC_SERVER_TO_DEVICE,       /* <project>/ServerToDevice/<serial>[/AES]      subscribe */
    AIRNGIN_TOPIC_TIME_UTC,               /* <project>/Time                                subscribe, public (never /AES) */
    AIRNGIN_TOPIC_TIME_TEHRAN,            /* <project>/Time/Tehran                         subscribe, public (never /AES) */
    AIRNGIN_TOPIC_NOTIFY_CENTER,          /* <project>/SendNotificationToCenter[/AES]      publish   */
    AIRNGIN_TOPIC_NOTIFY_USER,            /* <project>/SendNotificationToUser[/AES]        publish   */
} airngin_topic_kind_t;

#define AIRNGIN_TOPIC_AES_SUFFIX "/AES"
/* Longest topic body besides the project code (+ "/AES", + NUL are added by the caller's capacity macro). */
#define AIRNGIN_TOPIC_NAME_MAX   (sizeof("/SendNotificationToCenter") - 1U)

/* Public topics are shared by all devices of a project and carry no application-layer AES in any build. */
static inline bool airngin_topic_is_public(airngin_topic_kind_t kind)
{
    return kind == AIRNGIN_TOPIC_TIME_UTC || kind == AIRNGIN_TOPIC_TIME_TEHRAN;
}

/* Returns the topic length, or -1 if it does not fit `capacity` (including the NUL) or an argument is missing. */
static inline int airngin_topic_build(airngin_topic_kind_t kind, bool aes, const char *project, const char *serial,
                                      char *out, size_t capacity)
{
    if (!project || !out || !capacity) return -1;
    const char *suffix = (aes && !airngin_topic_is_public(kind)) ? AIRNGIN_TOPIC_AES_SUFFIX : "";
    int n;
    switch (kind) {
    case AIRNGIN_TOPIC_DEVICE_TO_SERVER: n = snprintf(out, capacity, "%s/DeviceToServer%s", project, suffix); break;
    case AIRNGIN_TOPIC_SERVER_TO_DEVICE:
        if (!serial) return -1;
        n = snprintf(out, capacity, "%s/ServerToDevice/%s%s", project, serial, suffix);
        break;
    case AIRNGIN_TOPIC_TIME_UTC:          n = snprintf(out, capacity, "%s/Time", project); break;
    case AIRNGIN_TOPIC_TIME_TEHRAN:       n = snprintf(out, capacity, "%s/Time/Tehran", project); break;
    case AIRNGIN_TOPIC_NOTIFY_CENTER:     n = snprintf(out, capacity, "%s/SendNotificationToCenter%s", project, suffix); break;
    case AIRNGIN_TOPIC_NOTIFY_USER:       n = snprintf(out, capacity, "%s/SendNotificationToUser%s", project, suffix); break;
    default: return -1;
    }
    return (n < 0 || (size_t)n >= capacity) ? -1 : n;
}
