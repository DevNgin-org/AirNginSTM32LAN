#include "airngin_identity.h"
#include <string.h>

bool airngin_identity_valid(const char *serial, const char *producer)
{
    if (!serial || !producer || strlen(serial) != 14 || strlen(producer) != 4) return false;
    for (unsigned i = 0; i < 4; ++i) {
        unsigned char c = (unsigned char)producer[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))) return false;
    }
    if (memcmp(serial, producer, 4) != 0) return false;
    for (unsigned i = 4; i < 14; ++i) if (serial[i] < '0' || serial[i] > '9') return false;
    return true;
}
