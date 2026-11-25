#pragma once
#include <stddef.h>
#include <stdint.h>
namespace airngin_lan {
// DNS-SD responses for one enumerated AirNgin LAN setup service.
struct Discovery {
    explicit Discovery(const char *serial);
    bool query(const uint8_t *packet,size_t length,bool &unicast,size_t *endOfQuestions = nullptr) const;
    size_t answer(uint8_t *out,size_t capacity,const uint8_t ip[4],uint32_t ttl,bool flushCache = true) const;
    char host[24], instance[48], txt[20];
};
}
