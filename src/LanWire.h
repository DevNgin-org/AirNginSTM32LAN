#pragma once
#include <stddef.h>
#include <stdint.h>

namespace airngin_lan {
struct Profile {
    char project[21], host[101], user[17], password[17], client[39], aesKey[45];
};
struct Command {
    char key[65], value[513];
};
bool parseProfile(const char *data, size_t length, bool aes, Profile &profile);
bool parseCommand(const char *data, size_t length, const char *serial, Command &command);
bool report(const char *key, const char *value, char *out, size_t capacity);
}
