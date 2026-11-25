#include "LanWire.h"
#include "wire/cJSON.h"
#include "wire/airngin_utf8.h"
extern "C" {
#include "wire/airngin_crypto.h"
}
#include <string.h>

namespace airngin_lan {
static cJSON *object(const char *data, size_t size) {
    if (!data || !size || size > 4096 || memchr(data, 0, size) ||
        !airngin_utf8_valid((const unsigned char *)data, size)) return nullptr;
    for (size_t i = 0; i + 1 < size; ++i) {
        if (data[i] == '\\') {
            if (size - i >= 6 && memcmp(data+i+1, "u0000", 5) == 0) return nullptr;
            ++i;
        }
    }
    const char *end = nullptr;
    cJSON *root = cJSON_ParseWithLengthOpts(data, size, &end, false);
    if (!root) return nullptr;
    while (end < data + size && strchr(" \t\r\n", *end)) ++end;
    bool ok = end == data + size && cJSON_IsObject(root);
    for (cJSON *v = root->child; ok && v; v = v->next)
        for (cJSON *prev = root->child; prev != v; prev = prev->next)
            if (!strcmp(v->string,prev->string)) { ok = false; break; }
    if (ok) return root;
    cJSON_Delete(root);
    return nullptr;
}

static bool field(cJSON *obj, const char *name, char *out, size_t cap, bool profile, bool allowEmpty = false) {
    const char *s = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(obj, name));
    if (!s) return false;
    size_t n = strlen(s);
    if ((!allowEmpty && !n) || n >= cap) return false;
    if (profile) for (size_t i = 0; i < n; ++i)
        if ((unsigned char)s[i] < 32 || s[i] == 127) return false;
    memcpy(out, s, n+1);
    return true;
}

static bool hostValid(const char *s) {
    unsigned label = 0;
    for (size_t i = 0; s[i]; ++i) {
        const char c = s[i];
        if (c == '.') {
            if (!label || s[i-1] == '-') return false;
            label = 0;
        } else {
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || (label && c == '-')) || ++label > 63) return false;
        }
    }
    return label && s[strlen(s)-1] != '-';
}

bool parseProfile(const char *data, size_t length, bool aes, Profile &profile) {
    cJSON *root = object(data,length);
    if (!root) return false;
    Profile p{};
    cJSON *mode = cJSON_GetObjectItemCaseSensitive(root,"isUseEncrypted");
    cJSON *close = cJSON_GetObjectItemCaseSensitive(root,"closeConfig");
    bool ok = (!mode || (cJSON_IsBool(mode) && (bool)cJSON_IsTrue(mode) == aes)) &&
        (!close || cJSON_IsBool(close)) &&
        field(root,"projectCode",p.project,sizeof p.project,true) && !strpbrk(p.project,"/#+") &&
        field(root,"mqttBroker",p.host,sizeof p.host,true) && hostValid(p.host) &&
        field(root,"mqttUser",p.user,sizeof p.user,true) && field(root,"mqttPass",p.password,sizeof p.password,true) &&
        field(root,"clientId",p.client,sizeof p.client,true) &&
        (!aes || (field(root,"encryptionKey",p.aesKey,sizeof p.aesKey,true) && airngin_aes_key_valid(p.aesKey)));
    cJSON_Delete(root);
    if (ok) profile = p;
    return ok;
}

bool parseCommand(const char *data, size_t length, const char *serial, Command &command) {
    cJSON *outer = object(data,length);
    if (!outer) return false;
    const char *id = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(outer,"deviceSerial"));
    const char *body = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(outer,"data"));
    cJSON *inner = id && body && serial && !strcmp(id,serial) && cJSON_GetArraySize(outer)==2 ?
        object(body,strlen(body)) : nullptr;
    Command parsed{};
    bool ok = inner && cJSON_GetArraySize(inner)==2 &&
        field(inner,"key",parsed.key,sizeof parsed.key,false) &&
        field(inner,"value",parsed.value,sizeof parsed.value,false,true);
    cJSON_Delete(inner);
    cJSON_Delete(outer);
    if (ok) command = parsed;
    return ok;
}

bool report(const char *key, const char *value, char *out, size_t capacity) {
    if (!key || !*key || !value || !out || strlen(key)>64 || strlen(value)>512 ||
        !airngin_utf8_valid((const unsigned char *)key,strlen(key)) ||
        !airngin_utf8_valid((const unsigned char *)value,strlen(value))) return false;
    cJSON *array = cJSON_CreateArray();
    cJSON *entry = cJSON_CreateObject();
    if (!array || !entry) { cJSON_Delete(array); cJSON_Delete(entry); return false; }
    cJSON_AddItemToArray(array,entry);
    bool ok = cJSON_AddStringToObject(entry,"key",key) && cJSON_AddStringToObject(entry,"value",value) &&
              cJSON_PrintPreallocated(array,out,capacity,false);
    cJSON_Delete(array);
    return ok;
}
}
