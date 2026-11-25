#include "AirNginSTM32LAN.h"
#include "MqttRoot.h"
#include <EEPROM.h>
#include "wire/cJSON.h"
#include "wire/airngin_utf8.h"
#include <memory>
extern "C" {
#include "wire/airngin_identity.h"
#include "wire/airngin_topic.h"
}

static constexpr uint16_t setupPort = 45454;
static uint32_t checksum(const void *data, size_t length) {
    auto p = static_cast<const uint8_t *>(data);
    uint32_t crc = 0xffffffff;
    while (length--) {
        crc ^= *p++;
        for (int bit=0; bit<8; ++bit) crc = (crc >> 1) ^ ((0u - (crc & 1u)) & 0xedb88320u);
    }
    return ~crc;
}

AirNginSTM32LAN::AirNginSTM32LAN(int entropyPin) :
    tls(tcp, &mqttRoot, 1, entropyPin), mqtt(4352, 512) {}

bool AirNginSTM32LAN::begin(const char *id, const char *producer, Clock clock,
                            CommandHandler handler, RandomBytes aesRandom, unsigned eepromOffset) {
    if (utc || !clock || !airngin_identity_valid(id,producer) ||
        eepromOffset > EEPROM.length() || sizeof(Record) > EEPROM.length() - eepromOffset) return false;
    strcpy(serial,id);
    utc = clock;
    handle = handler;
    random = aesRandom;
    offset = eepromOffset;
    mqtt.begin(tls);
    mqtt.setOptions(60,true,5000);
    mqtt.dropOverflow(true);
    mqtt.ref = this;
    mqtt.onMessageAdvanced(+[](MQTTClient *m,char *topic,char *data,int n) {
        static_cast<AirNginSTM32LAN *>(m->ref)->receive(topic,data,n);
    });
    Record record{};
    readRecord(record);
    if (!memcmp(record.magic,"AGN1",4) && !memcmp(record.serial,serial,sizeof serial) &&
        record.aesMode == (random != nullptr) && record.crc == checksum(&record,offsetof(Record,crc))) activate(record.profile);
    return true;
}

void AirNginSTM32LAN::readRecord(Record &r) {
    auto bytes = reinterpret_cast<uint8_t *>(&r);
    eeprom_buffer_fill();
    for (size_t i=0; i<sizeof r; ++i) bytes[i] = eeprom_buffered_read_byte(offset+i);
}

bool AirNginSTM32LAN::save(const airngin_lan::Profile &p) {
    Record r{}, previous{};
    memcpy(r.magic,"AGN1",4);
    memcpy(r.serial,serial,sizeof serial);
    r.aesMode = random != nullptr;
    r.profile = p;
    r.crc = checksum(&r,offsetof(Record,crc));
    readRecord(previous);
    if (!memcmp(&r,&previous,sizeof r)) return true;
    const auto bytes = reinterpret_cast<const uint8_t *>(&r);
    for (size_t i=0; i<sizeof r; ++i) eeprom_buffered_write_byte(offset+i,bytes[i]);
    eeprom_buffer_flush();
    readRecord(previous);
    return !memcmp(&r,&previous,sizeof r);
}

void AirNginSTM32LAN::activate(const airngin_lan::Profile &p) {
    if (random && !airngin_aes_key_decode(p.aesKey,key)) return;
    if (memcmp(profile.aesKey,p.aesKey,sizeof p.aesKey)) airngin_aes_replay_reset(&replay);
    hasTime = false;
    profile = p;
    if (timeSource >= 0)
        airngin_topic_build(timeSource == AIRNGIN_TIME_SOURCE_UTC ? AIRNGIN_TOPIC_TIME_UTC : AIRNGIN_TOPIC_TIME_TEHRAN,
                            false,profile.project,serial,timeTopic,sizeof timeTopic);
    airngin_topic_build(AIRNGIN_TOPIC_SERVER_TO_DEVICE,random,profile.project,serial,incoming,sizeof incoming);
    airngin_topic_build(AIRNGIN_TOPIC_DEVICE_TO_SERVER,random,profile.project,serial,outgoing,sizeof outgoing);
    mqtt.setHost(profile.host,8883);
    configured = true;
    attempted = millis()-5000;
}

bool AirNginSTM32LAN::startProvisioning() {
    if (!utc || configuring) return false;
    if (mqtt.connected()) mqtt.disconnect();
    subscribed = false;
    count = first = 0;
    if (!udp.begin(setupPort)) {
        finishProvisioning();
        return false;
    }
    http.begin();
    if (!http) { finishProvisioning(); return false; }
    opened = millis();
    announced = opened-1000;
    paused = false;
    configuring = true;
    return true;
}

void AirNginSTM32LAN::finishProvisioning() {
    closeHttp();
    // Ethernet 2.x does not expose Server::end(). Release our port on the W5x00.
    for (uint8_t i=0; i<MAX_SOCK_NUM; ++i) {
        if (EthernetServer::server_port[i] == 80) {
            EthernetClient(i).stop();
            EthernetServer::server_port[i] = 0;
        }
    }
    udp.stop();
    configuring = paused = false;
    attempted = millis()-5000;
}

void AirNginSTM32LAN::pollProvisioning() {
    uint32_t now = millis();
    if (now-opened >= 180000) { finishProvisioning(); return; }
    pollHttp();
    if (!configuring) return;
    if (!paused && now-announced >= 1000) {
        announced = now;
        char advert[240];
        snprintf(advert,sizeof advert,"{\"name\":\"DVC-%s-key\",\"ip\":\"%s\",\"gateway\":\"%s\","
            "\"subnet\":\"%s\",\"dns\":\"%s\",\"deviceSerial\":\"%s\"}",serial,Ethernet.localIP().toString().c_str(),
            Ethernet.gatewayIP().toString().c_str(),Ethernet.subnetMask().toString().c_str(),
            Ethernet.dnsServerIP().toString().c_str(),serial);
        if (udp.beginPacket(IPAddress(255,255,255,255),setupPort)) {
            udp.write(reinterpret_cast<const uint8_t *>(advert),strlen(advert));
            udp.endPacket();
        }
    }
    int size = udp.parsePacket();
    if (size <= 0 || size > 4096) return;
    std::unique_ptr<char[]> packet(new(std::nothrow) char[size+1]);
    if (!packet || udp.read(packet.get(),size) != size) return;
    char *data = packet.get();
    data[size] = 0;
    if (size == 4 && !memcmp(data,"STOP",4)) { paused = true; return; }
    if (size == 5 && !memcmp(data,"START",5)) { paused = false; return; }
    if (size == 6 && !memcmp(data,"FINISH",6)) { finishProvisioning(); return; }
    airngin_lan::Profile next{};
    if (airngin_lan::parseProfile(data,size,random,next) && save(next)) {
        activate(next);
        finishProvisioning();
    }
}

void AirNginSTM32LAN::receive(const char *topic, const char *body, int length) {
    if (timeSource >= 0 && topic && !strcmp(topic,timeTopic)) {
        airngin_time_info_t parsed{};
        if (length > 0 && airngin_time_parse(body,length,(airngin_time_source_t)timeSource,&parsed)==AIRNGIN_TIME_PARSE_OK) {
            parsed.received_at_ms=millis();
            timeValue=parsed;
            hasTime=true;
        }
        return;
    }
    if (!topic || strcmp(topic,incoming) || length <= 0 || length > 4096 || !handle) return;
    if (count == 4) { ++dropped; return; }
    std::unique_ptr<uint8_t[]> clear;
    size_t n = length;
    if (random) {
        clear.reset(new(std::nothrow) uint8_t[AIRNGIN_AES_PLAIN_IN_MAX+1]);
        if (!clear || airngin_aes_open(key,serial,utc(),&replay,body,length,clear.get(),
            AIRNGIN_AES_PLAIN_IN_MAX+1,&n,nullptr) != AIRNGIN_AES_OK) return;
        body = reinterpret_cast<const char *>(clear.get());
    }
    if (airngin_lan::parseCommand(body,n,serial,queue[(first+count)%4])) ++count;
}

void AirNginSTM32LAN::poll() {
    if (!utc) return;
    IPAddress ip = Ethernet.localIP();
    if (Ethernet.linkStatus() == LinkOFF || ip == IPAddress(0,0,0,0)) {
        if (configuring) finishProvisioning();
        if (mdnsActive) multicast.stop();
        if (mqtt.connected()) mqtt.disconnect();
        mdnsActive = subscribed = false;
        return;
    }
    if (!mdnsActive || ip != advertisedIP) {
        if (millis()-lastJoin >= 1000) {
            lastJoin = millis();
            multicast.stop();
            mdnsActive = multicast.beginMulticast(IPAddress(224,0,0,251),5353);
            if (mdnsActive) {
                advertisedIP = ip;
                announceMdns(120);
                lastAdvertisement = millis()-59000;
            }
        }
    }
    if (mdnsActive) {
        pollMdns();
        if (millis()-lastAdvertisement >= 60000) {
            announceMdns(120);
            lastAdvertisement = millis();
        }
    }
    // A new board can be commissioned as soon as DHCP succeeds. Replacing a
    // stored profile requires the local button, while discovery stays available.
    if (firstNetwork && mdnsActive) {
        if (configured || startProvisioning()) firstNetwork = false;
    }
    if (configuring) { pollProvisioning(); return; }
    if (!configured) return;
    if (!mqtt.connected()) {
        subscribed = false;
        first = count = 0;
        uint32_t now = millis();
        if (now-attempted < 5000) return;
        attempted = now;
        uint32_t epoch = utc();
        if (epoch < AIRNGIN_AES_MIN_EPOCH) return;
        tls.removeSession(profile.host);
        tls.setVerificationTime(719528u+epoch/86400u,epoch%86400u);
        if (!mqtt.connect(profile.client,profile.user,profile.password)) return;
        subscribed = mqtt.subscribe(incoming,1);
        if (subscribed && timeSource >= 0) subscribed = mqtt.subscribe(timeTopic,0);
        if (!subscribed) { mqtt.disconnect(); return; }
    }
    if (!mqtt.loop() || !count) return;
    Command cmd = queue[first], reply{};
    first = (first+1)%4;
    --count;
    strcpy(reply.key,cmd.key);
    if (handle(cmd,reply) && memchr(reply.key,0,sizeof reply.key) && memchr(reply.value,0,sizeof reply.value))
        publish(reply.key,reply.value);
}

bool AirNginSTM32LAN::publish(const char *name, const char *value) {
    if (!ready() || !name || !value) return false;
    if (strnlen(name,65)>64 || strnlen(value,513)>512) return false;
    size_t capacity = 32 + 6*(strlen(name)+strlen(value));
    std::unique_ptr<char[]> body(new(std::nothrow) char[capacity]);
    if (!body || !airngin_lan::report(name,value,body.get(),capacity)) return false;
    return send(outgoing,body.get());
}

bool AirNginSTM32LAN::send(const char *topic,const char *body) {
    if (!random) return mqtt.publish(topic,body,false,1);
    uint8_t nonce[AIRNGIN_AES_NONCE_LEN];
    if (!random(nonce,sizeof nonce)) return false;
    size_t plain = strlen(body), len = 0, cap = AIRNGIN_AES_ENVELOPE_CAP(plain);
    std::unique_ptr<char[]> envelope(new(std::nothrow) char[cap]);
    return envelope && airngin_aes_seal(key,serial,utc(),nonce,(const uint8_t *)body,plain,
        envelope.get(),cap,&len) == AIRNGIN_AES_OK && mqtt.publish(topic,envelope.get(),len,false,1);
}

bool AirNginSTM32LAN::followTime(airngin_time_source_t source) {
    if (source != AIRNGIN_TIME_SOURCE_UTC && source != AIRNGIN_TIME_SOURCE_TEHRAN) return false;
    if (source == timeSource) return true;
    if (!stopTime()) return false;
    if (configured) {
        airngin_topic_build(source==AIRNGIN_TIME_SOURCE_UTC ? AIRNGIN_TOPIC_TIME_UTC : AIRNGIN_TOPIC_TIME_TEHRAN,
                            false,profile.project,serial,timeTopic,sizeof timeTopic);
        if (ready() && !mqtt.subscribe(timeTopic,0)) return false;
    }
    timeSource = source;
    hasTime = false;
    return true;
}

bool AirNginSTM32LAN::stopTime() {
    if (timeSource >= 0 && ready() && !mqtt.unsubscribe(timeTopic)) return false;
    timeSource = -1;
    return true;
}

bool AirNginSTM32LAN::latestTime(airngin_time_info_t &value) const {
    if (hasTime) value = timeValue;
    return hasTime;
}

bool AirNginSTM32LAN::notify(Notification destination,const char *code) {
    if (!ready() || !code) return false;
    size_t n = strnlen(code,65);
    if (!n || n>64 || !airngin_utf8_valid((const unsigned char *)code,n)) return false;
    for (size_t i=0;i<n;++i) if ((unsigned char)code[i]<32 || code[i]==127) return false;
    const char *suffix;
    switch (destination) {
        case Notification::Center: suffix="}"; break;
        case Notification::Sms: suffix=",\"type\":20}"; break;
        case Notification::Push: suffix=",\"type\":30}"; break;
        default: return false;
    }
    char topic[64], quoted[144], body[176];
    cJSON *item=cJSON_CreateString(code);
    if (!item) return false;
    bool ok=cJSON_PrintPreallocated(item,quoted,sizeof quoted,false);
    cJSON_Delete(item);
    if (!ok) return false;
    snprintf(body,sizeof body,"{\"code\":%s%s",quoted,suffix);
    airngin_topic_build(destination==Notification::Center ? AIRNGIN_TOPIC_NOTIFY_CENTER : AIRNGIN_TOPIC_NOTIFY_USER,
                        random,profile.project,serial,topic,sizeof topic);
    return send(topic,body);
}
