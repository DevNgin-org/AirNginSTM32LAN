#pragma once
#include <Arduino.h>
#include <Ethernet.h>
#include <EthernetUdp.h>
#include <MQTT.h>
#include <memory>
#include <SSLClient.h>
#include "LanWire.h"
extern "C" {
#include "wire/airngin_crypto.h"
#include "wire/airngin_time.h"
}

class AirNginSTM32LAN {
public:
    using Command = airngin_lan::Command;
    using CommandHandler = bool (*)(const Command &received, Command &reply);
    using Clock = uint32_t (*)();                 // UTC seconds, zero until synchronized
    using RandomBytes = bool (*)(uint8_t *, size_t); // cryptographic RNG for AES mode
    explicit AirNginSTM32LAN(int entropyPin);
    AirNginSTM32LAN(const AirNginSTM32LAN &) = delete;
    AirNginSTM32LAN &operator=(const AirNginSTM32LAN &) = delete;
    bool begin(const char *serial, const char *producer, Clock clock,
               CommandHandler handler = nullptr, RandomBytes aesRandom = nullptr, unsigned eepromOffset = 0);
    bool startProvisioning();
    bool provisioning() const { return configuring; }
    bool hasProfile() const { return configured; }
    bool ready() { return subscribed && mqtt.connected(); }
    void poll();
    bool publish(const char *key, const char *value);
    enum class Notification { Center, Sms, Push };
    bool notify(Notification destination, const char *code);
    bool followTime(airngin_time_source_t source);
    bool stopTime();
    bool latestTime(airngin_time_info_t &value) const;
    unsigned long droppedCommands() const { return dropped; }
private:
    struct Record {
        char magic[4], serial[15];
        uint8_t aesMode;
        airngin_lan::Profile profile;
        uint32_t crc;
    };
    void readRecord(Record &r);
    bool save(const airngin_lan::Profile &p);
    void activate(const airngin_lan::Profile &p);
    bool send(const char *topic,const char *plain);
    void pollProvisioning();
    int timeSource = -1;
    char timeTopic[48]{};
    bool hasTime = false;
    airngin_time_info_t timeValue{};
    void finishProvisioning();
    void receive(const char *topic, const char *body, int length);
    EthernetClient tcp;
    SSLClient tls;
    MQTTClient mqtt;
    void pollHttp();
    void closeHttp(const char *status = nullptr);
    EthernetUDP udp, multicast;
    void pollMdns();
    IPAddress advertisedIP;
    bool mdnsActive = false;
    bool firstNetwork = true;
    uint32_t lastJoin = uint32_t(-1000), lastAdvertisement = 0;
    void announceMdns(uint32_t ttl);
    EthernetServer http{80};
    EthernetClient peer;
    std::unique_ptr<char[]> request;
    size_t lineLength = 0, headerLength = 0;
    uint32_t peerSince = 0;
    bool headers = false, blank = true;
    Clock utc = nullptr;
    RandomBytes random = nullptr;
    CommandHandler handle = nullptr;
    unsigned offset = 0;
    char serial[15]{}, incoming[64]{}, outgoing[64]{};
    airngin_lan::Profile profile{};
    airngin_aes_replay_t replay{};
    uint8_t key[32]{};
    uint32_t opened = 0, announced = 0, attempted = 0;
    bool configured = false, configuring = false, paused = false, subscribed = false;
    Command queue[4]{};
    uint8_t first = 0, count = 0;
    unsigned long dropped = 0;
};
