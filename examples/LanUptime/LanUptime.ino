#include <AirNginSTM32LAN.h>
#include <NTPClient.h>
#include <Dhcp.h>

AirNginSTM32LAN device(A0); // Keep this analog input free for SSLClient.
EthernetUDP timeSocket;
NTPClient timeClient(timeSocket);
const char serialNumber[] = "TEST0000000000"; // Replace with your registered serial.
const char producer[] = "TEST";
byte mac[6];
bool hasLease = false;
uint32_t lastDhcp = 0, lastNtp = 0, lastReport = 0, pressedAt = 0;
bool held = false, consumed = false;

uint32_t utcNow() { return timeClient.isTimeSet() ? timeClient.getEpochTime() : 0; }

bool command(const AirNginSTM32LAN::Command &cmd, AirNginSTM32LAN::Command &reply) {
    if (strcmp(cmd.key,"ch1") || (strcmp(cmd.value,"on") && strcmp(cmd.value,"off"))) return false;
    static bool switchState;
    switchState = !strcmp(cmd.value,"on");
    strcpy(reply.value,switchState ? "on" : "off");
    return true;
}

void setup() {
    Serial.begin(115200);
    pinMode(A0,INPUT);
    pinMode(PC13,INPUT_PULLUP);
    pinMode(4,OUTPUT); // D4 deselects the SD card on a standard Ethernet shield.
    digitalWrite(4,HIGH);
    Ethernet.init(10);
    // FNV-1a over the full chip UID. Locally administered unicast MAC.
    uint32_t uid[] = {HAL_GetUIDw0(),HAL_GetUIDw1(),HAL_GetUIDw2()};
    uint64_t hash = 14695981039346656037ULL;
    for (size_t i=0; i<sizeof uid; ++i) hash = (hash ^ ((uint8_t *)uid)[i])*1099511628211ULL;
    for (unsigned i=0; i<6; ++i) mac[i] = hash >> (8*i);
    mac[0] = (mac[0] & 0xfc) | 2;
    if (!device.begin(serialNumber,producer,utcNow,command)) {
        Serial.println("Invalid identity or EEPROM range");
        while (true) delay(1000);
    }
    lastDhcp = millis()-5000;
}

void loop() {
    uint32_t now = millis();
    if (!hasLease) {
        if (now-lastDhcp < 5000) return;
        lastDhcp = now;
        if (!Ethernet.begin(mac,3500,1000)) return;
        hasLease = true;
        lastNtp = millis()-10000;
        timeClient.begin();
        Serial.println("Ethernet ready. Hold the user button for 3 seconds to provision.");
        return;
    }
    int lease = Ethernet.maintain();
    if (lease == DHCP_CHECK_REBIND_FAIL) { hasLease = false; return; }
    if (digitalRead(PC13) == LOW) {
        if (!held) { held = true; pressedAt = now; }
        if (!consumed && now-pressedAt >= 3000) {
            consumed = device.startProvisioning();
            if (consumed) Serial.println("LAN setup open for 3 minutes");
        }
    } else { held = consumed = false; }
    if (!device.provisioning() && now-lastNtp >= 10000) {
        lastNtp = now;
        timeClient.update();
    }
    device.poll();
    if (device.ready() && now-lastReport >= 30000) {
        lastReport = now;
        char value[16];
        snprintf(value,sizeof value,"%lu",(unsigned long)(now/1000));
        Serial.println(device.publish("uptime_seconds",value) ? "Uptime acknowledged by MQTT" : "Publish failed");
    }
}
