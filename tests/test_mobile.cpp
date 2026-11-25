#include "LanWire.h"
#include "LanDiscovery.h"
extern "C" {
#include "wire/airngin_provision_query.h"
}
#include <cassert>
#include <cstring>
#include <string>

int main() {
    const char *serial = "TEST0000000000";
    airngin_lan::Discovery discovery(serial);
    uint8_t q[]={0,0,0,0,0,1,0,0,0,0,0,0,8,'_','m','a','t','t','e','r','c',4,'_','u','d','p',5,'l','o','c','a','l',0,0,12,0,1};
    bool unicast;
    assert(discovery.query(q,sizeof q,unicast) && !unicast);
    q[sizeof q-2]=128;
    assert(discovery.query(q,sizeof q,unicast) && unicast);
    q[13]='X'; assert(!discovery.query(q,sizeof q,unicast));
    q[12]=0xc0; q[13]=12; assert(!discovery.query(q,sizeof q,unicast));
    uint8_t reply[384],ip[]={192,0,2,1};
    size_t n=discovery.answer(reply,sizeof reply,ip,120);
    assert(n>12 && reply[7]==4 && !memcmp(reply+n-4,ip,4));
    assert(!discovery.answer(reply,24,ip,120));
    std::string wire((char*)reply,n);
    assert(wire.find("sn=TEST0000000000")!=std::string::npos && wire.find("gw=")==std::string::npos);

    const char *profile=R"({"mqttBroker":"mqtt.example.org","mqttUser":"u","mqttPass":"p+%&","clientId":"id","modemSsid":"","modemPass":"","projectCode":"PROJECT","closeConfig":true})";
    const char hex[]="0123456789ABCDEF";
    std::string query="data=";
    for (const unsigned char c:std::string(profile)) { query += '%'; query+=hex[c>>4]; query+=hex[c&15]; }
    char decoded[1024]; size_t bytes;
    assert(airngin_provision_decode_query(query.c_str(),query.size(),decoded,sizeof decoded,&bytes));
    airngin_lan::Profile p{};
    assert(airngin_lan::parseProfile(decoded,bytes,false,p) && !strcmp(p.password,"p+%&"));
    assert(!airngin_lan::parseProfile(decoded,bytes,true,p));
    assert(!airngin_lan::parseProfile("{}",2,false,p) && !strcmp(p.client,"id"));
    std::string broken=std::string(profile).substr(0,strlen(profile)-1)+",\"mqttUser\":\"other\"}";
    assert(!airngin_lan::parseProfile(broken.data(),broken.size(),false,p));
    const char *message=R"({"deviceSerial":"TEST0000000000","data":"{\"key\":\"ch1\",\"value\":\"on\"}"})";
    airngin_lan::Command cmd{};
    assert(airngin_lan::parseCommand(message,strlen(message),serial,cmd) && !strcmp(cmd.value,"on"));
    assert(!airngin_lan::parseCommand(message,strlen(message),"TEST0000000001",cmd));
    assert(!airngin_lan::parseCommand(message,strlen(message)-1,serial,cmd));
    assert(airngin_lan::report(cmd.key,cmd.value,decoded,sizeof decoded));
    assert(!strcmp(decoded,R"([{"key":"ch1","value":"on"}])"));
}
