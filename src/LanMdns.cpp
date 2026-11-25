#include "AirNginSTM32LAN.h"
#include "LanDiscovery.h"

static const IPAddress group(224,0,0,251);
static void answer(EthernetUDP &socket,const char *serial,IPAddress dest,uint16_t port,uint32_t ttl) {
    uint8_t packet[384], addr[4];
    IPAddress ip = Ethernet.localIP();
    for (unsigned i=0;i<4;++i) addr[i]=ip[i];
    airngin_lan::Discovery discovery(serial);
    size_t n=discovery.answer(packet,sizeof packet,addr,ttl);
    if (n && socket.beginPacket(dest,port)) {
        socket.write(packet,n);
        socket.endPacket();
    }
}

void AirNginSTM32LAN::announceMdns(uint32_t ttl) { answer(multicast,serial,group,5353,ttl); }

void AirNginSTM32LAN::pollMdns() {
    uint8_t packet[768];
    int n = multicast.parsePacket();
    if (n<=0 || (size_t)n>sizeof packet || multicast.read(packet,n)!=n) return;
    bool unicast=false;
    airngin_lan::Discovery discovery(serial);
    size_t questionEnd = 0;
    if (!discovery.query(packet,n,unicast,&questionEnd)) return;
    // Multicast-DNS clients use port 5353. Dart may send a one-shot query
    // from an ephemeral port: echo its question section and transaction ID.
    if (multicast.remotePort()!=5353) {
        uint8_t reply[384], addr[4];
        IPAddress ip=Ethernet.localIP();
        for (unsigned i=0;i<4;++i) addr[i]=ip[i];
        size_t len=discovery.answer(reply,sizeof reply,addr,10,false);
        if (!len || !multicast.beginPacket(multicast.remoteIP(),multicast.remotePort())) return;
        reply[0]=packet[0]; reply[1]=packet[1]; reply[4]=packet[4]; reply[5]=packet[5];
        multicast.write(reply,12); multicast.write(packet+12,questionEnd-12); multicast.write(reply+12,len-12);
        multicast.endPacket();
        return;
    }
    answer(multicast,serial,unicast ? multicast.remoteIP() : group,5353,120);
}
