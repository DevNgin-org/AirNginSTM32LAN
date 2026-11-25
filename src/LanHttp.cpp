#include "AirNginSTM32LAN.h"
extern "C" {
#include "wire/airngin_provision_query.h"
}

void AirNginSTM32LAN::closeHttp(const char *status) {
    if (peer) {
        if (status) {
            peer.print("HTTP/1.1 ");
            peer.print(status);
            peer.print("\r\nCache-Control: no-store\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
        peer.stop();
    }
    peer = EthernetClient();
    request.reset();
}

void AirNginSTM32LAN::pollHttp() {
    constexpr size_t maxLine = AIRNGIN_PROVISION_SET_URI_MAX + 16;
    if (!request) {
        peer = http.accept();
        if (!peer) return;
        request.reset(new(std::nothrow) char[maxLine+1]);
        if (!request) { closeHttp("503 Service Unavailable"); return; }
        peerSince = millis();
        lineLength = headerLength = 0;
        headers = false;
        blank = true;
    }
    if (millis()-peerSince > 5000 || !peer.connected()) { closeHttp(); return; }
    uint8_t buf[256];
    int n = peer.read(buf,sizeof buf);
    for (int i=0; i<n; ++i) {
        char c = buf[i];
        if (!headers) {
            if (!c || lineLength >= maxLine) { closeHttp("414 URI Too Long"); return; }
            if (c != '\n') { request[lineLength++] = c; continue; }
            if (!lineLength || request[lineLength-1] != '\r') { closeHttp("400 Bad Request"); return; }
            request[lineLength-1] = 0;
            headers = true;
            continue;
        }
        if (++headerLength > 4096) { closeHttp("431 Request Header Fields Too Large"); return; }
        if (c == '\r') continue;
        if (c != '\n') { blank = false; continue; }
        if (!blank) { blank = true; continue; }
        char *line = request.get();
        char *version = strrchr(line,' ');
        if (!version || (strcmp(version," HTTP/1.1") && strcmp(version," HTTP/1.0"))) {
            closeHttp("400 Bad Request"); return;
        }
        *version = 0;
        if (strncmp(line,"GET /set?",9)) { closeHttp("404 Not Found"); return; }
        const char *query = line+9;
        size_t length = 0;
        airngin_lan::Profile next{};
        // Decode towards the start of the same allocation. The destination always trails the read cursor.
        if (!airngin_provision_decode_query(query,strlen(query),line,AIRNGIN_PROVISION_JSON_MAX+1,&length) ||
            !airngin_lan::parseProfile(line,length,random,next)) { closeHttp("400 Bad Request"); return; }
        if (!save(next)) { closeHttp("500 Internal Server Error"); return; }
        activate(next);
        closeHttp("200 OK");
        finishProvisioning();
        return;
    }
}
