#include "LanDiscovery.h"
#include <stdio.h>
#include <string.h>
#include <strings.h>

namespace airngin_lan {
static const char service[] = "_matterc._udp.local";

Discovery::Discovery(const char *serial) {
    snprintf(host,sizeof host,"%s.local",serial);
    snprintf(instance,sizeof instance,"%s.%s",serial,service);
    snprintf(txt,sizeof txt,"sn=%s",serial);
}

static bool readName(const uint8_t *p,size_t n,size_t &offset,char *out,size_t cap) {
    size_t cursor = offset, used = 0;
    bool jumped = false;
    for (unsigned steps=0; steps<128 && cursor<n; ++steps) {
        size_t labelAt = cursor;
        unsigned len = p[cursor++];
        if (!len) {
            if (!jumped) offset = cursor;
            out[used] = 0;
            return true;
        }
        if ((len & 0xc0) == 0xc0) {
            if (cursor>=n) return false;
            size_t target = ((len & 63)<<8) | p[cursor++];
            if (target>=labelAt) return false;
            if (!jumped) offset = cursor;
            cursor=target; jumped=true; continue;
        }
        if (len>63 || cursor+len>n || used+len+2>cap || memchr(p+cursor,0,len)) return false;
        if (used) out[used++]='.';
        memcpy(out+used,p+cursor,len);
        used+=len;
        cursor+=len;
    }
    return false;
}

bool Discovery::query(const uint8_t *p,size_t n,bool &unicast,size_t *endOfQuestions) const {
    unicast = false;
    if (n<12 || (p[2]&0xf8)) return false;
    unsigned count=(p[4]<<8)|p[5];
    size_t pos=12;
    bool match=false;
    for (unsigned i=0;i<count;++i) {
        char name[256];
        if (!readName(p,n,pos,name,sizeof name) || pos+4>n) return false;
        unsigned type=(p[pos]<<8)|p[pos+1], cls=(p[pos+2]<<8)|p[pos+3];
        pos+=4;
        if ((cls&0x7fff)!=1 && (cls&0x7fff)!=255) continue;
        if ((!strcasecmp(name,service) && (type==12 || type==255)) ||
            (!strcasecmp(name,instance) && (type==16 || type==33 || type==255)) ||
            (!strcasecmp(name,host) && (type==1 || type==255))) {
            match=true;
            if (cls&0x8000) unicast=true;
        }
    }
    if (endOfQuestions) *endOfQuestions = pos;
    return match;
}

struct Writer {
    uint8_t *bytes;
    size_t capacity, used;
    bool ok;
    void byte(unsigned v) {
        if (used==capacity) { ok=false; return; }
        bytes[used++]=v;
    }
    void word(unsigned v) { byte(v>>8); byte(v); }
    void name(const char *s) {
        while (*s) {
            size_t n=strcspn(s,".");
            byte(n);
            for (size_t i=0;i<n;++i) byte(*s++);
            if (*s) ++s;
        }
        byte(0);
    }
    size_t record(const char *owner,unsigned type,unsigned cls,uint32_t ttl) {
        name(owner); word(type); word(cls); word(ttl>>16); word(ttl); word(0);
        return used;
    }
    void end(size_t start) {
        if (ok) { bytes[start-2]=(used-start)>>8; bytes[start-1]=used-start; }
    }
};

size_t Discovery::answer(uint8_t *out,size_t capacity,const uint8_t ip[4],uint32_t ttl,bool flushCache) const {
    unsigned uniqueClass = flushCache ? 0x8001 : 1;
    Writer w{out,capacity,0,true};
    w.word(0); w.word(0x8400); w.word(0); w.word(4); w.word(0); w.word(0);
    size_t start=w.record(service,12,1,ttl);
    w.name(instance); w.end(start);
    start=w.record(instance,33,uniqueClass,ttl);
    w.word(0); w.word(0); w.word(45454); w.name(host); w.end(start);
    start=w.record(instance,16,uniqueClass,ttl);
    w.byte(strlen(txt));
    for (const char *s=txt;*s;++s) w.byte(*s);
    w.end(start);
    start=w.record(host,1,uniqueClass,ttl);
    for (unsigned i=0;i<4;++i) w.byte(ip[i]);
    w.end(start);
    return w.ok ? w.used : 0;
}
}
