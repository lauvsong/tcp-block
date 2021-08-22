#pragma once

#include <arpa/inet.h>
#include "ip.h"

struct IpHdr final{
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t hlen_:4;
    uint8_t ver_:4;
#endif
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t ver_:4;
    uint8_t hlen_:4;
#endif
    uint8_t tos_;
    uint16_t tlen_;
    uint16_t id_;
    uint16_t offset_;
    uint8_t ttl_;
    uint8_t protocol_;
    uint16_t chksum_;
    Ip sip_;
    Ip dip_;

    uint8_t protocol() {return ntohs(protocol_);}
    uint16_t tlen() {return ntohs(tlen_);}
    uint16_t offset() {return ntohs(offset_);}

    /* protocol */
    enum: uint8_t {
        TCP = 6
    };
};
typedef IpHdr *PIpHdr;
