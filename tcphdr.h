#pragma once

#include <arpa/inet.h>

struct TcpHdr {
    uint16_t sport_;
    uint16_t dport_;
    uint32_t seq_;
    uint32_t ack_;
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t x:4; // unused
    uint8_t offset_:4;
#endif
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t offset:4;
    u_int8_t x:4; // unused
#endif
    uint8_t flag_;
    uint16_t winsize_;
    uint16_t chksum_;
    uint16_t urgptr_;

    uint8_t offset() {return ntohs(offset_);}

    /* flag */
    enum: uint8_t{
        FIN = 0x01,
        RST = 0x04,
        ACK = 0x10
    };
};
typedef TcpHdr *PTcpHdr;
