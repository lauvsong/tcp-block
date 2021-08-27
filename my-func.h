#pragma once

#define PAYLOAD "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n"
#define PAYLOAD_SIZE 59

#include <cstdio>
#include <string.h>
#include <pcap.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdint.h>
#include <unistd.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"
#include "tcphdr.h"

#pragma pack(push, 1)
typedef struct TcpPacket final {
    EthHdr eth_;
    IpHdr  ip_;
    TcpHdr tcp_;
    char data_[65535];
}TcpPacket;
typedef TcpPacket *PTcpPacket;
#pragma pack(pop)

void usage();
Mac resolve_mymac(char* interface);
uint16_t calc_checksum(uint16_t* buf, uint size);
uint16_t resolve_IPchecksum(PIpHdr packet);
uint16_t resolve_TCPchecksum(PIpHdr iph, PTcpHdr tcph, u_char* data, uint data_size);
bool is_match(const u_char* packet, char* pattern);
void forward(pcap_t* handle , Mac mymac, const u_char* org_pkt);
void backward(pcap_t* handle, Mac mymac, const u_char* org_pkt);
