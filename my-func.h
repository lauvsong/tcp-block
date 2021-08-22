#pragma once

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
struct TcpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
    IpHdr  ip_;
    TcpHdr tcp_;
};
#pragma pack(pop)

Mac mymac;

void usage();
Mac resolve_mymac(char* interface);
bool is_target(const u_char* packet, char* pattern);
void forward(TcpPacket org);
void backward(TcpPacket org);
