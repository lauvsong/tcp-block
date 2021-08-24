#include "my-func.h"

void usage() {
    printf("tcp-block <interface> <pattern>\n");
    printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

Mac resolve_mymac(char* interface){
    // Reference: https://pencil1031.tistory.com/66
    uint8_t mac[6];
    char ip[40];

    int sock;
    struct ifreq ifr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0){
        fprintf(stderr, "Fail to get interface MAC address - socket() failed - %m\n");
        exit(-1);
    }

    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr)<0){
        fprintf(stderr, "Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
        close(sock);
        exit(-1);
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(sock, SIOCGIFADDR, &ifr)<0){
        fprintf(stderr, "Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
        close(sock);
        exit(-1);
    }

    inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ip, sizeof(struct sockaddr));

    close(sock);
    return mac;
}

uint16_t calc_checksum(uint16_t* buf, uint size){
    uint res = 0;

    for (uint i=0;i<size/2;i++)
        res += ntohs(buf[i]);

    while (res >> 16)
        res = (res & 0xFFFF) + (res >> 16);
    return (uint16_t)~res;
}

uint16_t resolve_IPchecksum(PIpHdr packet){
    packet->chksum_ = 0;
    return calc_checksum((uint16_t*)packet,20);
}

uint16_t resolve_TCPchecksum(PIpHdr iph, PTcpHdr tcph, uint data_size){
    u_char* data = (u_char*)(tcph + sizeof(TcpHdr));
    PseudoHdr psdh;

    psdh.dip_ = iph->dip_;
    psdh.sip_ = iph->sip_;
    psdh.protocol_ = iph->protocol_;
    psdh.tlen_ = htons(sizeof(TcpHdr)+data_size);

    u_char* buf = nullptr;
    memcpy(buf, tcph, sizeof(PseudoHdr));
    memcpy(buf+sizeof(PseudoHdr), tcph, sizeof(TcpHdr));
    memcpy(buf+sizeof(PseudoHdr)+sizeof(TcpHdr), data, data_size);

    tcph->chksum_ = 0;
    return calc_checksum((uint16_t*)buf,data_size);
}

bool is_match(const u_char* packet, char* pattern) {
    const u_char* pkt = packet;

    PEthHdr eth_hdr = (PEthHdr)pkt;
    if (eth_hdr->type() != EthHdr::Ip4) return false;

    pkt += sizeof(EthHdr);
    PIpHdr ip_hdr = (PIpHdr)pkt;
    if (ip_hdr->protocol() != IpHdr::TCP) return false;

    pkt += sizeof(IpHdr);
    PTcpHdr tcp_hdr = (PTcpHdr)pkt;
    const u_char* data = pkt + tcp_hdr->offset();

    if (strstr((char*)data, pattern) == NULL) return false;
    printf("2\n");
    return true;
}

void forward(pcap_t* handle, const u_char* org_pkt){
    PTcpPacket org = (PTcpPacket)org_pkt;
    uint data_size = org->ip_.tlen() - sizeof(IpHdr) - org->tcp_.offset();

    PTcpPacket packet = nullptr;

    packet->eth_.smac_ = mymac;
    packet->eth_.dmac_ = org->eth_.dmac();
    packet->eth_.type_ = htons(EthHdr::Ip4);

    packet->ip_.tlen_ = htons(sizeof(IpHdr) + sizeof(TcpHdr));
    packet->ip_.ttl_ = org->ip_.ttl_;
    packet->ip_.sip_ = org->ip_.sip_;
    packet->ip_.dip_ = org->ip_.dip_;

    packet->tcp_.sport_ = org->tcp_.sport_;
    packet->tcp_.dport_ = org->tcp_.dport_;
    packet->tcp_.seq_ = htonl(ntohl(org->tcp_.seq_) + data_size);
    packet->tcp_.ack_ = org->tcp_.ack_;
    packet->tcp_.flag_ = TcpHdr::RST;

    packet->ip_.chksum_ = resolve_IPchecksum((PIpHdr)&packet->ip_);
    packet->tcp_.chksum_ = resolve_TCPchecksum((PIpHdr)&packet->ip_, (PTcpHdr)&packet->tcp_, data_size);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthHdr) + packet->ip_.offset());
    if (res != 0){
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        exit(-1);
    }
}

void backward(pcap_t* handle, const u_char* org_pkt){
    PTcpPacket org = (PTcpPacket)org_pkt;
    uint data_size = org->ip_.tlen() - sizeof(IpHdr) - org->tcp_.offset();

    PTcpPacket packet = nullptr;

    packet->eth_.smac_ = mymac;
    packet->eth_.dmac_ = org->eth_.dmac();
    packet->eth_.type_ = htons(EthHdr::Ip4);

    packet->ip_.tlen_ = htons(sizeof(IpHdr) + sizeof(TcpHdr) + PAYLOAD_SIZE); // if FIN -> add data
    packet->ip_.ttl_ = 0x80;
    packet->ip_.sip_ = org->ip_.dip_;
    packet->ip_.dip_ = org->ip_.sip_;

    packet->tcp_.sport_ = org->tcp_.dport_;
    packet->tcp_.dport_ = org->tcp_.sport_;
    packet->tcp_.seq_ = htonl(ntohl(org->tcp_.ack_) + data_size);
    packet->tcp_.ack_ = org->tcp_.seq_;
    packet->tcp_.flag_ = TcpHdr::FIN;

    packet->ip_.chksum_ = resolve_IPchecksum((PIpHdr)&packet->ip_);
    packet->tcp_.chksum_ = resolve_TCPchecksum((PIpHdr)&packet->ip_, (PTcpHdr)&packet->tcp_, data_size);

    memcpy(packet->data_, PAYLOAD, PAYLOAD_SIZE);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthHdr) + packet->ip_.offset());
    if (res != 0){
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        exit(-1);
    }
}
