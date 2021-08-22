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
}

bool is_target(const u_char* packet, char* pattern) {
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
    return true;
}

void forward(TcpPacket org){
    u_int tcp_data_size = org.ip_.tlen() - sizeof(IpHdr) - org.tcp_.offset();

    TcpPacket packet;

    packet.eth_.smac_ = mymac;
    packet.eth_.dmac_ = org.eth_.dmac();
    packet.eth_.type_ = htons(EthHdr::Ip4);

    packet.ip_.tlen_ = sizeof(IpHdr) + sizeof(TcpHdr); // if FIN -> add data
    packet.ip_.ttl_ = org.ip_.ttl_;
    packet.ip_.sip_ = org.ip_.sip_;
    packet.ip_.dip_ = org.ip_.dip_;

    packet.tcp_.sport_ = org.tcp_.sport_;
    packet.tcp_.dport_ = org.tcp_.dport_;
    packet.tcp_.seq_ = org.tcp_.seq_ + tcp_data_size;
    packet.tcp_.ack_ = org.tcp_.ack_;
    packet.tcp_.flag_ = TcpHdr::RST;

    //packet.ip_.checksum_ =
    //packet.tcp_.chksum_ =
}

void backward(){

}
