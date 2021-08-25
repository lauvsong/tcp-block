#include "my-func.h"

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return -1;
    }

    setbuf(stdout, NULL);
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    Mac mymac = resolve_mymac(dev);

    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK){
            fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            exit(-1);
        }
        if (!is_match(packet, argv[2])) continue;
        printf("matched\n");

        forward(handle, mymac, packet);
        printf("forwarded\n");
        backward(handle, mymac, packet);
        printf("backwarded\n");
    }

    pcap_close(handle);
}
