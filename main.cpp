#include <pcap.h>
#include <stdio.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void ethernet(u_char *packet);
void ip(const u_char *packet);
void tcp(const u_char *packet);
void tcp(const u_char *packet);

int ether_hdr = 0;
int ip_hdr = ether_hdr+14;
int tcp_hdr = ip_hdr+20;
int udp_hdr = ip_hdr+20;

int main()
{
    pcap_t *handle;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 mask;
    bpf_u_int32 net;
    dev = "wlan1";
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);
    return(0);
}

void ethernet(const u_char *packet)
{
    int sm, dm;
    printf("===================ethernet====================\n");
    printf("\ndestination mac -> ");
    for(dm=ether_hdr; dm<=ether_hdr+5; dm++) {
          printf("%02x",packet[dm]);
          if(dm!=ether_hdr+5)
               printf(":");
    }


    printf("\n\nsource mac -> ");
    for(sm=ether_hdr+6; sm<=ether_hdr+11; sm++) {
          printf("%02x",packet[sm]);
          if(sm!=ether_hdr+11)
               printf(":");
    }
    printf("\n\n");
}

void ip(const u_char *packet)
{
    int si, di;
    printf("=======================IP=======================\n");
    printf("\nsource IP -> ");
    for(si=ip_hdr+12; si<=ip_hdr+15; si++) {
          printf("%02d",packet[si]);
          if(si!=ip_hdr+15)
               printf(".");
    }

    printf("\n\ndestination IP -> ");
    for(di=ip_hdr+16; di<=ip_hdr+19; di++) {
          printf("%02d",packet[di]);
          if(di!=ip_hdr+19)
               printf(".");
    }
    printf("\n\n");
}

void tcp(const u_char *packet)
{
    int sp, dp;
    printf("======================TCP=======================\n");
    printf("\nsource port -> ");
    for(sp=tcp_hdr; sp<=tcp_hdr+1; sp++) {
          printf("%02d",packet[sp]);
    }

    printf("\n\ndestination port -> ");
    for(dp=tcp_hdr+2; dp<=tcp_hdr+3; dp++) {
          printf("%02d",packet[dp]);
    }
    printf("\n\n");
}

void udp(const u_char *packet)
{
    int sp, dp;
    printf("======================UDP======================\n");
    printf("\nsource port -> ");
    for(sp=udp_hdr; sp<=udp_hdr+1; sp++) {
          printf("%02d",packet[sp]);
    }

    printf("\n\ndestination port -> ");
    for(dp=udp_hdr+2; dp<=udp_hdr+3; dp++) {
          printf("%02d",packet[dp]);
    }
    printf("\n\n");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    ethernet(packet);
    if(packet[ether_hdr+12]==8 && packet[ether_hdr+13]==0)
        ip(packet);
    if(packet[ip_hdr+9]==6)
        tcp(packet);
    if (packet[ip_hdr+9]==17)
        udp(packet);
}
