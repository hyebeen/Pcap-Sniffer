#include <pcap.h>
#include <stdio.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void ethernet(u_char *packet, int a, int b);
void ip(const u_char *packet, int a, int b);
void tcp(const u_char *packet, int a, int b);
void tcp(const u_char *packet, int a, int b);

int main()
{
    pcap_t *handle;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
  //  struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    //struct pcap_pkthdr header;
    //const u_char *packet;
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

void ethernet(const u_char *packet, int a, int b)
{
    int sm, dm;
    printf("destination mac      -> ");
    for(dm=0; dm<=a; dm++) {
          printf("%02x",packet[dm]);
          if(dm!=a)
               printf(":");
    }
    printf("\t");
    printf("source mac           -> ");
    for(sm=a+1; sm<=b; sm++) {
          printf("%02x",packet[sm]);
          if(sm!=b)
               printf(":");
    }
    printf("\n");

}

void ip(const u_char *packet, int a, int b)
{
    int si, di;
    printf("source IP            -> ");
    for(si=26; si<=a; si++) {
          printf("%02d",packet[si]);
          if(si!=a)
               printf(".");
    }
    printf("\t");
    printf("        destination IP       -> ");
    for(di=a+1; di<=b; di++) {
          printf("%02d",packet[di]);
          if(di!=b)
               printf(".");
    }
    printf("\n");

}

void tcp(const u_char *packet, int a, int b)
{
    int sp, dp;
    printf("tcp source port      -> ");
    for(sp=34; sp<=a; sp++) {
          printf("%02d",packet[sp]);
    }
    printf("\t");
    printf("                tcp destination port -> ");
    for(dp=a+1; dp<=b; dp++) {
          printf("%02d",packet[dp]);

    }
    printf("\n");
}

void udp(const u_char *packet, int a, int b)
{
    int sp, dp;
    printf("udp source port      -> ");
    for(sp=34; sp<=a; sp++) {
          printf("%02d",packet[sp]);
    }
    printf("\t");
    printf("                udp destination port -> ");
    for(dp=a+1; dp<=b; dp++) {
          printf("%02d",packet[dp]);

    }
    printf("\n");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    ethernet(packet, 5, 11);
    if(packet[12]==8 && packet[13]==0)
        ip(packet, 29, 33);
    if(packet[23]==6)
        tcp(packet, 35, 37);
    if (packet[23]==17)
        udp(packet, 35, 37);
}
