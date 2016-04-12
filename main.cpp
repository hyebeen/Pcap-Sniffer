#include <pcap.h>
#include <stdio.h>
#include <libnet.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main()
{
    pcap_t *handle;
    char *dev = "wlan1";
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);
    return(0);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    char buf[24];
    libnet_ethernet_hdr *eth_header = (libnet_ethernet_hdr*) packet;
    printf("===================ethernet=====================\n");
    printf("Destination mac -> %s\n", ether_ntoa_r((ether_addr*)eth_header->ether_dhost, buf));
    printf("Source mac -> %s\n", ether_ntoa_r((ether_addr*)eth_header-> ether_shost, buf));
    if(ntohs(eth_header->ether_type)==ETHERTYPE_IP)
    {
        libnet_ipv4_hdr *ip_header = (libnet_ipv4_hdr*) (packet + sizeof(libnet_ethernet_hdr));
        printf("=======================IP=======================\n");
        printf("Destination IP -> %s\n", inet_ntoa(ip_header->ip_src));
        printf("Source IP -> %s\n", inet_ntoa(ip_header->ip_dst));
        if((ip_header->ip_p)==IPPROTO_TCP)
        {
            libnet_tcp_hdr *tcp_header = (libnet_tcp_hdr*) (packet + sizeof(libnet_ethernet_hdr) + (ip_header->ip_hl * 4));
            printf("======================TCP=======================\n");
            printf("Destination protocol -> %d\n", (int)ntohs(tcp_header->th_dport));
            printf("Source protocol -> %d\n", (int)ntohs(tcp_header->th_sport));
        }
        if((ip_header->ip_p)==IPPROTO_UDP)
        {
            libnet_udp_hdr *udp_header = (libnet_udp_hdr*) (packet + sizeof(libnet_ethernet_hdr) + (ip_header->ip_hl * 4));
            printf("======================UDP=======================\n");
            printf("Destination protocol -> %d\n", (int)ntohs(udp_header->uh_dport));
            printf("Source protocol -> %d\n", (int)ntohs(udp_header->uh_sport));
        }
    }
}
