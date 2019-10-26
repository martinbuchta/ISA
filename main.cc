#include <stdlib.h>
#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

using namespace std;

struct ipv6_header
{
    unsigned int
        version : 4,
        traffic_class : 8,
        flow_label : 20;
    uint16_t length;
    uint8_t  next_header;
    uint8_t  hop_limit;
    struct in6_addr src;
    struct in6_addr dst;
};

/**
 * Get name of the first non-loopback device.
 * 
 * @return Name of the interface
 */
char *getFirstDevice()
{
    char *dev, errbuf[PCAP_ERRBUF_SIZE];

    dev = pcap_lookupdev(errbuf);

    if (dev == NULL)
    {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        exit(1);
    }

    return dev;
}

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    useless = NULL;
    static int count = 1;

    printf("\nPacket number [%d], length of this packet is: %d\n", count++, pkthdr->len);

    /**
     * ethernet header
     */

    struct ether_header ethernet_header;
    memcpy(&ethernet_header, packet, sizeof(struct ether_header));

    printf("--------- Ethernet ---------\n");
    printf("Source: ");
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", ethernet_header.ether_shost[0], ethernet_header.ether_shost[1],
           ethernet_header.ether_shost[2], ethernet_header.ether_shost[3], ethernet_header.ether_shost[4], ethernet_header.ether_shost[5]);
    printf("Dest: ");
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", ethernet_header.ether_dhost[0], ethernet_header.ether_dhost[1],
           ethernet_header.ether_dhost[2], ethernet_header.ether_dhost[3], ethernet_header.ether_dhost[4], ethernet_header.ether_dhost[5]);

    struct ipv6_header ip_header;
    memcpy(&ip_header, packet + sizeof(struct ether_header), sizeof(struct ipv6_header));
    printf("--------- IPv6 ---------\n");
    printf("Next header: %u\n", ip_header.next_header);

    if (ip_header.next_header != 17) { // TODO
        printf("Oh, this should never happen :( \n Next header should be UDP, but isn't.\n");
    }
}

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 pMask; /* subnet mask */
    bpf_u_int32 pNet;  /* ip address*/
    cout << "Hello world!\n";

    char *interface = getFirstDevice();
    printf("Device: %s\n", interface);

    pcap_lookupnet(interface, &pNet, &pMask, errbuf);

    pcap_t *descr = pcap_open_live(interface, BUFSIZ, 1, -1, errbuf);
    if (descr == NULL)
    {
        printf("pcap_open_live() failed due to [%s]\n", errbuf);
        return -1;
    }

    // Compile the filter expression
    if (pcap_compile(descr, &fp, "port 546 or port 547", 0, pNet) == -1)
    {
        printf("\npcap_compile() failed\n");
        return -1;
    }

    // Set the filter compiled above
    if (pcap_setfilter(descr, &fp) == -1)
    {
        printf("\npcap_setfilter() failed\n");
        exit(1);
    }

    pcap_loop(descr, 1500, callback, NULL);

    //pcap_loop();

    return 0;
}
