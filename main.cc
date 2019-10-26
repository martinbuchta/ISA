#include <stdlib.h>
#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <string.h>

using namespace std;

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

    printf("Dest: ");
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", ethernet_header.ether_dhost[0], ethernet_header.ether_dhost[1],
           ethernet_header.ether_dhost[2], ethernet_header.ether_dhost[3], ethernet_header.ether_dhost[4], ethernet_header.ether_dhost[5]);

    printf("Source: ");
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", ethernet_header.ether_shost[0], ethernet_header.ether_shost[1],
           ethernet_header.ether_shost[2], ethernet_header.ether_shost[3], ethernet_header.ether_shost[4], ethernet_header.ether_shost[5]);
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
