#include <stdlib.h>
#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <cstdint>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <thread>
#include <vector>

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

struct ipv6_header_option
{
    uint8_t next_header;
    uint8_t length;
    uint8_t data[];
};

struct __attribute__((__packed__)) dhcpv6_relay_server_message
{
    uint8_t msgType;
    uint8_t hopCount;
    struct in6_addr link_addr;
    struct in6_addr peer_addr;
    uint8_t options[];
};

struct __attribute__((__packed__)) option
{
    uint8_t option_code[2];
    uint8_t option_length[2];
    uint8_t option_data[];
};

struct __attribute__((__packed__)) mac_option
{
    uint8_t option_code[2];
    uint8_t option_length[2];
    uint8_t link_layer_type[2];
    uint8_t link_layer_addr[];
};

char currentInterface[1000];

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

/**
 * This function is insiped by https://stackoverflow.com/a/33127330
 */
struct in6_addr getIp6OfInterface(char *interface)
{

    struct in6_addr toReturn;
    struct ifaddrs *ifa, *ifa_tmp;
    char addr[50];

    if (getifaddrs(&ifa) == -1) {
        perror("getifaddrs failed");
        exit(1);
    }

    ifa_tmp = ifa;
    struct sockaddr_in6 *in6;

    while (ifa_tmp) {
        if ((ifa_tmp->ifa_addr) && ((ifa_tmp->ifa_addr->sa_family == AF_INET) ||
                                (ifa_tmp->ifa_addr->sa_family == AF_INET6))) {
            if (ifa_tmp->ifa_addr->sa_family == AF_INET) {
                // create IPv4 string
                struct sockaddr_in *in = (struct sockaddr_in*) ifa_tmp->ifa_addr;
                inet_ntop(AF_INET, &in->sin_addr, addr, sizeof(addr));
            } else { // AF_INET6
                // create IPv6 string
                in6 = (struct sockaddr_in6*) ifa_tmp->ifa_addr;
                inet_ntop(AF_INET6, &in6->sin6_addr, addr, sizeof(addr));
            }

            if (strcmp(interface, ifa_tmp->ifa_name) == 0  && ifa_tmp->ifa_addr->sa_family == AF_INET6) {
                printf("\nname = %s\n", ifa_tmp->ifa_name);
                printf("addr = %s\n", addr);
                return in6->sin6_addr;
            }
        }
        ifa_tmp = ifa_tmp->ifa_next;
    }

    return in6->sin6_addr;
}

void sendUdpForward(char *data, size_t length)
{
    int sockfd;
    if ( (sockfd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0 ) { 
        perror("socket creation failed"); 
        exit(EXIT_FAILURE); 
    } else {
        //printf("Socket created\n");
    } 

    struct sockaddr_in6     servaddr; 
    memset(&servaddr, 0, sizeof(servaddr)); 
      
    // Filling server information 
    servaddr.sin6_family = AF_INET6; 
    servaddr.sin6_port = htons(547); 
    inet_pton(AF_INET6, "2001:67c:1220:80c::93e5:dd2", &servaddr.sin6_addr);

    if( sendto(sockfd, (const char *)data, length, 
        MSG_CONFIRM, (const struct sockaddr *) &servaddr,  
            sizeof(servaddr)) <0 ) {
        /* buffers aren't available locally at the moment,
        * try again.
        */
        perror("UDP err");
        exit(1);
    }

    printf("RELY FORWARD sent\n");
}

void sendUdpReply(uint8_t *data, size_t length, struct in6_addr clientAddr, struct in6_addr linkAddr)
{
    int sockfd;
    if ( (sockfd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    } else {
        printf("REPLY Socket created\n");
    }

    // bind to interface
    /*struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), currentInterface);
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
        fprintf(stderr, "Can't bind socket to interface\n");
        exit(13);
    }*/


    // bind source ip
    struct sockaddr_in6 localaddr;
    localaddr.sin6_family = AF_INET6;
    localaddr.sin6_addr = linkAddr;
    localaddr.sin6_port = 467;
    bind(sockfd, (struct sockaddr *) &localaddr, sizeof(localaddr));

    struct sockaddr_in6     servaddr;
    memset(&servaddr, 0, sizeof(servaddr));

    // Filling server information
    servaddr.sin6_family = AF_INET6;
    servaddr.sin6_port = htons(546);
    servaddr.sin6_addr = clientAddr;

    if( sendto(sockfd, (const char *)data, length,
               MSG_CONFIRM, (const struct sockaddr *) &servaddr,
               sizeof(servaddr)) <0 ) {
        /* buffers aren't available locally at the moment,
        * try again.
        */
        perror("UDP err");
        exit(1);
    }

    printf("RELY REPLY sent to interface %s\n", currentInterface);
}

void callbackServer(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    struct ether_header ethernet_header;
    memcpy(&ethernet_header, packet, sizeof(struct ether_header));

    struct ipv6_header ip_header;
    memcpy(&ip_header, packet + sizeof(struct ether_header), sizeof(struct ipv6_header));

    if (ip_header.next_header != 17) { // TODO
        printf("Oh, this should never happen :( \n Next header should be UDP, but isn't.\n");
    }

    const struct udphdr *udp_header;
    udp_header = (struct udphdr *) (packet + sizeof(struct ether_header) + sizeof(struct ipv6_header));

    const u_char *dhcpMshType = packet + sizeof(struct ether_header) + sizeof(struct ipv6_header) + sizeof(struct udphdr);
    const uint8_t msgType = *dhcpMshType;

    if (msgType == 13) {
        printf("I have rely reply (13) message\n");

        struct dhcpv6_relay_server_message *msg = (struct dhcpv6_relay_server_message *) dhcpMshType;
        struct option *opt = (struct option *) &(msg->options);

        if (opt->option_code[1] != 9) { // relay msg
            fprintf(stderr, "This should never happen!\n"); // TODO
            exit(12);
        }

        sendUdpReply(opt->option_data, opt->option_length[1], msg->peer_addr, msg->link_addr);
    }
}


void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    useless = NULL;
    static int count = 1;

    size_t ipv6OptionsLen = 0;

    //printf("\nPacket number [%d], length of this packet is: %d\n", count++, pkthdr->len);

    /**
     * ethernet header
     */

    struct ether_header ethernet_header;
    memcpy(&ethernet_header, packet, sizeof(struct ether_header));

    /*printf("--------- Ethernet ---------\n");
    printf("Source: ");
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", ethernet_header.ether_shost[0], ethernet_header.ether_shost[1],
           ethernet_header.ether_shost[2], ethernet_header.ether_shost[3], ethernet_header.ether_shost[4], ethernet_header.ether_shost[5]);
    printf("Dest: ");
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", ethernet_header.ether_dhost[0], ethernet_header.ether_dhost[1],
           ethernet_header.ether_dhost[2], ethernet_header.ether_dhost[3], ethernet_header.ether_dhost[4], ethernet_header.ether_dhost[5]);
    */
    struct ipv6_header ip_header;
    memcpy(&ip_header, packet + sizeof(struct ether_header), sizeof(struct ipv6_header));
    /*printf("--------- IPv6 ---------\n");
    printf("ip version %d\n", ip_header.version);
    printf("Next header: %u\n", ip_header.next_header);*/

    if (ip_header.next_header != 17) {
        struct ipv6_header_option *option = (struct ipv6_header_option *) (packet + sizeof(struct ether_header) + sizeof(struct ipv6_header) + ipv6OptionsLen);

        while (option->next_header != 17 && ipv6OptionsLen < 1500) {
            ipv6OptionsLen += option->length + 8;
            option = (struct ipv6_header_option *) (packet + sizeof(struct ether_header) + sizeof(struct ipv6_header) + ipv6OptionsLen);
        }

        if (option->next_header != 17) {
            // udp header not found
            printf("Udp header not found\n");
            return;
        }
    }

    printf("found\n");

    const struct udphdr *udp_header;
    udp_header = (struct udphdr *) (packet + sizeof(struct ether_header) + sizeof(struct ipv6_header));
    /*printf("--------- UDP ---------\n");
    printf("Source: %d\n", ntohs(udp_header->uh_sport));
    printf("Dest: %d\n", ntohs(udp_header->uh_dport));
    printf("Length: %d\n", ntohs(udp_header->uh_ulen));*/

    //printf("---- zkousim stesti DHCP ----");
    const u_char *dhcpMshType = packet + sizeof(struct ether_header) + sizeof(struct ipv6_header) + sizeof(struct udphdr);
    const uint8_t msgType = *dhcpMshType;
    //printf("Msg-Type: %d\n", msgType);

    if (msgType == 1 || msgType == 3) {
        /*printf("I have a SOLICIT (1) message.\n");
        printf("For relay rofward message alloc %d bytes\n", 34 + ntohs(udp_header->uh_ulen) - 8 + 12);*/

        // create relay forward message
        
        struct dhcpv6_relay_server_message *msg = (struct dhcpv6_relay_server_message *) malloc(
            (34 + ntohs(udp_header->uh_ulen) - 8) + (12) + 100
            + 4 + strlen(currentInterface)
        ); // 100 bytu alokuju navic, abych se pojistil, ze omylem neprepisu data od klihovny c pro spravu pameti

        //printf("malloc ok\n");
        msg->msgType = 12;
        msg->hopCount = 0;
        msg->link_addr = getIp6OfInterface(currentInterface);
        msg->peer_addr = ip_header.src;

        struct option *relay_message_option = (struct option *) &(msg->options);
        relay_message_option->option_code[0] = 0;
        relay_message_option->option_code[1] = 9;
        relay_message_option->option_length[0] = 0;
        relay_message_option->option_length[1] = ntohs(udp_header->uh_ulen) - 8;
        memcpy(&(relay_message_option->option_data), dhcpMshType, ntohs(udp_header->uh_ulen) - 8);

        char *macOptionAddr = (char *) &(msg->options);
        macOptionAddr += ntohs(udp_header->uh_ulen) - 8 + 4;
        struct mac_option *macOption = (struct mac_option *) macOptionAddr;
        macOption->option_code[0] = 0;
        macOption->option_code[1] = 79;
        macOption->option_length[0] = 0;
        macOption->option_length[1] = 8;
        macOption->link_layer_type[0] = 0;
        macOption->link_layer_type[1] = 1;
        memcpy(&(macOption->link_layer_addr), &(ethernet_header.ether_shost), 6);

        char *interfaceIdOptionAddr = (char *) &(msg->options);
        interfaceIdOptionAddr += ntohs(udp_header->uh_ulen) - 8 + 4 + 12;
        struct option *interfaceIdOption = (struct option *) interfaceIdOptionAddr;
        interfaceIdOption->option_code[0] = 0;
        interfaceIdOption->option_code[1] = 18;
        interfaceIdOption->option_length[0] = 0;
        interfaceIdOption->option_length[1] = strlen(currentInterface);
        memcpy(&(interfaceIdOption->option_data), currentInterface, strlen(currentInterface));

        printf("================ interface %s\n\n\n", currentInterface);

                //if (macOption->link_layer_addr[5] == 0x54) {
            sendUdpForward((char *) msg, 34 + ntohs(udp_header->uh_ulen) - 8 + 12 + 4 + 4 + strlen(currentInterface));
        //}

        free(msg);
    }
}

void sniffInterface(char *interface)
{
    strcpy(currentInterface, interface);

    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 pMask; /* subnet mask */
    bpf_u_int32 pNet;  /* ip address*/
    printf("Device: %s\n", interface);

    pcap_lookupnet(interface, &pNet, &pMask, errbuf);

    pcap_t *descr = pcap_open_live(interface, BUFSIZ, 1, -1, errbuf);
    if (descr == NULL) {
        return;
    }

    // Compile the filter expression
    if (pcap_compile(descr, &fp, "port 547", 0, pNet) == -1) {
        return;
    }

    // Set the filter compiled above
    if (pcap_setfilter(descr, &fp) == -1) {
        printf("\npcap_setfilter() failed\n");
        exit(1);
    }

    pcap_loop(descr, 1500, callback, NULL);
}

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 pMask; /* subnet mask */
    bpf_u_int32 pNet;  /* ip address*/
    cout << "Hello world!\n";
    char *interface;

    if (fork() == 0) {
        // sniffing interface that comunicates with server
        interface = (char *) "enp4s0f1";
        printf("Device: %s\n", interface);

        pcap_lookupnet(interface, &pNet, &pMask, errbuf);

        pcap_t *descr = pcap_open_live(interface, BUFSIZ, 1, -1, errbuf);
        if (descr == NULL) {
            printf("pcap_open_live() failed due to [%s]\n", errbuf);
            return -1;
        }

        // Compile the filter expression
        if (pcap_compile(descr, &fp, "port 547", 0, pNet) == -1) {
            printf("\npcap_compile() failed\n");
            return -1;
        }

        // Set the filter compiled above
        if (pcap_setfilter(descr, &fp) == -1) {
            printf("\npcap_setfilter() failed\n");
            exit(1);
        }

        pcap_loop(descr, 1500, callbackServer, NULL);
    } else {
        pcap_if_t *interfaces;
        char errbuf[PCAP_ERRBUF_SIZE];
        if (pcap_findalldevs(&interfaces,errbuf) == -1) {
            fprintf(stderr, "Couldnt find any device.\n");
        }

        int i = 0;

        while (interfaces != nullptr) {
            if (fork() == 0) {
                sniffInterface(interfaces->name);
                return 0;
            }
            i++;
            interfaces = interfaces->next;
        }

        while(1);
    }

    //pcap_loop();

    return 0;
}
