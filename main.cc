#include <stdlib.h>
#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <cstdint>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <thread>
#include <vector>
#include <map>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <iterator>
#include <syslog.h>
#include <mutex>

#define DHCPv6_PORT_SERVER 547
#define DHCPv6_PORT_CLIENT 546

#define RELAY_FORW 12
#define RELY_REPLY 13
#define RELAY_REPLY_FIXED_SIZE 34
#define INTERFACE_BUFFER_LENGTH 1000
#define UDP_HEADER_LENGTH 8

#define OPTION_PREFERENCE 7
#define OPTION_RELAY_MSG 9
#define OPTION_IA_TA 4
#define OPTION_IAADDR 5
#define OPTION_IA_PD 25
#define OPTION_IAPREFIX 26
#define OPTION_CLIENT_LINKLAYER_ADDR 79
#define OPTION_INTERFACE_ID 18

#define IP_NEXT_HEADER_UDP 17

using namespace std;

/**
 * @brief UDP hlavička
 */
struct udphdr {
    u_short	uh_sport;
    u_short	uh_dport;
    short	uh_ulen;
    u_short	uh_sum;
};

/**
 * @brief Struktura pro parametry, se kterými byl program spuštěn.
 */
struct parameters
{
    bool stdout_enabled;
    bool syslog_enabled;
    char *server;
    char *interface;
};

/**
 * @brief IPv6 hlavička
 * @author https://stackoverflow.com/a/7980674
 */
struct ipv6_header
{
    unsigned int
        version : OPTION_IA_TA,
        traffic_class : UDP_HEADER_LENGTH,
        flow_label : 20;
    uint16_t length;
    uint8_t  next_header;
    uint8_t  hop_limit;
    struct in6_addr src;
    struct in6_addr dst;
};

/**
 * @brief Option v IPv6 hlavičce
 */
struct ipv6_header_option
{
    uint8_t next_header;
    uint8_t length;
    uint8_t data[];
};

/**
 * @brief Struktura pro DHCPv6 relay-server zprávu
 */
struct __attribute__((__packed__)) dhcpv6_relay_server_message
{
    uint8_t msgType;
    uint8_t hopCount;
    struct in6_addr link_addr;
    struct in6_addr peer_addr;
    uint8_t options[];
};

/**
 * @brief Struktura pro DHCPv6 option
 */
struct __attribute__((__packed__)) option
{
    uint16_t option_code;
    uint16_t option_length;
    uint8_t option_data[];
};

/**
 * @brief Struktura pro posílání MAC adresy klienta DHCPv6 serveru.
 * Viz RFC 6939.
 */
struct __attribute__((__packed__)) mac_option
{
    uint16_t option_code;
    uint16_t option_length;
    uint16_t link_layer_type;
    uint8_t link_layer_addr[];
};

/**
 * @brief Mapa, která mapuje lokální IPv6 adresu klienta a jeho MAC adresu.
 * Pro účely logování a výpisu na stdout.
 */
std::map<string, string> ipMacMap;

/**
 * @brief Zámek pro práci se sdílenými zdroji (ipMacMap, stdout).
 */
std::mutex mtx;

/**
 * @brief Parametry, se kterými byl spuštěný program
 */
struct parameters params;

/**
 * @brief Vrací první IPv6 adresu inteface.
 * @param interface Název interface
 * Inspirované: https://stackoverflow.com/a/33127330
 */
struct in6_addr getIp6OfInterface(char *interface)
{

    struct ifaddrs *ifa, *ifa_tmp;
    char addr[50];

    if (getifaddrs(&ifa) == -1) {
        perror("getifaddrs error");
        exit(1);
    }

    ifa_tmp = ifa;
    struct sockaddr_in6 *in6;

    while (ifa_tmp) {
        if ((ifa_tmp->ifa_addr) && ((ifa_tmp->ifa_addr->sa_family == AF_INET) ||
                                (ifa_tmp->ifa_addr->sa_family == AF_INET6))) {
            if (ifa_tmp->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *in = (struct sockaddr_in*) ifa_tmp->ifa_addr;
                inet_ntop(AF_INET, &in->sin_addr, addr, sizeof(addr));
            } else {
                in6 = (struct sockaddr_in6*) ifa_tmp->ifa_addr;
                inet_ntop(AF_INET6, &in6->sin6_addr, addr, sizeof(addr));
            }

            if (strcmp(interface, ifa_tmp->ifa_name) == 0  && ifa_tmp->ifa_addr->sa_family == AF_INET6) {
                return in6->sin6_addr;
            }
        }
        ifa_tmp = ifa_tmp->ifa_next;
    }

    return in6->sin6_addr;
}

/**
 * @brief Posílá UDP packet na DHCP server
 * @param data Packet
 * @param length Délka dat
 */
void sendUdpForward(char *data, size_t length)
{
    int sockfd;
    if ( (sockfd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in6 servaddr;
    memset(&servaddr, 0, sizeof(servaddr));

    // Údaje o serveru
    servaddr.sin6_family = AF_INET6;
    servaddr.sin6_port = htons(DHCPv6_PORT_SERVER);
    int s = inet_pton(AF_INET6, params.server, &servaddr.sin6_addr);
    if (s <= 0) {
        if (s == 0) {
            fprintf(stderr, "Adresa serveru je ve špatném formátu. Zadejte IPv6 adresu.\n");
            exit(22);
        } else {
            perror("Adresa serveru:");
            exit(22);
        }
    }

    if( sendto(sockfd, (const char *)data, length,
        MSG_CONFIRM, (const struct sockaddr *) &servaddr,
            sizeof(servaddr)) < 0) {
        perror("UDP err");
        exit(1);
    }
}

/**
 * @brief Posílá UDP odpověd klientovi
 * @param data Packet data
 * @param length Délka dat
 * @param clientAddr Lokální adresa klienta
 * @param linkAddr Adresa interface
 * @param interface Název interface, přes který se má zpráva poslat
 */
void sendUdpReply(uint8_t *data, size_t length, struct in6_addr clientAddr, struct in6_addr linkAddr, char *interface)
{
    int sockfd;
    if ( (sockfd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Vyber interface
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), interface);
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
        fprintf(stderr, "Can't bind socket to interface\n");
        exit(RELY_REPLY);
    }


    // Nastav zdrojovou adresa
    struct sockaddr_in6 localaddr;
    localaddr.sin6_family = AF_INET6;
    localaddr.sin6_addr = linkAddr;
    bind(sockfd, (struct sockaddr *) &localaddr, sizeof(localaddr));

    struct sockaddr_in6     servaddr;
    memset(&servaddr, 0, sizeof(servaddr));

    // Informace o serveru
    servaddr.sin6_family = AF_INET6;
    servaddr.sin6_port = htons(DHCPv6_PORT_CLIENT);
    servaddr.sin6_addr = clientAddr;

    if( sendto(sockfd, (const char *)data, length,
               MSG_CONFIRM, (const struct sockaddr *) &servaddr,
               sizeof(servaddr)) <0 ) {
        perror("UDP err");
        exit(1);
    }
}

/**
 * Funkce zpracovávající zprávy od DHCPv6 serveru
 * @param packet Data
 * @param packetLength Délka dat
 */
void callbackServer(const u_char *packet, unsigned int packetLength)
{
    const u_char *dhcpMshType = packet;
    const uint8_t msgType = *dhcpMshType;

    if (msgType == RELY_REPLY) {
        struct dhcpv6_relay_server_message *msg = (struct dhcpv6_relay_server_message *) dhcpMshType;
        char interface[INTERFACE_BUFFER_LENGTH];
        uint8_t *msgPtr = nullptr;
        size_t msgSize = 0;
        struct option *opt;
        uint16_t move = 0;
        unsigned int usedOptions = 0;

        while (packetLength > (unsigned) UDP_HEADER_LENGTH + (unsigned) RELAY_REPLY_FIXED_SIZE + move) {
            opt = (struct option *) ((char *) &(msg->options) + move);

            if (ntohs(opt->option_code) == OPTION_RELAY_MSG) {
                msgPtr = opt->option_data;
                msgSize = ntohs(opt->option_length);
                usedOptions++;
                if (opt->option_data[0] == OPTION_PREFERENCE) {
                    struct option *replyOption = (struct option *) &(opt->option_data[OPTION_IA_TA]);

                    while (((char *) replyOption) < ((char *) opt) + ntohs(opt->option_length)) {
                        if (ntohs(replyOption->option_code) == 3) {
                            struct option *addrOption = (struct option *) &(replyOption->option_data[RELAY_FORW]);
                            while ((char *) addrOption < ((char *) replyOption) + ntohs(replyOption->option_length)) {
                                if (ntohs(addrOption->option_code) == OPTION_IAADDR) {
                                    char ipHumbanBuff[INET6_ADDRSTRLEN];
                                    char ipReceived[INET6_ADDRSTRLEN];
                                    inet_ntop(AF_INET6, &(msg->peer_addr), ipHumbanBuff, sizeof(ipHumbanBuff));
                                    inet_ntop(AF_INET6, &(addrOption->option_data), ipReceived, sizeof(ipReceived));
                                    string ipHumanString = ipHumbanBuff;
                                    string ipReceivedString = ipReceived;
                                    mtx.lock();
                                    if (params.stdout_enabled) {
                                        cout << ipReceivedString << "," << ipMacMap.find(ipHumanString)->second << "\n" << flush;
                                    }
                                    if (params.syslog_enabled) {
                                        string log = ipReceivedString + "," + ipMacMap.find(ipHumanString)->second;
                                        syslog(LOG_INFO, "%s", log.c_str());
                                    }
                                    mtx.unlock();
                                    break;
                                } else {
                                    addrOption = (struct option *) (((char *) addrOption) +
                                            ntohs(addrOption->option_length) + OPTION_IA_TA);
                                }
                            }
                            break;
                        } else if (ntohs(replyOption->option_code) == OPTION_IA_TA) {
                            struct option *addrOption = (struct option *) &(replyOption->option_data[OPTION_IA_TA]);
                            while ((char *) addrOption < ((char *) replyOption) + ntohs(replyOption->option_length)) {
                                if (ntohs(addrOption->option_code) == OPTION_IAADDR) {
                                    char ipHumbanBuff[INET6_ADDRSTRLEN];
                                    char ipReceived[INET6_ADDRSTRLEN];
                                    inet_ntop(AF_INET6, &(msg->peer_addr), ipHumbanBuff, sizeof(ipHumbanBuff));
                                    inet_ntop(AF_INET6, &(addrOption->option_data), ipReceived, sizeof(ipReceived));
                                    string ipHumanString = ipHumbanBuff;
                                    string ipReceivedString = ipReceived;
                                    mtx.lock();
                                    if (params.stdout_enabled) {
                                        cout << ipReceivedString << "," << ipMacMap.find(ipHumanString)->second << "\n" << flush;
                                    }
                                    if (params.syslog_enabled) {
                                        string log = ipReceivedString + "," + ipMacMap.find(ipHumanString)->second;
                                        syslog(LOG_INFO, "%s", log.c_str());
                                    }
                                    mtx.unlock();
                                    break;
                                } else {
                                    addrOption = (struct option *) (((char *) addrOption) +
                                            ntohs(addrOption->option_length) + OPTION_IA_TA);
                                }
                            }
                            break;
                        } else if (ntohs(replyOption->option_code) == OPTION_IA_PD) {
                            struct option *addrOption = (struct option *) &(replyOption->option_data[RELAY_FORW]);
                            while ((char *) addrOption < ((char *) replyOption) + ntohs(replyOption->option_length)) {
                                if (ntohs(addrOption->option_code) == OPTION_IAPREFIX) {
                                    uint8_t prefix = (uint8_t) addrOption->option_data[UDP_HEADER_LENGTH];
                                    char prefixBuff[10];
                                    sprintf(prefixBuff, "%d", prefix);
                                    string prefixString = prefixBuff;
                                    char ipHumbanBuff[INET6_ADDRSTRLEN];
                                    char ipReceived[INET6_ADDRSTRLEN];
                                    inet_ntop(AF_INET6, &(msg->peer_addr), ipHumbanBuff, sizeof(ipHumbanBuff));
                                    inet_ntop(AF_INET6, &(addrOption->option_data[OPTION_RELAY_MSG]), ipReceived, sizeof(ipReceived));
                                    string ipHumanString = ipHumbanBuff;
                                    string ipReceivedString = ipReceived;
                                    mtx.lock();
                                    if (params.stdout_enabled) {
                                        cout << ipReceivedString << "/" << prefixString << "," << ipMacMap.find(ipHumanString)->second << "\n" << flush;
                                    }
                                    if (params.syslog_enabled) {
                                        string log = ipReceivedString + "/" + prefixString + "," + ipMacMap.find(ipHumanString)->second;
                                        syslog(LOG_INFO, "%s", log.c_str());
                                    }
                                    mtx.unlock();
                                    break;
                                } else {
                                    addrOption = (struct option *) (((char *) addrOption) +
                                            ntohs(addrOption->option_length) + OPTION_IA_TA);
                                }
                            }
                            break;
                        } else {
                            replyOption = (struct option *) (((char *) replyOption) + ntohs(replyOption->option_length));
                        }
                    }
                }
            }

            if (ntohs(opt->option_code) == OPTION_INTERFACE_ID) {
                memcpy(interface, opt->option_data, ntohs(opt->option_length));
                interface[ntohs(opt->option_length)] = '\0';

                usedOptions++;
            }

            move += ntohs(opt->option_length) + OPTION_IA_TA;
        }

        if (usedOptions < 2) {
            return;
        }


        sendUdpReply(msgPtr, msgSize, msg->peer_addr, msg->link_addr, interface);
    }
}


/**
 * Funkce zpracovávající zprávy od klienta
 * @param interface Název interface, na kterém byl dotaz zachycen
 * @param pkthdr
 * @param packet Data
 */
void callback(u_char *interface, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    static int count = 1;
    char *currentInterface = (char *) interface;

    size_t ipv6OptionsLen = 0;

    struct ether_header ethernet_header;
    memcpy(&ethernet_header, packet, sizeof(struct ether_header));

    struct ipv6_header ip_header;
    memcpy(&ip_header, packet + sizeof(struct ether_header), sizeof(struct ipv6_header));

    if (ip_header.next_header != IP_NEXT_HEADER_UDP) {
        struct ipv6_header_option *option = (struct ipv6_header_option *) (packet + sizeof(struct ether_header) + sizeof(struct ipv6_header) + ipv6OptionsLen);

        while (option->next_header != IP_NEXT_HEADER_UDP && ipv6OptionsLen < 1500) {
            ipv6OptionsLen += option->length + UDP_HEADER_LENGTH;
            option = (struct ipv6_header_option *) (packet + sizeof(struct ether_header) + sizeof(struct ipv6_header) + ipv6OptionsLen);
        }

        if (option->next_header != IP_NEXT_HEADER_UDP) {
            return;
        }
    }

    const struct udphdr *udp_header;
    udp_header = (struct udphdr *) (packet + sizeof(struct ether_header) + sizeof(struct ipv6_header));
    const u_char *dhcpMshType = packet + sizeof(struct ether_header) + sizeof(struct ipv6_header) + sizeof(struct udphdr);
    const uint8_t msgType = *dhcpMshType;

    if (msgType == 1 || msgType == 3 || msgType == 5 || msgType == 6 || msgType == 8 || msgType == 9 || msgType == 11) {
        char macAddrStr[20];
        sprintf(macAddrStr,"%02x:%02x:%02x:%02x:%02x:%02x", ethernet_header.ether_shost[0], ethernet_header.ether_shost[1],
               ethernet_header.ether_shost[2], ethernet_header.ether_shost[3], ethernet_header.ether_shost[OPTION_IA_TA], ethernet_header.ether_shost[OPTION_IAADDR]);
        char ipHumbanBuff[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, (const void *) &(ip_header.src), ipHumbanBuff, sizeof(ipHumbanBuff));
        string ipHumanString = ipHumbanBuff;
        string macHumanString = macAddrStr;
        mtx.lock();
        ipMacMap.insert({ipHumanString, macHumanString});
        mtx.unlock();

        // Vytvoř relay forward zprávu
        
        struct dhcpv6_relay_server_message *msg = (struct dhcpv6_relay_server_message *) malloc(
            (RELAY_REPLY_FIXED_SIZE + ntohs(udp_header->uh_ulen) - UDP_HEADER_LENGTH) + RELAY_FORW + 100
            + OPTION_IA_TA + strlen(currentInterface)
        );

        msg->msgType = RELAY_FORW;
        msg->hopCount = 0;
        msg->link_addr = getIp6OfInterface(currentInterface);
        msg->peer_addr = ip_header.src;

        struct option *relay_message_option = (struct option *) &(msg->options);
        relay_message_option->option_code = htons(0);
        relay_message_option->option_code = htons(OPTION_RELAY_MSG);
        relay_message_option->option_length = htons(ntohs(udp_header->uh_ulen) - UDP_HEADER_LENGTH);
        memcpy(&(relay_message_option->option_data), dhcpMshType, ntohs(udp_header->uh_ulen) - UDP_HEADER_LENGTH);

        char *macOptionAddr = (char *) &(msg->options);
        macOptionAddr += ntohs(udp_header->uh_ulen) - UDP_HEADER_LENGTH + OPTION_IA_TA;
        struct mac_option *macOption = (struct mac_option *) macOptionAddr;
        macOption->option_code = htons(0);
        macOption->option_code = htons(OPTION_CLIENT_LINKLAYER_ADDR);
        macOption->option_length = htons(UDP_HEADER_LENGTH);
        macOption->link_layer_type = htons(1);
        memcpy(&(macOption->link_layer_addr), &(ethernet_header.ether_shost), 6);

        char *interfaceIdOptionAddr = (char *) &(msg->options);
        interfaceIdOptionAddr += ntohs(udp_header->uh_ulen) - UDP_HEADER_LENGTH + OPTION_IA_TA + RELAY_FORW;
        struct option *interfaceIdOption = (struct option *) interfaceIdOptionAddr;
        interfaceIdOption->option_code = htons(0);
        interfaceIdOption->option_code = htons(OPTION_INTERFACE_ID);
        interfaceIdOption->option_length = htons(strlen(currentInterface));
        memcpy(&(interfaceIdOption->option_data), currentInterface, strlen(currentInterface));

        sendUdpForward((char *) msg, RELAY_REPLY_FIXED_SIZE + ntohs(udp_header->uh_ulen) - UDP_HEADER_LENGTH + RELAY_FORW + OPTION_IA_TA + OPTION_IA_TA + strlen(currentInterface));

        free(msg);
    }
}

/**
 * @brief Zapíná poslouchání na daném interface
 * @param interface Název interface
 */
void sniffInterface(char *interface)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    pcap_t *descr = pcap_open_live(interface, BUFSIZ, 1, -1, errbuf);
    if (descr == NULL) {
        fprintf(stderr, "Pcap open live error na interface %s: %s\n", interface, errbuf);
        exit(32);
    }

    if (pcap_compile(descr, &fp, "udp port 547", 0, 0) == -1) {
        perror("Pcap compile error: ");
        exit(32);
    }

    if (pcap_setfilter(descr, &fp) == -1) {
        fprintf(stderr, "\npcap_setfilter() error\n");
        exit(1);
    }

    pcap_loop(descr, 1500, callback, (u_char *) interface);
}

/**
 * @brief Zapíná poslouchání zpráv od DHCPv6 serveru
 */
void sniffServer()
{
    int sockfd;
    char buffer[2048];
    struct sockaddr_in6 servaddr, cliaddr;

    if ( (sockfd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));

    servaddr.sin6_family = AF_INET6;
    servaddr.sin6_addr = in6addr_any;
    servaddr.sin6_port = htons(DHCPv6_PORT_SERVER);

    if ( bind(sockfd, (const struct sockaddr *)&servaddr,
              sizeof(servaddr)) < 0 )
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    unsigned int len, n;
    while (1) {
        n = recvfrom(sockfd, (char *) buffer, 2048,
                     MSG_WAITALL, (struct sockaddr *) &cliaddr,
                     &len);

        callbackServer((const u_char *) buffer, n);
    }
}

/**
 * @brief Parsuje argumenty programu
 * @param argc Počet argumentů
 * @param argv Argumenty
 */
void parseParameters(int argc, char *argv[])
{
    int opt;
    while((opt = getopt(argc, argv, "s:li:d")) != -1) {
        switch (opt) {
            case 's':
                params.server = optarg;
                break;

            case 'l':
                params.syslog_enabled = true;
                break;

            case 'i':
                params.interface = optarg;
                break;

            case 'd':
                params.stdout_enabled = true;
                break;

            case '?':
                fprintf(stderr, "Špatně zadaný parametr %c! Viz manuál.\n", optopt);
                exit(22);
                break;

            case ':':
                fprintf(stderr, "Argument potřebuje hodnotu!\n");
                exit(22);
                break;
        }
    }

    for(; optind < argc; optind++){
        fprintf(stderr, "Neznámý argument: %s\n", argv[optind]);
        exit(22);
    }

    if (params.server == nullptr) {
        fprintf(stderr, "Zadejte adresu DHCPv6 serveru. Např.: d6r -s IP6_ADDR_SERVERU\n");
        exit(22);
    }
}

/**
 * @brief Vstupní bod programu
 * @param argc počet argumentů
 * @param argv argumenty
 * @return
 */
int main(int argc, char *argv[])
{
    parseParameters(argc, argv);

    char errbuf[PCAP_ERRBUF_SIZE];
    openlog ("d6r", LOG_CONS, LOG_USER);

    std::thread ts(sniffServer);

    pcap_if_t *interfaces;
    if (pcap_findalldevs(&interfaces,errbuf) == -1) {
        fprintf(stderr, "Není žádný interface dostupný.\n");
    }

    int i = 0;
    std::thread threads[100];

    while (interfaces != nullptr) {
        pcap_addr_t *addr;
        bool hasIpv6 = false;

        // zjisti, jestli interface ma ipv6 hlavicku
        for (addr = interfaces->addresses; addr != NULL; addr = addr->next) {
            if (addr->addr->sa_family == AF_INET6 && addr->addr && addr->netmask) {
                hasIpv6 = true;
            }
        }

        if (params.interface == nullptr || strcmp(params.interface, interfaces->name) == 0) {
            if (hasIpv6) {
                threads[i] = std::thread(sniffInterface, interfaces->name);
                i++;
            }
        }

        interfaces = interfaces->next;
    }

    if (i == 0) {
        fprintf(stderr, "No interface found\n");
        exit(33);
    }

    for (int y = 0; y < i; y++) {
        threads[y].join();
    }

    while(1);

    return 0;
}
