#include <stdlib.h>
#include <iostream>
#include <pcap.h>

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

int main()
{
    cout << "Hello world!\n";

    char *interface = getFirstDevice();
    printf("Device: %s\n", interface);

    return 0;
}
