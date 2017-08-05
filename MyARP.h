#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <netinet/in.h>
//#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#define IP_ADDR_LEN 4
#define HW_ADDR_LEN 6

struct ARP_addr
{
    struct ether_addr   sha;
    struct in_addr      sip;
    struct ether_addr   tha;
    struct in_addr      tip;
} __attribute__((packed));

typedef struct in_addr      IPaddr;
typedef struct ether_addr   HWaddr;

struct ARPpkt
{
    struct ether_header eth_hdr;
    struct arphdr       arp_hdr;
    struct ARP_addr     arp_addr;
} __attribute__((packed));

bool equalIPaddr(const IPaddr, const IPaddr);
bool equalHWaddr(const HWaddr, const HWaddr);

bool getMyHWaddr(HWaddr *, const char *);
bool getMyIPaddr(IPaddr *, const char *);

void makeARPBroadcastPacket(ARPpkt *, const HWaddr, const IPaddr, const IPaddr);
void makeARPPacket(ARPpkt *, const HWaddr, const IPaddr, const HWaddr, const IPaddr, const int);

bool getHWaddrByIPaddr(HWaddr *, pcap_t *, const HWaddr, const IPaddr, const IPaddr);