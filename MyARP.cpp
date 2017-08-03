#include "MyARP.h"
#include <glog/logging.h>

bool equalIPaddr(const IPaddr ip1, const IPaddr ip2)
{
    return memcmp(&ip1, &ip2, IP_ADDR_LEN) == 0;
}

bool equalHWaddr(const HWaddr ha1, const HWaddr ha2)
{
    return memcmp(&ha1, &ha2, HW_ADDR_LEN) == 0;
}

bool getMyHWaddr(HWaddr *myha, const char *interface)
{
    int             fd;
    struct ifreq    ifr;

    if((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP))==-1)
    {
        LOG(FATAL) << "socket : failed";
        return false;
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strcpy(ifr.ifr_name, interface);
    if(ioctl(fd, SIOCGIFHWADDR, &ifr)!=0)
    {
        LOG(FATAL) <<  "ioctl : failed";
        return false;
    }

    memcpy(myha, ifr.ifr_hwaddr.sa_data, HW_ADDR_LEN);

    close(fd);

    return true;
}

bool getMyIPaddr(IPaddr *myip, const char *interface)
{
    int             fd;
    struct ifreq    ifr;

    if((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP))==-1)
    {
        LOG(FATAL) << "socket : failed";
        return false;
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strcpy(ifr.ifr_name, interface);
    if(ioctl(fd, SIOCGIFADDR, &ifr)!=0)
    {
        LOG(FATAL) <<  "ioctl : failed";
        return false;
    }

    memcpy(myip, ifr.ifr_addr.sa_data, IP_ADDR_LEN);

    close(fd);

    return true;
}

void makeARPBroadcastPacket(ARPpkt *packet, const HWaddr sha, const IPaddr sip, const IPaddr tip)
{
    *(HWaddr *)packet->eth_hdr.ether_shost = sha;
    memset(packet->eth_hdr.ether_dhost, 0xFF, HW_ADDR_LEN);
    packet->eth_hdr.ether_type = htons(ETHERTYPE_ARP);

    packet->arp_hdr.ar_hrd = htons(ARPHRD_ETHER);
    packet->arp_hdr.ar_pro = htons(ETHERTYPE_IP);
    packet->arp_hdr.ar_hln = HW_ADDR_LEN;
    packet->arp_hdr.ar_pln = IP_ADDR_LEN;
    packet->arp_hdr.ar_op  = htons(ARPOP_REQUEST);

    packet->arp_addr.sha = sha;
    packet->arp_addr.sip = sip;
    memset(&packet->arp_addr.tha, 0x00, HW_ADDR_LEN);
    packet->arp_addr.tip = tip;
}

void makeARPPacket(ARPpkt *packet, const HWaddr sha, const IPaddr sip, const HWaddr tha, const IPaddr tip, const int oper)
{
    *(HWaddr *)packet->eth_hdr.ether_shost = sha;
    *(HWaddr *)packet->eth_hdr.ether_dhost = tha;
    packet->eth_hdr.ether_type = htons(ETHERTYPE_ARP);

    packet->arp_hdr.ar_hrd = htons(ARPHRD_ETHER);
    packet->arp_hdr.ar_pro = htons(ETHERTYPE_IP);
    packet->arp_hdr.ar_hln = HW_ADDR_LEN;
    packet->arp_hdr.ar_pln = IP_ADDR_LEN;
    packet->arp_hdr.ar_op  = htons(oper);

    packet->arp_addr.sha = sha;
    packet->arp_addr.sip = sip;
    packet->arp_addr.tha = tha;
    packet->arp_addr.tip = tip;
}

bool getHWaddrByIPaddr(HWaddr *tha, pcap_t *handle, const HWaddr sha, const IPaddr sip, const IPaddr tip)
{
    ARPpkt sendpkt, *recvpkt;
    struct pcap_pkthdr *header;

    int res;

    makeARPBroadcastPacket(&sendpkt, sha, sip, tip);
    if(pcap_sendpacket(handle, (u_char *)&sendpkt, sizeof(sendpkt)) != 0)
    {
        LOG(FATAL) << "pcap_sendpacket : failed";
        return false;
    }
    while(true)
    {
        res = pcap_next_ex(handle, &header, (const u_char **)&recvpkt);

        if(res < 0)
        {
            LOG(FATAL) << "pcap_next_ex : failed";
            return -1;
        }

        if(res == 0)
        {
            LOG(INFO) << "timeout";
            if(pcap_sendpacket(handle, (u_char *)&sendpkt, sizeof(sendpkt)) != 0)
            {
                LOG(FATAL) << "pcap_sendpacket : failed";
                return false;
            }
            continue;
        }

        if(!equalHWaddr(*(HWaddr *)recvpkt->eth_hdr.ether_dhost, sha) || ntohs(recvpkt->eth_hdr.ether_type) != ETHERTYPE_ARP)
        {
            continue;
        }

        if(ntohs(recvpkt->arp_hdr.ar_hrd) != ARPHRD_ETHER || ntohs(recvpkt->arp_hdr.ar_pro) != ETHERTYPE_IP || ntohs(recvpkt->arp_hdr.ar_op) != ARPOP_REPLY)
        {
            continue;
        }

        if(!equalHWaddr(recvpkt->arp_addr.tha, sha) || !equalIPaddr(recvpkt->arp_addr.tip, sip) || !equalIPaddr(recvpkt->arp_addr.sip, tip))
        {
            continue;
        }

        *tha = recvpkt->arp_addr.sha;
        break;
    }

    return true;
}

int main(int argc, char **argv)
{
    google::InitGoogleLogging(argv[0]);
    return 0;
}