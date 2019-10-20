#include "filter.h"

bool filter_ip(pktbyte_n *pkt){
    ethhdr *ethernet = ETHERNET(pkt);

    if(ethernet->h_proto == htons(ETH_P_IP)){
        return CATCH;
    }

    return FAIL;
}

bool filter_arp(pktbyte_n *pkt){
    ethhdr *ethernet = ETHERNET(pkt);

    if(ethernet->h_proto == htons(ETH_P_ARP)){
        return CATCH;
    }
    
    return FAIL;
}

bool filter_arp_req(pktbyte_n *pkt){
    ethhdr *ethernet = ETHERNET(pkt);

    if(ethernet->h_proto != htons(ETH_P_ARP))
        return FAIL;

    arphdr *arp = ARP(pkt);

    if(arp->ar_op == htons(ARPOP_REQUEST))
        return CATCH;
    
    return FAIL;
}

bool filter_arp_reply(pktbyte_n *pkt){
    ethhdr *ethernet = ETHERNET(pkt);

    if(ethernet->h_proto != htons(ETH_P_ARP))
        return FAIL;

    arphdr *arp = ARP(pkt);

    if(arp->ar_op == htons(ARPOP_REPLY))
        return CATCH;
    
    return FAIL;
}