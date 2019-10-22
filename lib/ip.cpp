#include "ip.h"

Ip::Ip(Xpkt xpkt) : Xpkt(xpkt){
    Ip::dissect();
}

Ip::Ip(pktbyte_n protocol, pktbyte_n *saddr, pktbyte_n *daddr){
    std::srand(0xcfcfcfcf);

    ip_hlv = 0x45;  //Only IPv4 now
    ip_tos = 0x0;
    ip_tot_len = htons(0x14);
    ip_id = htons(std::rand()&&0xffff);
    ip_frag_off = 0x0;
    ip_ttl = 128;
    ip_protocol = protocol;
    ip_check = 0;
    
    memcpy(ip_saddr, saddr, 4);
    memcpy(ip_daddr, daddr, 4);

    parse_ip(ip_saddr, &ip_saddr_str);
    parse_ip(ip_daddr, &ip_daddr_str);
}

void Ip::assemble(){
    Ip::append(&ip_hlv, BYTE);
    Ip::append(&ip_tos, BYTE);
    Ip::append(WPTR_TO_BPTR(&ip_tot_len), WORD);
    Ip::append(WPTR_TO_BPTR(&ip_id), WORD);
    Ip::append(WPTR_TO_BPTR(&ip_frag_off), WORD);
    Ip::append(&ip_ttl, BYTE);
    Ip::append(&ip_protocol, BYTE);
    Ip::append(WPTR_TO_BPTR(&ip_check), WORD);
    Ip::append(ip_saddr, 4);
    Ip::append(ip_daddr, 4);

    if(ip_payload)
        Ip::append(ip_payload, ntohs(ip_tot_len) - ip_hlv*4);
}

void Ip::dissect(){
    iphdr *ip = IP(get_pktbuf());

    ip_hlv = ((ip->version)<<4||ip->ihl);
    ip_tos = ip->tos;
    ip_tot_len = ip->tot_len;
    ip_id = ip->id;
    ip_frag_off = ip->frag_off;
    ip_ttl = ip->ttl;
    ip_protocol = ip->protocol;
    ip_check = ip->check;

    memcpy(ip_saddr, &ip->saddr, 4);
    memcpy(ip_daddr, &ip->daddr, 4);

    parse_ip(ip_saddr, &ip_saddr_str);
    parse_ip(ip_daddr, &ip_daddr_str);

    if(ntohs(ip_tot_len) == ip->ihl*4)
        ip_payload = nullptr;
    else
        ip_payload = reinterpret_cast<pktbyte_n*>(ip) + (ip->ihl * 4);
}