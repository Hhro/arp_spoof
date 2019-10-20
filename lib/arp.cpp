#include "arp.h"

Arp::Arp(Xpkt xpkt) : Xpkt(xpkt){
    Arp::dissect();
}

Arp::Arp(pktword_h op, pktbyte_h *sha, pktbyte_h *sip, pktbyte_h *tha, pktbyte_h *tip){
    ar_hrd = htons(ARPHRD_ETHER);  //Ethernet
    ar_pro = htons(ETH_P_IP);      //IPV4
    ar_hln = 6;
    ar_pln = 4;
    ar_op = htons(op);

    memcpy(ar_sha, sha, ETH_ALEN);
    memcpy(ar_sip, sip, 4);
    memcpy(ar_tha, tha, ETH_ALEN);
    memcpy(ar_tip, tip, 4);

    Arp::assemble();
}

pktword_n Arp::get_pro(){
    return ar_pro;
}

pktword_n Arp::get_op(){
    return ar_op;
}

pktbyte_n* Arp::get_sha(){
    return ar_sha;
}

pktbyte_n* Arp::get_sip(){
    return ar_sip;
}

pktbyte_n* Arp::get_tha(){
    return ar_tha;
}

pktbyte_n* Arp::get_tip(){
    return ar_tip;
}

void Arp::assemble(){
    Arp::append(WPTR_TO_BPTR(&ar_hrd), WORD);
    Arp::append(WPTR_TO_BPTR(&ar_pro), WORD);
    Arp::append(&ar_hln, BYTE);
    Arp::append(&ar_pln, BYTE);
    Arp::append(WPTR_TO_BPTR(&ar_op), WORD);
    Arp::append(ar_sha, ETH_ALEN);
    Arp::append(ar_sip, 4);
    Arp::append(ar_tha, ETH_ALEN);
    Arp::append(ar_tip, 4);
}

void Arp::dissect(){
    arphdr *arp = ARP(pktbuf); 

    ar_hrd = arp->ar_hrd;
    ar_pro = arp->ar_pro;
    ar_hln = arp->ar_hln;
    ar_pln = arp->ar_pln;
    ar_op = arp->ar_op;

    memcpy(ar_sha, arp->ar_sha, ETH_ALEN);
    memcpy(ar_sip, arp->ar_sip, 4);
    memcpy(ar_tha, arp->ar_tha, ETH_ALEN);
    memcpy(ar_tip, arp->ar_tip, 4);
}