#include "ether.h"

Ether::Ether(pktbyte_n *dst, pktbyte_n *src, pktword_h proto) : Xpkt(){
    memcpy(h_dest, dst, ETH_ALEN);
    memcpy(h_source, src, ETH_ALEN);
    h_proto = htons(proto);

    Ether::append(h_dest, ETH_ALEN);
    Ether::append(h_source, ETH_ALEN);
    Ether::append(WPTR_TO_BPTR(&h_proto), 2);
}

pktword_n Ether::get_proto(){
    return h_proto;
}