#pragma once

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <pcap.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include "utils.h"
#include "ether.h"
#include "xpkt.h"

#define IP(pkt)    (reinterpret_cast<struct iphdr *>(pkt + ETH_HLEN))

class Ip : public Xpkt{
    private:
        pktbyte_n  ip_hlv;
        pktbyte_n  ip_tos;
        pktword_n  ip_tot_len;
        pktword_n  ip_id;
        pktword_n  ip_frag_off;
        pktbyte_n  ip_ttl;
        pktbyte_n  ip_protocol;
        pktword_n  ip_check;
        pktbyte_n  ip_saddr[4];
        pktbyte_n  ip_daddr[4];
        pktbyte_n  *ip_payload;

        std::string ip_saddr_str;
        std::string ip_daddr_str;

    public:
        Ip(Xpkt xpkt);
        Ip(
            pktbyte_n protocol,
            pktbyte_n *saddr,
            pktbyte_n *daddr
        );
        pktbyte_n* get_saddr() { return ip_saddr; }
        pktbyte_n* get_daddr() { return ip_daddr; }
        std::string get_saddr_str() { return ip_saddr_str; }
        std::string get_daddr_str() { return ip_daddr_str; }
        void assemble();
        void dissect();
};