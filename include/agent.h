#pragma once

#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
#include <unistd.h>
#include <thread>
#include <pcap.h>
#include "ip.h"
#include "arp.h"
#include "ether.h"
#include "utils.h"
#include "filter.h"
#include "xpkt.h"

#define MAXNAME    0x10
#define MAXDEV     0x100
#define MAXMACSTR  0x15
#define MAXIPSTR   0x12

class Agent{
    private:
        std::string name;
        std::string dev;
        pktbyte_n mac[ETH_ALEN+1];
        std::string mac_str;
        pktbyte_n ip[4+1];
        std::string ip_str;
    
    public:
        Agent();
        Agent(std::string name);
        Agent(std::string _name, std::string _dev);
        Agent(const Agent &p);

        std::string get_name() { return this->name; }
        std::string get_dev() { return this->dev; }
        pktbyte_n* get_mac() { return this->mac; }
        std::string get_mac_str() { return this->mac_str; }
        pktbyte_n* get_ip() {return this->ip; }
        std::string get_ip_str() {return this->ip_str; }

        void set_mac(pktbyte_n *_mac);
        void set_mac_str(std::string mac_str);
        void set_ip_str(std::string _ip_str);

        void show_info();

        bool from_agent(Ip *ip);
        bool to_agent(Ip *ip);

        int send(Xpkt *pkt);
        int set_pcap_filter(pcap_t *handle, char *filter, bpf_u_int32 net);
        void snatch(std::vector<Xpkt> *caught, const char *pcap_filter, int cnt);

        void arp_send_req(Agent *target);
        //int arp_send_reply(char *dev, pktbyte *target);
        int arp_send_raw(
            pktword_h op, 
            pktbyte_n *sha, 
            pktbyte_n *sip, 
            pktbyte_n *tha, 
            pktbyte_n *tip
        );
        int arp_get_target_mac(Agent *target);
};
