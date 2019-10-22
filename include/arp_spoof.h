#pragma once

#include <map>
#include <unordered_map>
#include <string>
#include <thread>
#include <vector>
#include <pcap.h>
#include "agent.h"
#include "arp.h"
#include "ip.h"

class ArpSpoofSession {
    private:
        Agent sender;
        Agent target;

    public:
        ArpSpoofSession(Agent sender, Agent target);

        Agent* get_sender() { return &sender; }
        Agent* get_target() { return &target; }

        void print_session();
};

class ArpSpoofer: public Agent{
    private:
        std::vector<ArpSpoofSession> arp_sessions;
        std::unordered_map<std::string, std::string> arp_map;
        std::thread corrupter;      //corrupt sender ARP table
        std::thread relayer;        //relay packet to target
    
    public:
        ArpSpoofer() : Agent() {}
        ArpSpoofer(std::string name, std::string dev) : Agent(name, dev) {}

        int create_session(std::string sender_name, std::string sender_ip, std::string target_name, std::string target_ip);
        void print_sessions();
        void start_sessions();
        void join_sessions();
        void acquire_target_mac(Agent *target);
        void acquire_sessions_hwaddr();
        bool send_arp(Agent *sender, Agent *target);
        void corrupt();
        bool is_recovery_detected(Arp *arp, ArpSpoofSession *sess);
        void disrupt(ArpSpoofSession *sess);
        void relay();
        bool arp_spoof();
};