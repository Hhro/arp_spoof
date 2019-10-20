#pragma once

#include <unordered_map>
#include <string>
#include <vector>
#include "agent.h"
#include "arp.h"

class ArpSpoofSession {
    private:
        Agent sender;
        Agent target;
    public:
       // ArpSpoofSession() {}
        ArpSpoofSession(Agent sender, Agent target);
        void print_session();
        void get_sender() { return sender; }
        void get_target() { return target; }
};

class ArpSpoofer : public Agent{
    private:
        std::vector<ArpSpoofSession> arp_sessions;
        std::unordered_map<std::string, std::string> arp_map;
    
    public:
        ArpSpoofer();
        ArpSpoofer(char *name, char *dev);
        int create_session(char *sender_name, char *sender_ip, char *target_name, char *target_ip);
        void print_sessions();
        void acquire_session_hwaddr(Agent *agnt);
        void acquire_sessions_hwaddr();
        ~ArpSpoofer() {}
};