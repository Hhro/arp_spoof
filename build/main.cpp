#include <iostream>
#include <vector>
#include <arpa/inet.h>
#include "filter.h"
#include "utils.h"
#include "agent.h"
#include "ether.h"
#include "arp.h"
#include "arp_spoof.h"

void usage(){
    std::cout << "Usage: ./arp_spoof <interface> <sender1 ip> <target1 ip> [<sender2 ip> <target2 ip>...]" << std::endl;
    std::cout << "Example: ./send_arp wlan0 176.12.93.12 172.30.19.18 172.30.19.18 172.12.93.12" << std::endl;
}

int main(int argc, char *argv[]){
    if(argc < 4 || argc&1){
        usage();
        exit(-1);
    }

    std::string interface = argv[1];
    std::string sender_name;
    std::string target_name;
    std::string sender_ip;
    std::string target_ip;
    int num_sessions = (argc-2) / 2;
    ArpSpoofer attacker = {"hhro", interface};

    std::cout << "[Interface] "
              << "Adapter: " << interface << std::endl;

    for(int i = 1; i <= num_sessions ; i++){
        sender_name = "sender" + std::to_string(i);
        target_name = "target" + std::to_string(i);
        sender_ip = argv[2*i];
        target_ip = argv[2*i+1];

        attacker.create_session(sender_name, sender_ip, target_name, target_ip);
    }

    attacker.acquire_sessions_hwaddr();

    attacker.print_sessions();

    if(attacker.arp_spoof()){
        std::cout << "Spoofing success" << std::endl;
    }
    std::cout << std::endl;
}
