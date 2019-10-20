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

    char *interface = argv[1];
    char sender_name[MAXNAME+1];
    char target_name[MAXNAME+1];
    int num_sessions = (argc-2) / 2;
    ArpSpoofer attacker = ArpSpoofer("hhro", interface);
    Xpkt xpkt = Xpkt();                     // general packet object

    for(int i = 1; i <= num_sessions ; i++){
        BZERO(sender_name, MAXNAME+1);
        BZERO(target_name, MAXNAME+1);

        snprintf(sender_name, MAXNAME, "sender%d", i);
        snprintf(target_name, MAXNAME, "target%d", i);

        attacker.create_session(sender_name, argv[2*i], target_name, argv[2*i+1]);
    }

    attacker.acquire_sessions_hwaddr();

    std::cout << "[Interface]" << std::endl;
    std::cout << "Interface: " << interface << std::endl;

    std::cout << "[Sessions]" << std::endl;
    attacker.print_sessions();
    std::cout << std::endl;

    /*
    std::cout << "[Result]" << std::endl;
    // Do ARP spoof
    if(attacker.arp_spoof(&sender, &target)){
        std::cout << "Spoofing success" << std::endl;
    }
    std::cout << std::endl;
    */
}