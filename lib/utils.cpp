#include "utils.h"

/*
http://community.onion.io/topic/2441/obtain-the-mac-address-in-c-code/2
*/
void get_dev_info(char *dev, pktbyte_n *mac, pktbyte_n *ip)
{
    int s;
    struct ifreq ifr;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    ioctl(s, SIOCGIFHWADDR, &ifr);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    ioctl(s, SIOCGIFADDR, &ifr);
    memcpy(ip, ifr.ifr_addr.sa_data + 2, 4);
}

void print_mac(pktbyte_n *mac, const char *prefix){
    if(prefix){
        std::cout << prefix;
    }
    std::cout << "MAC: ";

    std::ios_base::fmtflags f( std::cout.flags() );

    for(int i=0; i < ETH_ALEN; i++){
        std::cout 
        << std::hex 
        << std::setw(2) 
        << std::setfill('0') 
        << static_cast<int>(mac[i]);
        
        if(i != ETH_ALEN-1){
            std::cout << ":";
        }
    }
    std::cout << std::endl;

    std::cout.flags(f);
}

void parse_mac(pktbyte_n *mac, char *mac_str){
    for(int i=0; i< ETH_ALEN; i++){
        sprintf(mac_str+3*i, "%02X", mac[i]);

        if(i!=ETH_ALEN-1)
            strcat(mac_str,":");
    }
}

void print_ip(pktbyte_n *ip, const char *prefix){
    char ip_str[20];

    if(prefix){
        std::cout << prefix;
    }

    inet_ntop(AF_INET, ip, ip_str, sizeof(ip_str));
    std::cout << "IP: " << ip_str;
}

void parse_ip(pktbyte_n *ip, char *ip_str){
    const char *res = inet_ntop(AF_INET, ip, ip_str, sizeof(ip_str));

    if(res == NULL){
        std::cerr << "IP is invalid" << std::endl;
        exit(-1);
    }
}