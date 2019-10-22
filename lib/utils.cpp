#include "utils.h"

/*
http://community.onion.io/topic/2441/obtain-the-mac-address-in-c-code/2
*/
void get_dev_info(std::string dev, pktbyte_n *mac, pktbyte_n *ip)
{
    int s;
    struct ifreq ifr;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, dev.c_str(), IFNAMSIZ);

    ioctl(s, SIOCGIFHWADDR, &ifr);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    ioctl(s, SIOCGIFADDR, &ifr);
    memcpy(ip, ifr.ifr_addr.sa_data + 2, 4);
}

void print_mac(pktbyte_n *mac, std::string prefix){
    std::cout << prefix << "MAC: ";

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

void parse_mac(pktbyte_n *mac, std::string *mac_str){
    std::stringstream ss;
    ss << std::hex;

    for(int i=0; i< ETH_ALEN; i++){
        ss << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);

        if(i!=ETH_ALEN-1)
            ss << ':';
    }
    *mac_str = ss.str();
}

void print_ip(pktbyte_n *ip, std::string prefix){
    char ip_str[20];

    inet_ntop(AF_INET, ip, ip_str, sizeof(ip_str));
    std::cout << prefix << "IP: " << ip_str;
}

void parse_ip(pktbyte_n *ip, std::string *ip_str){
    char ip_str_ch[20];
    const char *res = inet_ntop(AF_INET, ip, ip_str_ch, sizeof(ip_str_ch));

    if(res == NULL){
        std::cerr << "IP is invalid" << std::endl;
        exit(-1);
    }

    *ip_str = std::string(ip_str_ch);
}