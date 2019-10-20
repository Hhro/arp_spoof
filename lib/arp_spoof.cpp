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

ArpSpoofer::ArpSpoofer(){
}

ArpSpoofer::ArpSpoofer(char *name, char *dev): Agent(name, dev){
}

int ArpSpoofer::create_session(char *sender_name, char *sender_ip, char *target_name, char *target_ip){
    Agent sender = Agent(sender_name);
    Agent target = Agent(target_name);

    sender.set_ip_str(sender_ip);
    target.set_ip_str(target_ip);

    //would be deleted by destoryer
    ArpSpoofSession sess = ArpSpoofSession(sender, target);
    
    this->arp_sessions.push_back(sess);
    this->arp_sessions[sender_ip] = nullptr;
    this->arp_sessions[target_ip] = nullptr;

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
    if(arp_map.find(target->ip_str) == arp_map.end()){
        arp_get_target_mac(target);
        arp_map[target->ip_str] = target->mac_str;
    }
    else{
        target->set_mac_str(arp_map[target->ip_str]);
    }
}

void ArpSpoofer::acquire_sessions_hwaddr(){
    auto sess_iter = this->arp_sessions.begin();

    for(sess_iter; sess_iter!=this->arp_sessions.end(); sess_iter++){
        Agent *sender = &((*sess_iter).sender);
        Agent *target = &((*sess_iter).target);

        acquire_target_hwaddr(sender);
        acquire_target_hwaddr(target);
    }
}