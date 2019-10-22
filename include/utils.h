#pragma once

#include <iostream>
#include <iomanip>
#include <string>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h> 
#include "ether.h"
#include "xpkt.h"

#define BZERO(buf,size) memset(buf, 0, size)
#define IS_SAME_IP(ip1, ip2) !(memcmp(ip1, ip2, 4))

void get_dev_info(std::string dev, pktbyte_n *mac, pktbyte_n *ip);
void print_mac(pktbyte_n *mac, std::string prefix);
void parse_mac(pktbyte_n *mac, std::string *mac_str);
void print_ip(pktbyte_n *ip, std::string prefix);
void parse_ip(pktbyte_n *ip, std::string *ip_str);