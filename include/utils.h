#pragma once

#include <iostream>
#include <iomanip>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h> 
#include "ether.h"
#include "xpkt.h"

#define BZERO(buf,size) memset(buf, 0, size)

void get_dev_info(char *dev, pktbyte_n *mac, pktbyte_n *ip);
void print_mac(pktbyte_n *mac, const char *prefix);
void parse_mac(pktbyte_n *mac, char* mac_str);
void print_ip(pktbyte_n *ip, const char *prefix);
void parse_ip(pktbyte_n *ip, char* ip_str);