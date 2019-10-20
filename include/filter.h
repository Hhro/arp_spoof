#pragma once

#include "ether.h"
#include "arp.h"
#include "xpkt.h"

#define CATCH   true
#define FAIL    false

bool filter_ip(pktbyte_n *pkt);
bool filter_arp(pktbyte_n *pkt);
bool filter_arp_req(pktbyte_n *pkt);
bool filter_arp_reply(pktbyte_n *pkt);