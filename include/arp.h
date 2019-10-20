#pragma once

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <pcap.h>
#include <linux/types.h>
#include <arpa/inet.h>
#include "ether.h"
#include "xpkt.h"


/* ARP protocol HARDWARE identifiers. */
#define ARPHRD_ETHER 	1		/* Ethernet 10Mbps		*/

/* ARP protocol opcodes. */
#define	ARPOP_REQUEST	1		/* ARP request			*/
#define	ARPOP_REPLY	2		/* ARP reply			*/
#define	ARPOP_RREQUEST	3		/* RARP request			*/
#define	ARPOP_RREPLY	4		/* RARP reply			*/
#define	ARPOP_InREQUEST	8		/* InARP request		*/
#define	ARPOP_InREPLY	9		/* InARP reply			*/
#define	ARPOP_NAK	10		/* (ATM)ARP NAK			*/

#define ARP(pkt)    (reinterpret_cast<struct arphdr *>(pkt + ETH_HLEN))

struct arphdr {
	__be16		ar_hrd;		/* format of hardware address	*/
	__be16		ar_pro;		/* format of protocol address	*/
	unsigned char	ar_hln;		/* length of hardware address	*/
	unsigned char	ar_pln;		/* length of protocol address	*/
	__be16		ar_op;		/* ARP opcode (command)		*/

	unsigned char		ar_sha[ETH_ALEN];	/* sender hardware address	*/
	unsigned char		ar_sip[4];		/* sender IP address		*/
	unsigned char		ar_tha[ETH_ALEN];	/* target hardware address	*/
	unsigned char		ar_tip[4];		/* target IP address		*/
};

class Arp : public Xpkt{
    private:
        pktword_n  ar_hrd;
        pktword_n  ar_pro;
        pktbyte_n  ar_hln;
        pktbyte_n  ar_pln;
        pktword_n  ar_op;
        pktbyte_n  ar_sha[ETH_ALEN];
        pktbyte_n  ar_sip[4];
        pktbyte_n  ar_tha[ETH_ALEN];
        pktbyte_n  ar_tip[4]; 

    public:
        Arp(Xpkt xpkt);
        Arp(
            pktword_h op, 
            pktbyte_n *sha, 
            pktbyte_n *sip, 
            pktbyte_n *tha, 
            pktbyte_n *tip
        );
        pktword_n get_pro();
        pktword_n get_op();
        pktbyte_n* get_sha();
        pktbyte_n* get_sip();
        pktbyte_n* get_tha();
        pktbyte_n* get_tip();
        void assemble();
        void dissect();
};