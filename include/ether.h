#pragma once

#include <cstring>
#include <cstdint>
#include <linux/types.h>
#include <arpa/inet.h>
#include "xpkt.h"

#define ETH_ALEN	6		/* Octets in one ethernet addr	 */
#define ETH_HLEN	14		/* Total octets in header.	 */

#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define ETH_P_ARP	0x0806		/* Address Resolution packet	*/

#define ETHERNET(pkt)      (reinterpret_cast<struct ethhdr*>(pkt))    

struct ethhdr {
	unsigned char	h_dest[ETH_ALEN];	/* destination eth addr	*/
	unsigned char	h_source[ETH_ALEN];	/* source ether addr	*/
	__be16		h_proto;		/* packet type ID field	*/
} __attribute__((packed));

class Ether : public Xpkt{
    private:
        pktbyte_n h_dest[ETH_ALEN];
        pktbyte_n h_source[ETH_ALEN];
        pktword_n h_proto;

    public:
        Ether(pktbyte_n *dst, pktbyte_n *src, pktword_h proto);
        pktword_n get_proto();
};
