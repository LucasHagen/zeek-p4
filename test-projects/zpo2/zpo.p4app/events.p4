#ifndef ZPO_EVENTS
#define ZPO_EVENTS

#include "types.p4"

struct z_icmp_info {
    z_bool  v6;             // True if it's an ICMPv6 packet.
	z_count itype;          // The ICMP type of the current packet.
	z_count icode;          // The ICMP code of the current packet.
	z_count len;            // The length of the ICMP payload.
	z_count ttl;            // The encapsulating IP header's TTL (IPv4) or Hop Limit (IPv6).

    // Total: 33 bytes
}

// Generated for ICMP *echo request* messages.
header icmp_echo_request_event_h {
    z_count id;         // id           (8 bytes)
    z_count seq;        // seq          (8 bytes)
    z_icmp_info info;   // icmp_info    (33 bytes)
    // Total: 49 bytes
}

// Generated for ICMP *echo reply* messages.
header icmp_echo_reply_event_h {
    z_count id;         // id           (8 bytes)
    z_count seq;        // seq          (8 bytes)
    z_icmp_info info;   // icmp_info    (33 bytes)

    // Total: 49 bytes
}

// Generated for ARP requests or replies (ONLY IPV4).
header arp_request_or_reply_event_h {
    mac_addr_t  mac_src;
    mac_addr_t  mac_dst;
    ipv4_addr_t src_proto_addr;
    mac_addr_t  src_hw_addr;
    ipv4_addr_t target_proto_addr;
    mac_addr_t  target_hw_addr;
}


#endif /* ZPO_EVENTS */

