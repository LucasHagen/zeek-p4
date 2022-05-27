#ifndef ZPO_HEADERS
#define ZPO_HEADERS

#define ZPO_PROTOCOL_ETHERNET
#define ZPO_PROTOCOL_ARP
#define ZPO_PROTOCOL_IPV4
#define ZPO_PROTOCOL_IPV6
#define ZPO_PROTOCOL_ARP_IPV4
#define ZPO_PROTOCOL_ICMP
#define ZPO_NO_EVENT_UID 0
#define ZPO_ARP_REPLY_EVENT_UID 1
#define ZPO_ARP_REQUEST_EVENT_UID 2
#define ZPO_ICMP_ECHO_REPLY_EVENT_UID 3
#define ZPO_ICMP_ECHO_REQUEST_EVENT_UID 4

// ZEEK TYPES
typedef bit<8> z_bool;      // boolean      (1 byte)
typedef bit<64> z_int;      // signed int   (8 bytes)
typedef bit<64> z_count;    // unsigned int (8 bytes)

// MERGED HEADER DEFINITIONS     \/ \/ \/

// Header for protocol template 'ethernet':

// L3 PROTOCOL CODES
const bit<16>   ETH_P_EVENT     = 0x6601;
const bit<16>   ETH_P_EVENT_IP  = 0x6602;
const bit<16>   ETH_P_IPV4      = 0x0800;
const bit<16>   ETH_P_IPV6      = 0x86DD;
const bit<16>   ETH_P_ARP       = 0x0806;

typedef bit<48>  mac_addr_t;

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16>   ethertype;
}

// Header for protocol template 'arp':

header arp_h {
    bit<16> hw_type;
    bit<16> proto_type;
    bit<8>  hw_addr_len;
    bit<8>  proto_addr_len;
    bit<16> opcode;
}

// Header for protocol template 'ipv4':

// L4 PROTOCOL CODES
const bit<8>    IPPROTO_ICMP    = 0x01;
const bit<8>    IPPROTO_TCP     = 0x06;
const bit<8>    IPPROTO_UDP     = 0x11;

typedef bit<32>  ipv4_addr_t;

header ipv4_h {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   total_len;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   frag_offset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

// Header for protocol template 'ipv6':

// L4 PROTOCOL CODES
const bit<8>    IPPROTO_ICMPV6  = 0x3A;

typedef bit<128>  ipv6_addr_t;

header ipv6_h {
    bit<4>    version;
    bit<8>    traffic_class;
    bit<20>   flow_label;
    bit<16>   payload_length;
    bit<8>    next_header;
    bit<8>    hop_limit;
    ipv6_addr_t src_addr;
    ipv6_addr_t dst_addr;
}

// Header for protocol template 'arp_ipv4':

header arp_ipv4_h {
    mac_addr_t  src_hw_addr;
    ipv4_addr_t src_proto_addr;
    mac_addr_t  target_hw_addr;
    ipv4_addr_t target_proto_addr;
}

// Header for protocol template 'icmp':

#define ICMP_ECHOREPLY 0    /* Echo Reply			    */
#define ICMP_DEST_UNREACH 3    /* Destination Unreachable	*/
#define ICMP_SOURCE_QUENCH 4    /* Source Quench		    */
#define ICMP_REDIRECT 5    /* Redirect (change route)	*/
#define ICMP_ECHO 8    /* Echo Request			    */
#define ICMP_TIME_EXCEEDED 11   /* Time Exceeded		    */
#define ICMP_PARAMETERPROB 12   /* Parameter Problem		*/
#define ICMP_TIMESTAMP 13   /* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY 14   /* Timestamp Reply		    */
#define ICMP_INFO_REQUEST 15   /* Information Request		*/
#define ICMP_INFO_REPLY 16   /* Information Reply		*/
#define ICMP_ADDRESS 17   /* Address Mask Request		*/
#define ICMP_ADDRESSREPLY 18   /* Address Mask Reply		*/

/* Definition of type and code fields. */
/* defined above: ICMP_ECHOREPLY, ICMP_REDIRECT, ICMP_ECHO */
#define ICMP_UNREACH 3 /* dest unreachable, codes: */
#define ICMP_SOURCEQUENCH 4 /* packet lost, slow down */
#define ICMP_ROUTERADVERT 9 /* router advertisement */
#define ICMP_ROUTERSOLICIT 10 /* router solicitation */
#define ICMP_TIMXCEED 11 /* time exceeded, code: */
#define ICMP_PARAMPROB 12 /* ip header bad */
#define ICMP_TSTAMP 13 /* timestamp request */
#define ICMP_TSTAMPREPLY 14 /* timestamp reply */
#define ICMP_IREQ 15 /* information request */
#define ICMP_IREQREPLY 16 /* information reply */
#define ICMP_MASKREQ 17 /* address mask request */
#define ICMP_MASKREPLY 18 /* address mask reply */

#define ICMP_MAXTYPE 18

/* UNREACH codes */
#define ICMP_UNREACH_NET 0 /* bad net */
#define ICMP_UNREACH_HOST 1 /* bad host */
#define ICMP_UNREACH_PROTOCOL 2 /* bad protocol */
#define ICMP_UNREACH_PORT 3 /* bad port */
#define ICMP_UNREACH_NEEDFRAG 4 /* IP_DF caused drop */
#define ICMP_UNREACH_SRCFAIL 5 /* src route failed */
#define ICMP_UNREACH_NET_UNKNOWN 6 /* unknown net */
#define ICMP_UNREACH_HOST_UNKNOWN 7 /* unknown host */
#define ICMP_UNREACH_ISOLATED 8 /* src host isolated */
#define ICMP_UNREACH_NET_PROHIB 9 /* net denied */
#define ICMP_UNREACH_HOST_PROHIB 10 /* host denied */
#define ICMP_UNREACH_TOSNET 11 /* bad tos for net */
#define ICMP_UNREACH_TOSHOST 12 /* bad tos for host */
#define ICMP_UNREACH_FILTER_PROHIB 13 /* admin prohib */
#define ICMP_UNREACH_HOST_PRECEDENCE 14 /* host prec vio. */
#define ICMP_UNREACH_PRECEDENCE_CUTOFF 15 /* prec cutoff */

/* REDIRECT codes */
#define ICMP_REDIRECT_NET 0 /* for network */
#define ICMP_REDIRECT_HOST 1 /* for host */
#define ICMP_REDIRECT_TOSNET 2 /* for tos and net */
#define ICMP_REDIRECT_TOSHOST 3 /* for tos and host */

/* TIMEXCEED codes */
#define ICMP_TIMXCEED_INTRANS 0 /* ttl==0 in transit */
#define ICMP_TIMXCEED_REASS 1 /* ttl==0 in reass */

/* PARAMPROB code */
#define ICMP_PARAMPROB_OPTABSENT 1 /* req. opt. absent */

header icmp_h {
    bit<8>    type_;
    bit<8>    code;
    bit<16>   hdr_checksum;
    bit<16>   id;
    bit<16>   seq;
}

// Header for event template 'arp_reply':

// Generated for ARP requests or replies (ONLY IPV4).
header arp_reply_event_h {
    mac_addr_t  mac_src;
    mac_addr_t  mac_dst;
    mac_addr_t  src_hw_addr;
    ipv4_addr_t src_proto_addr;
    mac_addr_t  target_hw_addr;
    ipv4_addr_t target_proto_addr;
}

// Header for event template 'arp_request':

// Generated for ARP requests or replies (ONLY IPV4).
header arp_request_event_h {
    mac_addr_t  mac_src;
    mac_addr_t  mac_dst;
    mac_addr_t  src_hw_addr;
    ipv4_addr_t src_proto_addr;
    mac_addr_t  target_hw_addr;
    ipv4_addr_t target_proto_addr;
}

// Header for event template 'icmp_echo_reply':

// Generated for ICMP *echo reply* messages.
header icmp_echo_reply_event_h {
    z_count id;         // id           (8 bytes)
    z_count seq;        // seq          (8 bytes)
    // start 'icmp_info' struct
    z_bool  v6;         // True if it's an ICMPv6 packet.
	z_count itype;      // The ICMP type of the current packet.
	z_count icode;      // The ICMP code of the current packet.
	z_count len;        // The length of the ICMP payload.
	z_count ttl;        // The encapsulating IP header's TTL (IPv4) or Hop Limit (IPv6).
    // Total: 49 bytes
}

// Header for event template 'icmp_echo_request':

// Generated for ICMP *echo request* messages.
header icmp_echo_request_event_h {
    z_count id;         // id           (8 bytes)
    z_count seq;        // seq          (8 bytes)
    // start 'icmp_info' struct
    z_bool  v6;         // True if it's an ICMPv6 packet.
	z_count itype;      // The ICMP type of the current packet.
	z_count icode;      // The ICMP code of the current packet.
	z_count len;        // The length of the ICMP payload.
	z_count ttl;        // The encapsulating IP header's TTL (IPv4) or Hop Limit (IPv6).
    // Total: 49 bytes
}


// END MERGED HEADER DEFINITIONS /\ /\ /\

// Ethertype 0x6606
header rna_h {          // Bytes
    bit<8>  version;    // 1 -> hash
    bit<8>  rna_type;   // 1 -> debug (0), eth (1), ip (2), ipv6 (3)
}

// RNA_TYPE=1, Event Header for non-ip based events, for ex: ARP
header eth_event_h {
    bit<16> next_protocol;  // 2
    bit<16> protocol_l3;    // 2
}

// Event Header for IPv4 based events, for ex: ICMP, TCP, NTP...
header ipv4_event_h {
    bit<16>     next_protocol;      // 2
    bit<16>     src_port;           // 2
    bit<16>     dst_port;           // 2
    // IPv4 Header
    bit<4>      version;
    bit<4>      ihl;
    bit<8>      diffserv;
    bit<16>     total_len;
    bit<16>     identification;
    bit<3>      flags;
    bit<13>     frag_offset;
    bit<8>      ttl;
    bit<8>      protocol;
    bit<16>     hdr_checksum;
    bit<32>     src_addr;
    bit<32>     dst_addr;
    // End IPv4 Header
}

// Event Header for IPv6 based events, for ex: ICMP, TCP, NTP...
header ipv6_event_h {
    bit<16>     next_protocol;      // 2
    bit<16>     src_port;           // 2
    bit<16>     dst_port;           // 2
    // IPv6 Header
    bit<4>      version;
    bit<8>      traffic_class;
    bit<20>     flow_label;
    bit<16>     payload_length;
    bit<8>      next_header;
    bit<8>      hop_limit;
    bit<128>    src_addr;
    bit<128>    dst_addr;
    // End IPv6 Header
}

header_union event_h {
    eth_event_h eth_event;
    ipv4_event_h ipv4_event;
    ipv6_event_h ipv6_event;
}

struct metadata {
    bit<32>  nhop_ipv4;
    bit<128> nhop_ipv6;
    bit<32>  pkt_num;
    bit<16>  protocol_l3;
    bit<8>   protocol_l4;
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<16>  event_type;
}

// AUTOMATICALLY GENERATED HEADER STRUCT     \/ \/ \/

struct headers {
    ethernet_h ethernet;
    arp_h arp;
    ipv4_h ipv4;
    ipv6_h ipv6;
    arp_ipv4_h arp_ipv4;
    icmp_h icmp;
    event_h event;
    arp_request_event_h arp_request_event;
    icmp_echo_request_event_h icmp_echo_request_event;
    arp_reply_event_h arp_reply_event;
    icmp_echo_reply_event_h icmp_echo_reply_event;
}

// END AUTOMATICALLY GENERATED HEADER STRUCT /\ /\ /\

#endif
