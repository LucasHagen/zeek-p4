#ifndef ZPO_HEADERS
#define ZPO_HEADERS

#include "constants.p4"

// Some header definitions were based on:
// https://github.com/p4lang/papers/blob/master/sosr15/DC.p4/includes/headers.p4

typedef bit<48>  mac_addr_t;
typedef bit<32>  ipv4_addr_t;
typedef bit<128> ipv6_addr_t;

// START ZEEK DATATYPE DEFINITIONS

typedef bit<8> z_bool;     // boolean      (1 byte)
typedef bit<64> z_int;      // signed int   (8 bytes)
typedef bit<64> z_count;    // unsigned int (8 bytes)

// END ZEEK DATATYPE DEFINITIONS

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16>   ethertype;
}

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

header icmp_h {
    bit<8>    type_;
    bit<8>    code;
    bit<16>   hdr_checksum;
    bit<16>   id;
    bit<16>   seq;
}

header icmpv6_h {
    bit<8>    type_;
    bit<8>    code;
    bit<16>   hdr_checksum;
}

header arp_h {
    bit<16> hw_type;
    bit<16> proto_type;
    bit<8>  hw_addr_len;
    bit<8>  proto_addr_len;
    bit<16> opcode;
}

header arp_ipv4_h {
    bit<48> src_hw_addr;
    bit<32> src_proto_addr;
    bit<48> dst_hw_addr;
    bit<32> dst_proto_addr;
}

// Event Header for non-ip based events, for ex: ARP
header eth_event_h {
    bit<32> pkt_num;            // 4
    bit<16> protocol_l3;        // 2
    bit<16> type;               // 2
}

// Event Header for IPv4 based events, for ex: ICMP, TCP, NTP...
header ip_event_h {
    bit<32> pkt_num;            // 4
    bit<16> src_port;           // 2
    bit<16> dst_port;           // 2
    bit<16> type;               // 2
    // bit<160> ipv4_header;       // 20
}

header_union event_h {
    eth_event_h eth_event;
    ip_event_h ip_event;
}

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

struct headers  {
    ethernet_h  ethernet;
    event_h     event;
    ipv4_h      ipv4;
    ipv6_h      ipv6;
    arp_h       arp;
    arp_ipv4_h  arp_ipv4;
    icmp_h      icmp;
    icmpv6_h    icmpv6;
    icmp_echo_request_event_h   icmp_echo_request_event;
    icmp_echo_reply_event_h     icmp_echo_reply_event;
}

struct metadata {
    bit<32> nhop_ipv4;
    bit<32> pkt_num;
    bit<16> protocol_l3;
    bit<8>  protocol_l4;
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> event_type;
}

#endif /* ZPO_HEADERS */

