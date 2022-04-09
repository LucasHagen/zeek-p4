#ifndef ZPO_HEADERS
#define ZPO_HEADERS

#include "constants.p4"
#include "types.p4"
#include "events.p4"

// Some header definitions were based on:
// https://github.com/p4lang/papers/blob/master/sosr15/DC.p4/includes/headers.p4

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
    mac_addr_t  src_hw_addr;
    ipv4_addr_t src_proto_addr;
    mac_addr_t  target_hw_addr;
    ipv4_addr_t target_proto_addr;
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

struct headers  {
    ethernet_h  ethernet;
    event_h     event;
    ipv4_h      ipv4;
    ipv6_h      ipv6;
    arp_h       arp;
    arp_ipv4_h  arp_ipv4;
    icmp_h      icmp;
    icmpv6_h    icmpv6;
    icmp_echo_request_event_h       icmp_echo_request_event;
    icmp_echo_reply_event_h         icmp_echo_reply_event;
    arp_request_or_reply_event_h    arp_req_or_reply_event;
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

