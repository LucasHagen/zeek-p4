#ifndef ZPO_HEADERS
#define ZPO_HEADERS

// ZEEK TYPES
typedef bit<8> z_bool;      // boolean      (1 byte)
typedef bit<64> z_int;      // signed int   (8 bytes)
typedef bit<64> z_count;    // unsigned int (8 bytes)

// MERGED HEADER DEFINITIONS     \/ \/ \/

@@HEADER_DEFINITIONS@@

// END MERGED HEADER DEFINITIONS /\ /\ /\

// Event Header for non-ip based events, for ex: ARP
header eth_event_h {
    bit<32> pkt_num;            // 4
    bit<16> protocol_l3;        // 2
    bit<16> type;               // 2
}

// Event Header for IPv4 based events, for ex: ICMP, TCP, NTP...
header ipv4_event_h {
    bit<32>     pkt_num;            // 4
    bit<16>     src_port;           // 2
    bit<16>     dst_port;           // 2
    bit<16>     type;               // 2
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
    bit<32>     pkt_num;            // 4
    bit<16>     src_port;           // 2
    bit<16>     dst_port;           // 2
    bit<16>     type;               // 2
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
    bit<32> nhop_ipv4;
    bit<32> pkt_num;
    bit<16> protocol_l3;
    bit<8>  protocol_l4;
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> event_type;
}

// AUTOMATICALLY GENERATED HEADER STRUCT     \/ \/ \/

@@HEADERS_STRUCT@@

// END AUTOMATICALLY GENERATED HEADER STRUCT /\ /\ /\

#endif
