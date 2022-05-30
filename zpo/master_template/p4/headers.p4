#ifndef RNA_HEADERS
#define RNA_HEADERS

@@LOADED_PROTOCOLS@@

// ZEEK TYPES
typedef bit<8> z_bool;      // boolean      (1 byte)
typedef bit<64> z_int;      // signed int   (8 bytes)
typedef bit<64> z_count;    // unsigned int (8 bytes)

// MERGED HEADER DEFINITIONS     \/ \/ \/

@@HEADER_DEFINITIONS@@

// END MERGED HEADER DEFINITIONS /\ /\ /\

#define ETH_P_RNA 0x6606

#define RNA_P_DEBUG      0
#define RNA_P_ETH_EVENT  1
#define RNA_P_IPV4_EVENT 2
#define RNA_P_IPV6_EVENT 3

// Ethertype (ETH_P_RNA) 0x6606
header rna_h {          // Bytes
    bit<16>  version;    // 1 -> version/hash
    bit<16>  rna_type;   // 1 -> debug (0), eth (1), ip (2), ipv6 (3)
}

// Event Header for non-ip based events, for ex: ARP
header eth_event_h {
    bit<16> next_header;        // 2
    bit<16> protocol_l3;        // 2
}

struct ipv4_header_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

// Event Header for IPv4 based events, for ex: ICMP, TCP, NTP...
header ipv4_event_h {
    bit<16>       next_header; // Or next event
    bit<16>       src_port;
    bit<16>       dst_port;
    ipv4_header_t ipv4_hdr;
}

struct ipv6_header_t {
    bit<4>   version;
    bit<8>   traffic_class;
    bit<20>  flow_label;
    bit<16>  payload_length;
    bit<8>   next_header;
    bit<8>   hop_limit;
    bit<128> src_addr;
    bit<128> dst_addr;
}

// Event Header for IPv6 based events, for ex: ICMP, TCP, NTP...
header ipv6_event_h {
    bit<16>       next_header; // Or next event
    bit<16>       src_port;
    bit<16>       dst_port;
    ipv6_header_t ipv6_hdr;
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

@@HEADERS_STRUCT@@

// END AUTOMATICALLY GENERATED HEADER STRUCT /\ /\ /\

#endif
