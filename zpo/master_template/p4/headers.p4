#ifndef RNA_HEADERS
#define RNA_HEADERS


@@EXTRA_DEFINITIONS@@

// LOADED PROTOCOL DEFINITIONS
@@LOADED_PROTOCOLS@@

// OFFLOADER IDS
@@OFFLOADER_UIDS@@

// ZEEK TYPES
typedef bit<8> z_bool;      // boolean      (1 byte)
typedef bit<64> z_int;      // signed int   (8 bytes)
typedef bit<64> z_count;    // unsigned int (8 bytes)

// MERGED HEADER DEFINITIONS     \/ \/ \/

@@HEADER_DEFINITIONS@@

// END MERGED HEADER DEFINITIONS /\ /\ /\

#define ETH_P_RNA 0x6606

#define RNA_P_DEBUG      0
#define RNA_P_ETH_OFFLOADER  1
#define RNA_P_IPV4_OFFLOADER 2
#define RNA_P_IPV6_OFFLOADER 3

// Ethertype (ETH_P_RNA) 0x6606
header rna_h {          // Bytes
    bit<16>  version;    // 1 -> version/hash
    bit<16>  rna_type;   // 1 -> debug (0), eth (1), ip (2), ipv6 (3)
}

// OFFLOADER Header for non-ip based offloaders, for ex: ARP
header eth_offloader_h {
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

// OFFLOADER Header for IPv4 based offloaders, for ex: ICMP, TCP, NTP...
header ipv4_offloader_h {
    bit<16>       next_header; // Or next offloader
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

// OFFLOADER Header for IPv6 based offloader, for ex: ICMP, TCP, NTP...
header ipv6_offloader_h {
    bit<16>       next_header; // Or next offloader
    bit<16>       src_port;
    bit<16>       dst_port;
    ipv6_header_t ipv6_hdr;
}

header_union offloader_h {
    eth_offloader_h eth;
    ipv4_offloader_h ipv4;
    ipv6_offloader_h ipv6;
}

struct metadata {
    bit<32>  nhop_ipv4;
    bit<128> nhop_ipv6;
    bit<32>  pkt_num;
    bit<16>  protocol_l3;
    bit<8>   protocol_l4;
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<16>  offloader_type;
}

// AUTOMATICALLY GENERATED HEADER STRUCT     \/ \/ \/

@@HEADERS_STRUCT@@

// END AUTOMATICALLY GENERATED HEADER STRUCT /\ /\ /\

#endif
