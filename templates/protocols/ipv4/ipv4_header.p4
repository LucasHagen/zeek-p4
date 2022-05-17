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
