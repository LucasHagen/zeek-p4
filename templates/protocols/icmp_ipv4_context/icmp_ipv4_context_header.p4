struct ipv4_context_t {
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

header icmp_ipv4_context_h {
    bit<16>         _ignored1;
    bit<16>         _ignored2;
    ipv4_context_t  ipv4_context;
}
