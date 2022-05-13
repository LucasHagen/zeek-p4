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
