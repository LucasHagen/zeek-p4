header icmp_h {
    bit<8>    type_;
    bit<8>    code;
    bit<16>   hdr_checksum;
    bit<16>   id;
    bit<16>   seq;
}
