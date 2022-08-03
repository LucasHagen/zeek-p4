// Generated for ICMP *echo reply* and *request* messages.
header icmp_echo_message_h {
    bit<16> id;         // id           (8 bytes)
    bit<16> seq;        // seq          (8 bytes)
    // start 'icmp_info' struct
	bit<8>  itype;      // The ICMP type of the current packet.
	bit<8>  icode;      // The ICMP code of the current packet.
	bit<16> len;        // The length of the ICMP payload.
	bit<8>  ttl;        // The encapsulating IP header's TTL (IPv4) or Hop Limit (IPv6).
}
