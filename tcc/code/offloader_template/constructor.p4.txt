hdr.icmp_echo_message.setValid();

hdr.icmp_echo_message.id  = hdr.icmp_echo.id;
hdr.icmp_echo_message.seq = hdr.icmp_echo.seq;

// The ICMP type of the current packet.
hdr.icmp_echo_message.itype = hdr.icmp.type_;

// The ICMP code of the current packet.
hdr.icmp_echo_message.icode = hdr.icmp.code;

// The length of the ICMP payload. (total ipv4 length - (ipv4 header + icmp header))
hdr.icmp_echo_message.len = hdr.ipv4.total_len - hdr.ipv4.minSizeInBytes() - hdr.icmp.minSizeInBytes() - hdr.icmp_echo.minSizeInBytes();

// The encapsulating IP header's TTL (IPv4) or Hop Limit (IPv6).
hdr.icmp_echo_message.ttl = hdr.ipv4.ttl;

hdr.icmp_echo.setInvalid();
hdr.icmp.setInvalid();
hdr.ipv4.setInvalid();
