hdr.icmp_echo_request_event.setValid();

hdr.icmp_echo_request_event.id = (z_count) hdr.icmp.id;
hdr.icmp_echo_request_event.seq = (z_count) hdr.icmp.seq;

// True if it's an ICMPv6 packet.
// hdr.icmp_echo_request_event.v6 = (z_bool) 0;

// The ICMP type of the current packet.
hdr.icmp_echo_request_event.itype = (z_count) hdr.icmp.type_;

// The ICMP code of the current packet.
hdr.icmp_echo_request_event.icode = (z_count) hdr.icmp.code;

// The length of the ICMP payload. (total ipv4 length - (ipv4 header + icmp header))
// hdr.icmp_echo_request_event.len = (z_count) hdr.ipv4.total_len - hdr.ipv4.minSizeInBytes() - hdr.icmp.minSizeInBytes();

// The encapsulating IP header's TTL (IPv4) or Hop Limit (IPv6).
// hdr.icmp_echo_request_event.ttl = (z_count) hdr.ipv4.ttl;


#ifdef ZPO_PROTOCOL_IPV4

if(hdr.ipv4.isValid()) {
    hdr.icmp_echo_request_event.v6 = (z_bool) 8w0x00;
    hdr.icmp_echo_request_event.len = (z_count) hdr.ipv4.total_len - hdr.ipv4.minSizeInBytes() - hdr.icmp.minSizeInBytes();
    hdr.icmp_echo_request_event.ttl = (z_count) hdr.ipv4.ttl;

    hdr.ipv4.setInvalid();
}

#ifdef ZPO_PROTOCOL_IPV6
else
#endif
#endif

#ifdef ZPO_PROTOCOL_IPV6

if(hdr.ipv6.isValid()) {
    hdr.icmp_echo_request_event.v6 = (z_bool) 8w0xFF;
    hdr.icmp_echo_request_event.len = (z_count) hdr.ipv6.payload_length - hdr.icmp.minSizeInBytes();
    hdr.icmp_echo_request_event.ttl = (z_count) hdr.ipv6.hop_limit;

    hdr.ipv6.setInvalid();
}

#endif

hdr.icmp.setInvalid();
