// Generated for ICMP *echo reply* messages.
header icmp_echo_reply_event_h {
    z_count id;         // id           (8 bytes)
    z_count seq;        // seq          (8 bytes)
    // start 'icmp_info' struct
    z_bool  v6;         // True if it's an ICMPv6 packet.
	z_count itype;      // The ICMP type of the current packet.
	z_count icode;      // The ICMP code of the current packet.
	z_count len;        // The length of the ICMP payload.
	z_count ttl;        // The encapsulating IP header's TTL (IPv4) or Hop Limit (IPv6).
    // Total: 49 bytes
}
