meta.protocol_l4 = hdr.ipv6.next_header;

// Perform usual routing and forwarding.
ipv6_lpm.apply();
forward_v6.apply();
