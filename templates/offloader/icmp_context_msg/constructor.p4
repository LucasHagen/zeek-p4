hdr.icmp_context_msg.setValid();

// The ICMP type of the current packet.
hdr.icmp_context_msg.itype = hdr.icmp.type_;

// The ICMP code of the current packet.
hdr.icmp_context_msg.icode = hdr.icmp.code;

hdr.icmp_context_msg.ipv4_context = hdr.icmp_ipv4_context.ipv4_context;

hdr.icmp_ipv4_context.setInvalid();
hdr.icmp.setInvalid();
hdr.ipv4.setInvalid();
