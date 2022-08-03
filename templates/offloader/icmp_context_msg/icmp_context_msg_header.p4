header icmp_context_msg_h {
	bit<8>          itype;      // The ICMP type of the current packet.
	bit<8>          icode;      // The ICMP code of the current packet.
    ipv4_context_t  ipv4_context;
}
