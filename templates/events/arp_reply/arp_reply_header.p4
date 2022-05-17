// Generated for ARP requests or replies (ONLY IPV4).
header arp_reply_event_h {
    mac_addr_t  mac_src;
    mac_addr_t  mac_dst;
    mac_addr_t  src_hw_addr;
    ipv4_addr_t src_proto_addr;
    mac_addr_t  target_hw_addr;
    ipv4_addr_t target_proto_addr;
}
