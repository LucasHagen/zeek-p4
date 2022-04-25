hdr.arp_reply_event.setValid();

hdr.arp_reply_event.mac_src = hdr.ethernet.src_addr;
hdr.arp_reply_event.mac_dst = hdr.ethernet.dst_addr;
hdr.arp_reply_event.src_hw_addr = hdr.arp_ipv4.src_hw_addr;
hdr.arp_reply_event.src_proto_addr = hdr.arp_ipv4.src_proto_addr;
hdr.arp_reply_event.target_hw_addr = hdr.arp_ipv4.target_hw_addr;
hdr.arp_reply_event.target_proto_addr = hdr.arp_ipv4.target_proto_addr;

hdr.arp.setInvalid();
hdr.arp_ipv4.setInvalid();
