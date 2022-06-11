hdr.arp_reply.setValid();

hdr.arp_reply.mac_src = hdr.ethernet.src_addr;
hdr.arp_reply.mac_dst = hdr.ethernet.dst_addr;
hdr.arp_reply.src_hw_addr = hdr.arp_ipv4.src_hw_addr;
hdr.arp_reply.src_proto_addr = hdr.arp_ipv4.src_proto_addr;
hdr.arp_reply.target_hw_addr = hdr.arp_ipv4.target_hw_addr;
hdr.arp_reply.target_proto_addr = hdr.arp_ipv4.target_proto_addr;

hdr.arp.setInvalid();
hdr.arp_ipv4.setInvalid();
