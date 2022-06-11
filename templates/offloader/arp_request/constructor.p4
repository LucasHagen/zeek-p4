hdr.arp_request.setValid();

hdr.arp_request.mac_src = hdr.ethernet.src_addr;
hdr.arp_request.mac_dst = hdr.ethernet.dst_addr;
hdr.arp_request.src_hw_addr = hdr.arp_ipv4.src_hw_addr;
hdr.arp_request.src_proto_addr = hdr.arp_ipv4.src_proto_addr;
hdr.arp_request.target_hw_addr = hdr.arp_ipv4.target_hw_addr;
hdr.arp_request.target_proto_addr = hdr.arp_ipv4.target_proto_addr;

hdr.arp.setInvalid();
hdr.arp_ipv4.setInvalid();
