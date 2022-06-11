hdr.udp_req_or_rep.setValid();

hdr.udp_req_or_rep._ignored = 8w0xFF;

hdr.udp.setInvalid();
hdr.ipv4.setInvalid();
