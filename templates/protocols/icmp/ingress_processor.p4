meta.src_port = (bit<16>) hdr.icmp.type_;

// ICMP COUNTERPART START
if(hdr.ipv4.isValid()) {
    if (hdr.icmp.type_ == ICMP_ECHO) {
        meta.dst_port = (bit<16>) ICMP_ECHOREPLY;
    } else if (hdr.icmp.type_ == ICMP_ECHOREPLY) {
        meta.dst_port = (bit<16>) ICMP_ECHO;
    } else if (hdr.icmp.type_ == ICMP_TIMESTAMP) {
        meta.dst_port = (bit<16>) ICMP_TIMESTAMPREPLY;
    } else if (hdr.icmp.type_ == ICMP_TIMESTAMPREPLY) {
        meta.dst_port = (bit<16>) ICMP_TIMESTAMP;
    } else if (hdr.icmp.type_ == ICMP_INFO_REQUEST) {
        meta.dst_port = (bit<16>) ICMP_INFO_REPLY;
    } else if (hdr.icmp.type_ == ICMP_INFO_REPLY) {
        meta.dst_port = (bit<16>) ICMP_INFO_REQUEST;
    } else if (hdr.icmp.type_ == ICMP_ROUTER_SOLICIT) {
        meta.dst_port = (bit<16>) ICMP_ROUTER_ADVERT;
    } else if (hdr.icmp.type_ == ICMP_ROUTER_ADVERT) {
        meta.dst_port = (bit<16>) ICMP_ROUTER_SOLICIT;
    } else if (hdr.icmp.type_ == ICMP_ADDR_MASK_REQ) {
        meta.dst_port = (bit<16>) ICMP_ADDR_MASK_REPLY;
    } else if (hdr.icmp.type_ == ICMP_ADDR_MASK_REPLY) {
        meta.dst_port = (bit<16>) ICMP_ADDR_MASK_REQ;
    } else {
        meta.dst_port = (bit<16>) hdr.icmp.code;
    }
}

// ICMP COUNTERPART END
