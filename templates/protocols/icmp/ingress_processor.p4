meta.src_port = (bit<16>) hdr.icmp.type_;

// ICMP COUNTERPART START
#ifdef RNA_PROTOCOL_IPV4
if(hdr.ipv4.isValid()) {
    if (hdr.icmp.type_ == ICMP_ECHO) {
        meta.dst_port = (bit<16>) ICMP_ECHOREPLY;
    } else if (hdr.icmp.type_ == ICMP_ECHOREPLY) {
        meta.dst_port = (bit<16>) ICMP_ECHO;
    } else if (hdr.icmp.type_ == ICMP_TSTAMP) {
        meta.dst_port = (bit<16>) ICMP_TSTAMPREPLY;
    } else if (hdr.icmp.type_ == ICMP_TSTAMPREPLY) {
        meta.dst_port = (bit<16>) ICMP_TSTAMP;
    } else if (hdr.icmp.type_ == ICMP_IREQ) {
        meta.dst_port = (bit<16>) ICMP_IREQREPLY;
    } else if (hdr.icmp.type_ == ICMP_IREQREPLY) {
        meta.dst_port = (bit<16>) ICMP_IREQ;
    } else if (hdr.icmp.type_ == ICMP_ROUTERSOLICIT) {
        meta.dst_port = (bit<16>) ICMP_ROUTERADVERT;
    } else if (hdr.icmp.type_ == ICMP_ROUTERADVERT) {
        meta.dst_port = (bit<16>) ICMP_ROUTERSOLICIT;
    } else if (hdr.icmp.type_ == ICMP_MASKREQ) {
        meta.dst_port = (bit<16>) ICMP_MASKREPLY;
    } else if (hdr.icmp.type_ == ICMP_MASKREPLY) {
        meta.dst_port = (bit<16>) ICMP_MASKREQ;
    } else {
        meta.dst_port = (bit<16>) hdr.icmp.code;
    }
}
#endif

#ifdef RNA_PROTOCOL_IPV6
if(hdr.ipv6.isValid()) {
    // TODO: set ipv6 counterpart
}
#endif

// ICMP COUNTERPART END
