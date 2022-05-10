#ifndef ZPO_PARSER
#define ZPO_PARSER

#include "headers.p4"

parser ParserImpl(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    // Layer 2
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ethertype) {
            ETH_P_IPV4:     parse_ipv4;
            ETH_P_IPV6:     parse_ipv6;
            ETH_P_ARP:      parse_arp;
            default:        accept;
        }
    }

    // Layer 3
    state parse_ipv4 { // TODO: This may need to be adapted for variable-length headers.
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IPPROTO_ICMP: parse_icmp;
            default:      accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.next_header) {
            IPPROTO_ICMPV6: parse_icmpv6;
            default:        accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition select(hdr.arp.proto_type) {
            ETH_P_IPV4: parse_arp_ipv4;
            default:    accept;
        }
    }

    state parse_arp_ipv4 {
        packet.extract(hdr.arp_ipv4);
        transition accept;
    }

    // Layer 4

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }

    state parse_icmpv6 {
        packet.extract(hdr.icmpv6);
        transition accept;
    }

    // state parse_tcp {
    //     packet.extract(hdr.tcp);
    //     transition accept;
    // }

    // state parse_udp {
    //     packet.extract(hdr.udp);
    //     transition accept;
    // }

}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr);
    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
                hdr.ipv4.isValid(),
                { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
                hdr.ipv4.total_len, hdr.ipv4.identification,
                hdr.ipv4.flags, hdr.ipv4.frag_offset, hdr.ipv4.ttl,
                hdr.ipv4.protocol, hdr.ipv4.src_addr, hdr.ipv4.dst_addr },
                hdr.ipv4.hdr_checksum,
                HashAlgorithm.csum16);
    }
}

#endif /* ZPO_PARSER */
