#ifndef RNA_PARSER
#define RNA_PARSER

#include "headers.p4"

parser ParserImpl(packet_in packet,
                  out headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

// AUTOMATICALLY GENERATED PARSING STATES      \/ \/ \/

@@PARSING_STATES@@

// END AUTOMATICALLY GENERATED PARSING STATES  /\ /\ /\

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

#endif /* RNA_PARSER */
