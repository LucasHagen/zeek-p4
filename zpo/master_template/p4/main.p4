#include <v1model.p4>

#include "parser.p4"

typedef bit<9> egress_spec_t;

const bit<32> MIRROR_SESSION = 0x01;
const bit<32> INSTANCE_TYPE_NORMAL = 0;
const bit<32> INSTANCE_TYPE_CLONE = 1;

// TODO: Credits: Some actions and tables were based on https://github.com/p4lang/p4app.

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    // Update destination MAC address based on the next-hop IP (akin to an ARP lookup).
    action set_dmac(bit<48> dmac) {
        hdr.ethernet.dst_addr = dmac;
    }

#ifdef RNA_PROTOCOL_IPV4

    // IPv4 Routing

    // Update next hop, set egress port, and decrement TTL.
    action set_nhop(bit<32> nhop_ipv4, bit<9> port) {
        meta.nhop_ipv4 = nhop_ipv4;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        actions = {
            set_nhop;
            NoAction;
        }
        key = {
            hdr.ipv4.dst_addr: lpm;
        }
        size = 1024;
        default_action = NoAction();
    }

    // IPv4 Forwarding

    table forward {
        actions = {
            set_dmac;
            NoAction;
        }
        key = {
            meta.nhop_ipv4: exact;
        }
        size = 512;
        default_action = NoAction();
    }

#endif

#ifdef RNA_PROTOCOL_IPV6

    // IPv6 Routing

    // Update next hop, set egress port, and decrement TTL.
    action set_nhop_v6(bit<128> nhop_ipv6, bit<9> port) {
        meta.nhop_ipv6 = nhop_ipv6;
        standard_metadata.egress_spec = port;
        hdr.ipv6.hop_limit = hdr.ipv6.hop_limit - 1;
    }

    table ipv6_lpm {
        actions = {
            set_nhop_v6;
            NoAction;
        }
        key = {
            hdr.ipv6.dst_addr: lpm;
        }
        size = 1024;
        default_action = NoAction();
    }

    // IPv6 Forwarding

    table forward_v6 {
        actions = {
            set_dmac;
            NoAction;
        }
        key = {
            meta.nhop_ipv6: exact;
        }
        size = 512;
        default_action = NoAction();
    }

#endif

    // RNA Data Plane Logic
    apply {
        if (standard_metadata.instance_type == INSTANCE_TYPE_NORMAL) {
            meta.event_type = RNA_NO_EVENT_UID;

            clone3(CloneType.I2E, MIRROR_SESSION, { meta });

@@PROTOCOL_INGRESS_PROCESSORS@@

@@EVENT_IDENTIFICATION@@
        }
    }

}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    // Before emitting the frame, set the its source MAC address to the egress port's.
    action rewrite_mac(bit<48> smac) {
        hdr.ethernet.src_addr = smac;
    }

    table send_frame {
        actions = {
            rewrite_mac;
            NoAction;
        }
        key = {
            standard_metadata.egress_port: exact;
        }
        size = 256;
        default_action = NoAction();
    }

    action construct_eth_event_header() {
        hdr.ethernet.ethertype = ETH_P_RNA;

        hdr.rna.setValid();
        hdr.rna.version  = RNA_VERSION;
        hdr.rna.rna_type = RNA_P_ETH_EVENT;

        hdr.event.eth_event.setValid();
        hdr.event.eth_event.next_header = meta.event_type;
        hdr.event.eth_event.protocol_l3 = meta.protocol_l3;
    }

    #ifdef RNA_PROTOCOL_IPV4
    action construct_ipv4_event_header() {
        hdr.ethernet.ethertype = ETH_P_RNA;

        hdr.rna.setValid();
        hdr.rna.version  = RNA_VERSION;
        hdr.rna.rna_type = RNA_P_IPV4_EVENT;

        hdr.event.ipv4_event.setValid();
        hdr.event.ipv4_event.src_port = meta.src_port;
        hdr.event.ipv4_event.dst_port = meta.dst_port;
        hdr.event.ipv4_event.next_header = meta.event_type;

        // Clone IPv4 header
        hdr.event.ipv4_event.ipv4_hdr.version =        hdr.ipv4.version;
        hdr.event.ipv4_event.ipv4_hdr.ihl =            hdr.ipv4.ihl;
        hdr.event.ipv4_event.ipv4_hdr.diffserv =       hdr.ipv4.diffserv;
        hdr.event.ipv4_event.ipv4_hdr.total_len =      hdr.ipv4.total_len;
        hdr.event.ipv4_event.ipv4_hdr.identification = hdr.ipv4.identification;
        hdr.event.ipv4_event.ipv4_hdr.flags =          hdr.ipv4.flags;
        hdr.event.ipv4_event.ipv4_hdr.frag_offset =    hdr.ipv4.frag_offset;
        hdr.event.ipv4_event.ipv4_hdr.ttl =            hdr.ipv4.ttl;
        hdr.event.ipv4_event.ipv4_hdr.protocol =       hdr.ipv4.protocol;
        hdr.event.ipv4_event.ipv4_hdr.hdr_checksum =   hdr.ipv4.hdr_checksum;
        hdr.event.ipv4_event.ipv4_hdr.src_addr =       hdr.ipv4.src_addr;
        hdr.event.ipv4_event.ipv4_hdr.dst_addr =       hdr.ipv4.dst_addr;
    }
    #endif

    #ifdef RNA_PROTOCOL_IPV6
    action construct_ipv6_event_header() {
        hdr.ethernet.ethertype = ETH_P_RNA;

        hdr.rna.setValid();
        hdr.rna.version  = RNA_VERSION;
        hdr.rna.rna_type = RNA_P_IPV6_EVENT;

        hdr.event.ipv6_event.setValid();

        hdr.event.ipv6_event.next_header = meta.event_type;
        hdr.event.ipv6_event.src_port = meta.src_port;
        hdr.event.ipv6_event.dst_port = meta.dst_port;

        // Clone IPv6 header
        hdr.event.ipv6_event.ipv6_hdr.version        = hdr.ipv6.version;
        hdr.event.ipv6_event.ipv6_hdr.traffic_class  = hdr.ipv6.traffic_class;
        hdr.event.ipv6_event.ipv6_hdr.flow_label     = hdr.ipv6.flow_label;
        hdr.event.ipv6_event.ipv6_hdr.payload_length = hdr.ipv6.payload_length;
        hdr.event.ipv6_event.ipv6_hdr.next_header    = hdr.ipv6.next_header;
        hdr.event.ipv6_event.ipv6_hdr.hop_limit      = hdr.ipv6.hop_limit;
        hdr.event.ipv6_event.ipv6_hdr.src_addr       = hdr.ipv6.src_addr;
        hdr.event.ipv6_event.ipv6_hdr.dst_addr       = hdr.ipv6.dst_addr;
    }
    #endif

    apply {
        // NORMAL PACKETS
        if (standard_metadata.instance_type == INSTANCE_TYPE_NORMAL) {
            if (hdr.ethernet.isValid()) {
                send_frame.apply();
            }

        // EVENT PACKETS
        } else if (standard_metadata.instance_type == INSTANCE_TYPE_CLONE) {
            if(meta.event_type == RNA_NO_EVENT_UID) {
                mark_to_drop(standard_metadata);
            } else {
                // IPV4-BASED EVENT HEADER
                #ifdef RNA_PROTOCOL_IPV4
                if(meta.protocol_l3 == ETH_P_IPV4) {
                    construct_ipv4_event_header();
                } else
                #endif

                // IPV6-BASED EVENTS
                #ifdef RNA_PROTOCOL_IPV6
                if(meta.protocol_l3 == ETH_P_IPV6) {
                    construct_ipv6_event_header();
                } else
                #endif

                // ETHERNET-BASED EVENTS
                {
                    construct_eth_event_header();
                }

                // CONSTRUCT EVENT SPECIFIC HEADER
@@EVENT_CONSTRUCTORS@@

            }
        }
    }

}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
