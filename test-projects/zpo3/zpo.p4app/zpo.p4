#include <v1model.p4>

#include "icmp_codes.p4"
#include "parser.p4"

typedef bit<9> egress_spec_t;

const bit<32> MIRROR_SESSION = 0x01;
const bit<32> INSTANCE_TYPE_NORMAL = 0;
const bit<32> INSTANCE_TYPE_CLONE = 1;

// TODO: Credits: Some actions and tables were based on https://github.com/p4lang/p4app.

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    register<bit<32>>(1) pkt_counter;

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

    // IPv4 Forwarding

    // Update destination MAC address based on the next-hop IPv4 (akin to an ARP lookup).
    action set_dmac(bit<48> dmac) {
        hdr.ethernet.dst_addr = dmac;
    }

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

    // ZPO Data Plane Logic
    apply {
        if (standard_metadata.instance_type == INSTANCE_TYPE_NORMAL) {
            meta.protocol_l3 = hdr.ethernet.ethertype;
            meta.event_type = TYPE_NO_EVENT;

            pkt_counter.read(meta.pkt_num, 0);
            meta.pkt_num = meta.pkt_num + 1;
            pkt_counter.write(0, meta.pkt_num);

            clone3(CloneType.I2E, MIRROR_SESSION, { meta });

            if (hdr.ipv4.isValid()) {
                meta.protocol_l4 = hdr.ipv4.protocol;

                // Perform usual routing and forwarding.
                ipv4_lpm.apply();
                forward.apply();
            } else if(hdr.ipv6.isValid()) {
                meta.protocol_l4 = hdr.ipv6.next_header;

                // Perform usual routing and forwarding.
                ipv6_lpm.apply();
                forward_v6.apply();
            }

            if(hdr.icmp.isValid()) {
                meta.src_port = (bit<16>) hdr.icmp.type_;

                // ICMP COUNTERPART START
                #ifdef ZPO_PROTOCOL_IPV4
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

                #ifdef ZPO_PROTOCOL_IPV6
                if(hdr.ipv6.isValid()) {
                    // TODO: set ipv6 counterpart
                }
                #endif

                // ICMP COUNTERPART END

                if (hdr.icmp.type_ == ICMP_ECHOREPLY) {
                    meta.event_type = TYPE_ICMP_ECHO_REPLY_EVENT;

                } else if ( hdr.icmp.type_ == ICMP_ECHO) {
                    meta.event_type = TYPE_ICMP_ECHO_REQ_EVENT;
                }

            } else if(hdr.arp_ipv4.isValid()) {
                if(hdr.arp.opcode == 1) {        // ARP REQ
                    meta.event_type = TYPE_ARP_REQUEST_EVENT;
                } else if(hdr.arp.opcode == 2) { // ARP REPLY
                    meta.event_type = TYPE_ARP_REPLY_EVENT;
                }
            }
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
        hdr.ethernet.ethertype = ETH_P_EVENT;

        hdr.event.eth_event.setValid();

        hdr.event.eth_event.pkt_num = meta.pkt_num;
        hdr.event.eth_event.protocol_l3 = meta.protocol_l3;
        hdr.event.eth_event.type = meta.event_type;
    }

    action construct_ipv4_event_header() {
        hdr.ethernet.ethertype = ETH_P_EVENT_IP;

        hdr.event.ipv4_event.setValid();

        hdr.event.ipv4_event.pkt_num = meta.pkt_num;
        hdr.event.ipv4_event.src_port = meta.src_port;
        hdr.event.ipv4_event.dst_port = meta.dst_port;
        hdr.event.ipv4_event.type = meta.event_type;

        // Clone IPv4 header
        hdr.event.ipv4_event.version =        hdr.ipv4.version;
        hdr.event.ipv4_event.ihl =            hdr.ipv4.ihl;
        hdr.event.ipv4_event.diffserv =       hdr.ipv4.diffserv;
        hdr.event.ipv4_event.total_len =      hdr.ipv4.total_len;
        hdr.event.ipv4_event.identification = hdr.ipv4.identification;
        hdr.event.ipv4_event.flags =          hdr.ipv4.flags;
        hdr.event.ipv4_event.frag_offset =    hdr.ipv4.frag_offset;
        hdr.event.ipv4_event.ttl =            hdr.ipv4.ttl;
        hdr.event.ipv4_event.protocol =       hdr.ipv4.protocol;
        hdr.event.ipv4_event.hdr_checksum =   hdr.ipv4.hdr_checksum;
        hdr.event.ipv4_event.src_addr =       hdr.ipv4.src_addr;
        hdr.event.ipv4_event.dst_addr =       hdr.ipv4.dst_addr;
    }

    action construct_ipv6_event_header() {
        hdr.ethernet.ethertype = ETH_P_EVENT_IP;

        hdr.event.ipv6_event.setValid();

        hdr.event.ipv6_event.pkt_num = meta.pkt_num;
        hdr.event.ipv6_event.src_port = meta.src_port;
        hdr.event.ipv6_event.dst_port = meta.dst_port;
        hdr.event.ipv6_event.type = meta.event_type;

        // Clone IPv6 header
        hdr.event.ipv6_event.version        = hdr.ipv6.version;
        hdr.event.ipv6_event.traffic_class  = hdr.ipv6.traffic_class;
        hdr.event.ipv6_event.flow_label     = hdr.ipv6.flow_label;
        hdr.event.ipv6_event.payload_length = hdr.ipv6.payload_length;
        hdr.event.ipv6_event.next_header    = hdr.ipv6.next_header;
        hdr.event.ipv6_event.hop_limit      = hdr.ipv6.hop_limit;
        hdr.event.ipv6_event.src_addr       = hdr.ipv6.src_addr;
        hdr.event.ipv6_event.dst_addr       = hdr.ipv6.dst_addr;
    }

    action construct_icmp_echo_request_event() {
        hdr.icmp_echo_request_event.setValid();

        hdr.icmp_echo_request_event.id = (z_count) hdr.icmp.id;
        hdr.icmp_echo_request_event.seq = (z_count) hdr.icmp.seq;

        // True if it's an ICMPv6 packet.
        hdr.icmp_echo_request_event.info.v6 = (z_bool) 0;

        // The ICMP type of the current packet.
        hdr.icmp_echo_request_event.info.itype = (z_count) hdr.icmp.type_;

        // The ICMP code of the current packet.
        hdr.icmp_echo_request_event.info.icode = (z_count) hdr.icmp.code;

        // The length of the ICMP payload. (total ipv4 length - (ipv4 header + icmp header))
        hdr.icmp_echo_request_event.info.len = (z_count) hdr.ipv4.total_len - hdr.ipv4.minSizeInBytes() - hdr.icmp.minSizeInBytes();

        // The encapsulating IP header's TTL (IPv4) or Hop Limit (IPv6).
        hdr.icmp_echo_request_event.info.ttl = (z_count) hdr.ipv4.ttl;

        // hdr.ipv4.setInvalid();
        hdr.icmp.setInvalid();
        hdr.ipv4.setInvalid();
        hdr.ipv6.setInvalid();
    }

    action construct_icmp_echo_reply_event() {
        hdr.icmp_echo_reply_event.setValid();

        hdr.icmp_echo_reply_event.id = (z_count) hdr.icmp.id;
        hdr.icmp_echo_reply_event.seq = (z_count) hdr.icmp.seq;

        // True if it's an ICMPv6 packet.
        hdr.icmp_echo_reply_event.info.v6 = (z_bool) 0;

        // The ICMP type of the current packet.
        hdr.icmp_echo_reply_event.info.itype = (z_count) hdr.icmp.type_;

        // The ICMP code of the current packet.
        hdr.icmp_echo_reply_event.info.icode = (z_count) hdr.icmp.code;

        // The length of the ICMP payload. (total ipv4 length - (ipv4 header + icmp header))
        hdr.icmp_echo_reply_event.info.len = (z_count) hdr.ipv4.total_len - hdr.ipv4.minSizeInBytes() - hdr.icmp.minSizeInBytes();

        // The encapsulating IP header's TTL (IPv4) or Hop Limit (IPv6).
        hdr.icmp_echo_reply_event.info.ttl = (z_count) hdr.ipv4.ttl;

        // hdr.ipv4.setInvalid();
        hdr.icmp.setInvalid();
        hdr.ipv4.setInvalid();
        hdr.ipv6.setInvalid();
    }

    action construct_arp_req_or_reply_event () {
        hdr.arp_req_or_reply_event.setValid();

        hdr.arp_req_or_reply_event.mac_src = hdr.ethernet.src_addr;
        hdr.arp_req_or_reply_event.mac_dst = hdr.ethernet.dst_addr;
        hdr.arp_req_or_reply_event.src_hw_addr = hdr.arp_ipv4.src_hw_addr;
        hdr.arp_req_or_reply_event.src_proto_addr = hdr.arp_ipv4.src_proto_addr;
        hdr.arp_req_or_reply_event.target_hw_addr = hdr.arp_ipv4.target_hw_addr;
        hdr.arp_req_or_reply_event.target_proto_addr = hdr.arp_ipv4.target_proto_addr;

        hdr.arp.setInvalid();
        hdr.arp_ipv4.setInvalid();
    }

    apply {
        // NORMAL PACKETS
        if (standard_metadata.instance_type == INSTANCE_TYPE_NORMAL) {
            if (hdr.ethernet.isValid()) {
                send_frame.apply();
            }

        // EVENT PACKETS
        } else if (standard_metadata.instance_type == INSTANCE_TYPE_CLONE) {
            if(meta.event_type == TYPE_NO_EVENT) {
                mark_to_drop(standard_metadata);
            } else {
                // IPV4-BASED EVENT HEADER
                #ifdef ZPO_PROTOCOL_IPV4
                if(meta.protocol_l3 == ETH_P_IPV4) {
                    construct_ipv4_event_header();
                } else
                #endif

                // IPV6-BASED EVENTS
                #ifdef ZPO_PROTOCOL_IPV6
                if(meta.protocol_l3 == ETH_P_IPV6) {
                    construct_ipv6_event_header();
                } else
                #endif

                // ETHERNET-BASED EVENTS
                {
                    construct_eth_event_header();
                }

                // CONSTRUCT EVENT SPECIFIC HEADER
                if (meta.event_type == TYPE_ICMP_ECHO_REQ_EVENT) {
                    z_bool is_ipv6 = 8w0x00;
                    if(hdr.ipv6.isValid()) {
                        is_ipv6 = 8w0xFF;
                    }

                    construct_icmp_echo_request_event();

                    hdr.icmp_echo_reply_event.info.v6 = is_ipv6;
                } else if(meta.event_type == TYPE_ICMP_ECHO_REPLY_EVENT) {
                    z_bool is_ipv6 = 8w0x00;
                    if(hdr.ipv6.isValid()) {
                        is_ipv6 = 8w0xFF;
                    }

                    construct_icmp_echo_reply_event();

                    hdr.icmp_echo_reply_event.info.v6 = is_ipv6;
                } else if(meta.event_type == TYPE_ARP_REPLY_EVENT
                            || meta.event_type == TYPE_ARP_REQUEST_EVENT) {
                    construct_arp_req_or_reply_event();
                }

            }
        }
    }

}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
