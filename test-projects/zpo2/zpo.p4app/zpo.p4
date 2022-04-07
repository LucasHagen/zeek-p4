#include <v1model.p4>

#include "icmp_codes.p4"
#include "parser.p4"

typedef bit<9> egress_spec_t;

const bit<32> MIRROR_SESSION = 0x01;
const bit<32> INSTANCE_TYPE_NORMAL = 0;
const bit<32> INSTANCE_TYPE_CLONE = 1; // TODO: Add other instance types.

// const bit<16> ICMP_ECHO_16 = 8;    /* Echo Request			    */

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

    // ZPO Data Plane Logic
    apply {
        if (standard_metadata.instance_type == INSTANCE_TYPE_NORMAL) {
            meta.protocol_l3 = hdr.ethernet.ethertype;
            meta.event_type = TYPE_NO_EVENT;

            if (hdr.ipv4.isValid()) {
                meta.protocol_l4 = hdr.ipv4.protocol;

                // Only working with icmp events for now
                if (hdr.icmp.isValid()) {
                    meta.src_port = (bit<16>) hdr.icmp.type_;

                    // ICMP COUNTERPART START
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

                    // ICMP COUNTERPART END

                    if (hdr.icmp.type_ == ICMP_ECHOREPLY) {
                        meta.event_type = TYPE_ICMP_ECHO_REPLY_EVENT;

                    } else if ( hdr.icmp.type_ == ICMP_ECHO) {
                        meta.event_type = TYPE_ICMP_ECHO_REQ_EVENT;
                    }
                }
                // TODO: Add the edge cases: "something else we don't support yet."

                // Perform usual routing and forwarding.
                ipv4_lpm.apply();
                forward.apply();

                // Update state.
                pkt_counter.read(meta.pkt_num, 0);      // Packet Counter
                meta.pkt_num = meta.pkt_num + 1;
                pkt_counter.write(0, meta.pkt_num);

                // Generate an event packet.
                clone3(CloneType.I2E, MIRROR_SESSION, { meta });
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

    action construct_icmp_echo_request_event_t() {
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
    }

    action construct_icmp_echo_reply_event_t() {
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
    }

    apply {
        // Emit normal packets.
        if (standard_metadata.instance_type == INSTANCE_TYPE_NORMAL) {
            if (hdr.ipv4.isValid()) { // TODO: Is this condition necessary?
                send_frame.apply();
            }
        } else if (standard_metadata.instance_type == INSTANCE_TYPE_CLONE) {
            if(meta.event_type == TYPE_NO_EVENT) {
                mark_to_drop(standard_metadata);
            } else if(meta.protocol_l3 == ETH_P_IPV4) {
                // hdr.ethernet.len
                hdr.event.ip_event.setValid();
                hdr.event.ip_event.pkt_num = meta.pkt_num;
                hdr.event.ip_event.src_port = meta.src_port;
                hdr.event.ip_event.dst_port = meta.dst_port;
                hdr.event.ip_event.type = meta.event_type;
                // hdr.event.ip_event.ipv4_header = (bit<160>) hdr.ipv4;
                hdr.ethernet.ethertype = ETH_P_EVENT_IP;

                if (meta.event_type == TYPE_ICMP_ECHO_REQ_EVENT) {
                    construct_icmp_echo_request_event_t();
                } else if(meta.event_type == TYPE_ICMP_ECHO_REPLY_EVENT) {
                    construct_icmp_echo_reply_event_t();
                }
            } else if(meta.protocol_l3 == ETH_P_IPV6) {
                // TODO, not yet supported.
            } else {
                hdr.event.eth_event.setValid();
                hdr.event.eth_event.pkt_num = meta.pkt_num;
                hdr.event.eth_event.protocol_l3 = meta.protocol_l3;
                hdr.event.eth_event.type = meta.event_type;
                hdr.ethernet.ethertype = ETH_P_EVENT;

                // Set other headers invalid and construct event
            }
        }
    }

}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
