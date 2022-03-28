#include <v1model.p4>

#include "icmp_codes.p4"
#include "parser.p4"

typedef bit<9>   egress_spec_t;

const bit<32> MIRROR_SESSION = 0x01;
const bit<32> INSTANCE_TYPE_NORMAL = 0;
const bit<32> INSTANCE_TYPE_CLONE = 1; // TODO: Add other instance types.

// TODO: Credits: Some actions and tables were based on https://github.com/p4lang/p4app.

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    register<bit<32>>(1) pkt_counter;

    // IPv4 Routing

    // Update next hop, set egress port, and decrement TTL.
    action set_nhop(bit<32> nhop_ipv4, bit<9> port) {
        meta.nhop_ipv4 = nhop_ipv4;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl + 8w255;
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
            if (hdr.ipv4.isValid()) {

                meta.src_addr = hdr.ipv4.src_addr;
                meta.dst_addr = hdr.ipv4.dst_addr;

                // Only working with icmp events for now
                if (hdr.icmp.isValid()) {
                    meta.protocol = (bit<16>) TYPE_ICMP;
                    meta.src_port = hdr.icmp.type_;
                    icmp_counterpart(hdr.icmp.type_, meta);

                    switch (hdr.icmp.type_) {
                        ICMP_ECHOREPLY: {
                            meta.event_type = TYPE_ICMP_ECHO_REPLY_EVENT;
                        }
                        ICMP_ECHO: {
                            meta.event_type = TYPE_ICMP_ECHO_REQ_EVENT;
                        }
                        default: {
                            meta.event_type = 0;
                        }
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

    apply {

        // Emit normal packets.
        if (standard_metadata.instance_type == INSTANCE_TYPE_NORMAL) {
            if (hdr.ipv4.isValid()) { // TODO: Is this condition necessary?
                send_frame.apply();
            }
        }

        // Fill in the event header fields.
        if (standard_metadata.instance_type == INSTANCE_TYPE_CLONE) {
            hdr.event.setValid();
            hdr.event.pkt_num = meta.pkt_num;
            hdr.event.protocol = meta.protocol;
            hdr.event.src_addr = meta.src_addr;
            hdr.event.dst_addr = meta.dst_addr;
            hdr.event.src_port = meta.src_port;
            hdr.event.dst_port = meta.dst_port;
            hdr.ethernet.ethertype = TYPE_EVENT;
        }

        switch (meta.event_Type) {
            TYPE_ICMP_ECHO_REQ_EVENT: {
                construct_icmp_echo_request_event_t(hdr, meta);
            }
            TYPE_ICMP_ECHO_REPLY_EVENT: {
                construct_icmp_echo_reply_event_t(hdr, meta);
            }
            default: {
                mark_to_drop(standard_metadata);
            }
        }

    }

}

control construct_icmp_echo_request_event_t(inout headers hdr, inout metadata meta) {
    apply {
        hdr.icmp_echo_request_event_t.id = hdr.icmp.id;
        hdr.icmp_echo_request_event_t.seq = hdr.icmp.seq;

        // True if it's an ICMPv6 packet.
        hdr.icmp_echo_request_event_t.info.v6 = false;

        // The ICMP type of the current packet.
        hdr.icmp_echo_request_event_t.info.itype = hdr.icmp.type_;

        // The ICMP code of the current packet.
        hdr.icmp_echo_request_event_t.info.icode = hdr.icmp.code;

        // The length of the ICMP payload. (total ipv4 length - (ipv4 header + icmp header))
        hdr.icmp_echo_request_event_t.info.len = hdr.ipv4.total_len - 28;

        // The encapsulating IP header's TTL (IPv4) or Hop Limit (IPv6).
        hdr.icmp_echo_request_event_t.info.ttl = hdr.ipv4.ttl;

        hdr.icmp_echo_request_event_t.setValid();

        hdr.ipv4.setInvalid();
        hdr.icmp.setInvalid();
    }
}

control construct_icmp_echo_reply_event_t(in metadata meta, inout headers hdr) {
    apply {
        hdr.icmp_echo_reply_event_t.id = hdr.icmp.id;
        hdr.icmp_echo_reply_event_t.seq = hdr.icmp.seq;

        // True if it's an ICMPv6 packet.
        hdr.icmp_echo_reply_event_t.info.v6 = false;

        // The ICMP type of the current packet.
        hdr.icmp_echo_reply_event_t.info.itype = hdr.icmp.type_;

        // The ICMP code of the current packet.
        hdr.icmp_echo_reply_event_t.info.icode = hdr.icmp.code;

        // The length of the ICMP payload. (total ipv4 length - (ipv4 header + icmp header))
        hdr.icmp_echo_reply_event_t.info.len = hdr.ipv4.total_len - 28;

        // The encapsulating IP header's TTL (IPv4) or Hop Limit (IPv6).
        hdr.icmp_echo_reply_event_t.info.ttl = hdr.ipv4.ttl;

        hdr.icmp_echo_reply_event_t.setValid();

        hdr.ipv4.setInvalid();
        hdr.icmp.setInvalid();
    }
}

control icmp_counterpart(in icmp_t icmp, inout metadata meta) {
    apply {

        switch ( icmp.type_ ) {
            ICMP_ECHO: {
                meta.dst_port = ICMP_ECHOREPLY;
            }
            ICMP_ECHOREPLY: {
                meta.dst_port = ICMP_ECHO;
            }
            ICMP_TSTAMP: {
                meta.dst_port = ICMP_TSTAMPREPLY;
            }
            ICMP_TSTAMPREPLY: {
                meta.dst_port = ICMP_TSTAMP;
            }
            ICMP_IREQ: {
                meta.dst_port = ICMP_IREQREPLY;
            }
            ICMP_IREQREPLY: {
                meta.dst_port = ICMP_IREQ;
            }
            ICMP_ROUTERSOLICIT: {
                meta.dst_port = ICMP_ROUTERADVERT;
            }
            ICMP_ROUTERADVERT: {
                meta.dst_port = ICMP_ROUTERSOLICIT;
            }
            ICMP_MASKREQ: {
                meta.dst_port = ICMP_MASKREPLY;
            }
            ICMP_MASKREPLY: {
                meta.dst_port = ICMP_MASKREQ;
            }
            default: {
                meta.dst_port = icmp.code;
            }
        }
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
