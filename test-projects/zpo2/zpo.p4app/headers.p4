#ifndef ZPO_HEADERS
#define ZPO_HEADERS

// Header definitions for ICMP, TCP, and UDP loosely based on:
// https://github.com/p4lang/papers/blob/master/sosr15/DC.p4/includes/headers.p4

const bit<16>   TYPE_EVENT     = 0x6606; // L3
const bit<16>   TYPE_IPV4      = 0x0800;
const bit<16>   TYPE_IPV6      = 0x86DD;

const bit<8>    TYPE_ICMP      = 0x01;   // L4
const bit<8>    TYPE_ICMPV6    = 0x3A;
const bit<8>    TYPE_TCP       = 0x06;
const bit<8>    TYPE_UDP       = 0x11;

const bit<16>   TYPE_NTP      = 123;    // L7

typedef bit<16>  event_type_t;
typedef bit<48>  mac_addr_t;
typedef bit<32>  ipv4_addr_t;
typedef bit<128> ipv6_addr_t;

const bit<16> ICMP_ECHO_REQUEST_ID = 0x0008;

const event_type_t TYPE_NO_EVENT                = 16w0; // L3 (for events)
const event_type_t TYPE_ICMP_ECHO_REPLY_EVENT   = 16w1;
const event_type_t TYPE_ICMP_ECHO_REQ_EVENT     = 16w2;

// Zeek datatype definitions

typedef bit<8>  z_bool;     // boolean      (1 byte)
typedef bit<64> z_int;      // signed int   (8 bytes)
typedef bit<64> z_count;    // unsigned int (8 bytes)

header ethernet_t {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16>   ethertype;
}

// TODO: This may need to be adapted for variable-length headers.

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   total_len;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   frag_offset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header ipv6_t {
    bit<4>    version;
    bit<8>    traffic_class;
    bit<20>   flow_label;
    bit<16>   payload_length;
    bit<8>    next_header;
    bit<8>    hop_limit;
    ipv6_addr_t src_addr;
    ipv6_addr_t dst_addr;
}

header icmp_t {
    bit<8>    type_;
    bit<8>    code;
    bit<16>   hdr_checksum;
    bit<16>   id;  // Assuming echo request or reply.
    bit<16>   seq; // Ditto.

    // total:
}

header icmpv6_t {
    bit<8>    type_;
    bit<8>    code;
    bit<16>   hdr_checksum;
}

header tcp_t {
    bit<16>   src_port;
    bit<16>   dst_port;
    bit<32>   seq_no;
    bit<32>   ack_no;
    bit<4>    data_offset;
    bit<4>    res;
    bit<8>    flags;
    bit<16>   window;
    bit<16>   checksum;
    bit<16>   urgent_ptr;
}

header udp_t {
    bit<16>   src_port;
    bit<16>   dst_port;
    bit<16>   length_;
    bit<16>   checksum;
}

// NTP is specified on src/analyzer/protocol/ntp/ntp-protocol.pac

// This header specification applies to standard messages only (modes 1 to 5),
// but we also need to cover control (mode = 6) and private (mode = 7) messages.

// header ntp_t {

//     bit<2> leap_indicator;          // ntp.flags.li
//     bit<3> version;                 // ntp.flags.vn
//     bit<3> mode;                    // ntp.flags.mode
//     bit<8> peer_stratum;            // ntp.stratum
//     bit<8> peer_polling_interval;   // ntp.ppoll
//     bit<8> peer_clock_precision;    // ntp.precision

//     bit<32> root_delay;             // ntp.rootdelay
//     bit<32> root_dispersion;        // ntp.rootdispersion
//     bit<32> reference_id;           // ntp.refid

//     bit<64> reference_ts;           // ntp.reftime
//     bit<64> origin_ts;              // ntp.org
//     bit<64> receive_ts;             // ntp.rec
//     bit<64> transmit_ts;            // ntp.xmit

// }

// We begin by parsing the "flags" field so we know what mode will come next.
header ntp_flags_t {
    bit<2> leap;
    bit<3> version;
    bit<3> mode;
}

// Standard header for modes 1 to 5:
header ntp_std_t {
    bit<2> leap;                    // ntp.flags.li
    bit<3> version;                 // ntp.flags.vn
    bit<3> mode;                    // ntp.flags.mode
    bit<8> stratum;                 // ntp.stratum
    bit<8> poll;                    // ntp.ppoll
    bit<8> precision;               // ntp.precision

    bit<32> root_delay;             // ntp.rootdelay
    bit<32> root_dispersion;        // ntp.rootdispersion
    bit<32> reference_id;           // ntp.refid

    bit<64> reference_ts;           // ntp.reftime
    bit<64> origin_ts;              // ntp.org
    bit<64> receive_ts;             // ntp.rec
    bit<64> transmit_ts;            // ntp.xmit

    // Total: 48 bytes

    // TODO Add support for the extension fields, optionally followed by a MAC.

}

// Mode 7 header specification: src/analyzer/protocol/ntp/ntp-mode7.pac
header ntp_priv_t {
    bit<1>  response;
    bit<1>  more;
    bit<3>  version;
    bit<3>  mode;
    bit<1>  auth;
    bit<7>  seq;
    bit<8>  implementation; // TODO Is there an enum for this?
    bit<8>  request_code;   // TODO Is there an enum for this?

    bit<4>  err;
    bit<12> nb_items;
    bit<4>  mbz;
    bit<12> data_item_size;

    // Total: 8 bytes (excluding the data items, which will follow)

    // TODO Add support for the variable-length data field, optionally followed by a MAC.

}

// This will eventually become a Zeek-friendly event. The CP must translate (via a wrapper interface) our event signals into a format that Zeek can eat.
header event_t {
    bit<32> pkt_num;            // 4
    bit<16> protocol_l3;        // 2
    bit<16> protocol_l4;        // 2
    bit<32> src_addr;           // 4
    bit<32> dst_addr;           // 4
    bit<16> src_port;           // 2
    bit<16> dst_port;           // 2
    event_type_t type;          // 2
}

// Generated for ICMP *echo request* messages.
//
// See `Wikipedia
// <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
// information about the ICMP protocol.
//
// c: The connection record for the corresponding ICMP flow.
//
// icmp: Additional ICMP-specific information augmenting the standard
//       connection record *c*.
//
// info: Additional ICMP-specific information augmenting the standard
//       connection record *c*.
//
// id: The *echo request* identifier.
//
// seq: The *echo request* sequence number.
//
// payload: The message-specific data of the packet payload, i.e., everything
//          after the first 8 bytes of the ICMP header.
//
// .. zeek:see:: icmp_echo_reply
// event icmp_echo_request%(c: connection, info: icmp_info, id: count, seq: count, payload: string%);

struct z_icmp_info {
    z_bool  v6;             // True if it's an ICMPv6 packet.
	z_count itype;          // The ICMP type of the current packet.
	z_count icode;          // The ICMP code of the current packet.
	z_count len;            // The length of the ICMP payload.
	z_count ttl;            // The encapsulating IP header's TTL (IPv4) or Hop Limit (IPv6).

    // Total: 33 bytes
}

header icmp_echo_request_event_t {
    z_count id;         // id           (8 bytes)
    z_count seq;        // seq          (8 bytes)
    z_icmp_info info;   // icmp_info    (33 bytes)

    // Total: 49 bytes
}

// Generated for ICMP *echo reply* messages.
//
// See `Wikipedia
// <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
// information about the ICMP protocol.
//
// c: The connection record for the corresponding ICMP flow.
//
// icmp: Additional ICMP-specific information augmenting the standard connection
//       record *c*.
//
// info: Additional ICMP-specific information augmenting the standard
//       connection record *c*.
//
// id: The *echo reply* identifier.
//
// seq: The *echo reply* sequence number.
//
// payload: The message-specific data of the packet payload, i.e., everything
//          after the first 8 bytes of the ICMP header.
//
// .. zeek:see:: icmp_echo_request
// event icmp_echo_reply%(c: connection, info: icmp_info, id: count, seq: count, payload: string%);

header icmp_echo_reply_event_t {
    z_count id;         // id           (8 bytes)
    z_count seq;        // seq          (8 bytes)
    z_icmp_info info;   // icmp_info    (33 bytes)

    // Total: 49 bytes
}

struct headers  {
    ethernet_t  ethernet;
    event_t     event;
    ipv4_t      ipv4;
    ipv6_t      ipv6;
    icmp_t      icmp;
    icmpv6_t    icmpv6;
    tcp_t       tcp;
    udp_t       udp;
    ntp_flags_t ntp_flags;
    ntp_std_t   ntp_std;
    ntp_priv_t  ntp_priv;
    icmp_echo_request_event_t   icmp_echo_request_event;
    icmp_echo_reply_event_t     icmp_echo_reply_event;
}

struct metadata {
    bit<32> nhop_ipv4;
    bit<32> pkt_num;
    bit<16> protocol_l3;
    bit<16> protocol_l4;
    bit<32> src_addr;
    bit<32> dst_addr;
    bit<16> src_port;
    bit<16> dst_port;
    event_type_t event_type;
}

#endif /* ZPO_HEADERS */

