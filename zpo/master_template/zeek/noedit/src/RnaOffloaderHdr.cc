#include "RnaOffloaderHdr.h"

#include <netinet/ether.h>
#include <netinet/in.h>

#include "zeek/Conn.h"
#include "zeek/Reporter.h"
#include "zeek/RunState.h"
#include "zeek/net_util.h"
#include "zeek/session/Manager.h"

using namespace zeek::packet_analysis::BR_UFRGS_INF::RNA;
using ::zeek::Connection;
using ::zeek::ConnTuple;
using ::zeek::IP_Hdr;
using ::zeek::IPAddr;
using ::zeek::Layer3Proto;
using ::zeek::detail::ConnKey;

std::shared_ptr<RnaOffloaderHdr> RnaOffloaderHdr::InitEthOffloaderHdr(const uint8_t* data) {
    return std::make_shared<RnaOffloaderHdr>(data, (const eth_offloader_h*)data);
}

std::shared_ptr<RnaOffloaderHdr> RnaOffloaderHdr::InitIpv4OffloaderHdr(const uint8_t* data) {
    return std::make_shared<RnaOffloaderHdr>(data, (const ipv4_offloader_h*)data);
}

std::shared_ptr<RnaOffloaderHdr> RnaOffloaderHdr::InitIpv6OffloaderHdr(const uint8_t* data) {
    return std::make_shared<RnaOffloaderHdr>(data, (const ipv6_offloader_h*)data);
}

RnaOffloaderHdr::RnaOffloaderHdr(const uint8_t* data, const eth_offloader_h* hdr)
    : data(data),
      eth_offloader_hdr(hdr),
      hdr_size(ETH_OFFLOADER_HEADER_SIZE),
      payload(data + hdr_size) {
    offloader_type = ntohs(hdr->next_header);
    l3_protocol = ntohs(hdr->protocol_l3);
}

RnaOffloaderHdr::RnaOffloaderHdr(const uint8_t* data, const ipv4_offloader_h* hdr)
    : data(data),
      ipv4_offloader_hdr(hdr),
      hdr_size(IPV4_OFFLOADER_HEADER_SIZE),
      payload(data + hdr_size) {
    l3_protocol = ETH_P_IP;
    offloader_type = ntohs(hdr->next_header);
    src_port = ntohs(hdr->src_port);
    dst_port = ntohs(hdr->dst_port);
    ip_hdr = std::make_shared<IP_Hdr>(&hdr->ip_hdr, false, false);
}

RnaOffloaderHdr::RnaOffloaderHdr(const uint8_t* data, const ipv6_offloader_h* hdr)
    : data(data),
      ipv6_offloader_hdr(hdr),
      hdr_size(IPV6_OFFLOADER_HEADER_SIZE),
      payload(data + hdr_size) {
    l3_protocol = ETH_P_IPV6;
    offloader_type = ntohs(hdr->next_header);
    src_port = ntohs(hdr->src_port);
    dst_port = ntohs(hdr->dst_port);
    ip_hdr = std::make_shared<IP_Hdr>(&hdr->ipv6_hdr, false, false);
}

IPAddr RnaOffloaderHdr::GetSrcAddress() const { return ip_hdr->SrcAddr(); }

IPAddr RnaOffloaderHdr::GetDstAddress() const { return ip_hdr->DstAddr(); }

uint16_t RnaOffloaderHdr::GetLayer3Protocol() const { return l3_protocol; }

uint8_t RnaOffloaderHdr::GetLayer4Protocol() const { return (uint8_t)ip_hdr->NextProto(); }

uint16_t RnaOffloaderHdr::GetSrcPort() const { return src_port; }

uint16_t RnaOffloaderHdr::GetDstPort() const { return dst_port; }

uint16_t RnaOffloaderHdr::GetOffloaderType() const { return offloader_type; }

std::shared_ptr<IP_Hdr> RnaOffloaderHdr::GetIPHdr() const { return ip_hdr; }

uint32_t RnaOffloaderHdr::GetHdrSize() const { return hdr_size; }

bool RnaOffloaderHdr::IsIPv4() const { return l3_protocol == ETH_P_IP; }

bool RnaOffloaderHdr::IsIPv6() const { return l3_protocol == ETH_P_IPV6; }

Layer3Proto RnaOffloaderHdr::GetLayer3Proto() const {
    switch (l3_protocol) {
        case ETH_P_IP:
            return L3_IPV4;
        case ETH_P_IPV6:
            return L3_IPV6;
        case ETH_P_ARP:
            return L3_ARP;
        default:
            return L3_UNKNOWN;
    }
}

TransportProto RnaOffloaderHdr::GetTransportProto() const {
    switch (GetLayer4Protocol()) {
        case IPPROTO_TCP:
            return TRANSPORT_TCP;
        case IPPROTO_UDP:
            return TRANSPORT_UDP;
        case IPPROTO_ICMP:
            return TRANSPORT_ICMP;
        case IPPROTO_ICMPV6:
            return TRANSPORT_ICMP;
        default:
            return TRANSPORT_UNKNOWN;
    }
}

const uint8_t* RnaOffloaderHdr::GetPayload() const { return payload; }

Connection* RnaOffloaderHdr::GetOrCreateConnection(Packet* packet) {
    return GetOrCreateConnection(packet, false, false);
}

Connection* RnaOffloaderHdr::GetOrCreateConnection(Packet* packet, bool is_one_way,
                                                   bool flip_roles) {
    ConnTuple tuple;
    tuple.src_addr = GetSrcAddress();
    tuple.dst_addr = GetDstAddress();
    tuple.src_port = htons(GetSrcPort());
    tuple.dst_port = htons(GetDstPort());
    tuple.is_one_way = is_one_way;
    tuple.proto = GetTransportProto();

    return GetOrCreateConnection(packet, tuple, flip_roles);
}

Connection* RnaOffloaderHdr::GetOrCreateConnection(Packet* packet, const ConnTuple& tuple,
                                                   bool flip_roles) {
    detail::ConnKey key(tuple);

    Connection* conn = session_mgr->FindConnection(key);

    if (!conn) {
        conn = NewConn(&tuple, key, packet, flip_roles);

        if (conn) {
            session_mgr->Insert(conn, false);
        }
    } else {
        if (connection_reused) {
            conn->Event(connection_reused, nullptr);
        }

        // TODO: implement session adapter to check if the connection should be reused and
        // other controls (SessionAdapter) to make sure there is no memory leak.
        //
        // if (!conn->IsReuse(run_state::processing_start_time, ip_hdr->Payload())) {
        //     session_mgr->Remove(conn);
        //     conn = NewConn(&tuple, key, packet);
        //
        //     if (conn) {
        //         session_mgr->Insert(conn, false);
        //     }
        // }
    }

    bool is_orig = (tuple.src_addr == conn->OrigAddr()) && (tuple.src_port == conn->OrigPort());
    packet->is_orig = is_orig;

    conn->CheckFlowLabel(is_orig, ip_hdr->FlowLabel());

    return conn;
}

Connection* RnaOffloaderHdr::NewConn(const ConnTuple* id, const ConnKey& key, const Packet* packet,
                                     bool flip_roles) {
    // TODO: add timeout and memory deallocation.
    Connection* conn = new Connection(key, run_state::processing_start_time, id, 0, packet);
    conn->SetTransport(id->proto);

    if (flip_roles) {
        conn->FlipRoles();
    }

    if (new_connection) {
        conn->Event(new_connection, nullptr);
    }

    return conn;
}
