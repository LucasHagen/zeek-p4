#include "ZpoEventHdr.h"

#include <netinet/ether.h>
#include <netinet/in.h>

#include "zeek/Conn.h"
#include "zeek/Reporter.h"
#include "zeek/RunState.h"
#include "zeek/net_util.h"
#include "zeek/session/Manager.h"

using namespace zeek::packet_analysis::BR_UFRGS_INF_ZPO;
using ::zeek::Connection;
using ::zeek::ConnTuple;
using ::zeek::IP_Hdr;
using ::zeek::IPAddr;
using ::zeek::Layer3Proto;
using ::zeek::detail::ConnKey;

std::shared_ptr<ZpoEventHdr> ZpoEventHdr::InitEthEventHdr(const uint8_t* data) {
    return std::make_shared<ZpoEventHdr>(data, (const eth_event_h*)data);
}

std::shared_ptr<ZpoEventHdr> ZpoEventHdr::InitIpEventHdr(const uint8_t* data) {
    // Just for IP version checking:
    auto hdr = (const ipv4_event_h*)data;

    switch (hdr->ip_hdr.ip_v) {
        case 4:
            return std::make_shared<ZpoEventHdr>(data, (const ipv4_event_h*)data);
            break;
        case 6:
            return std::make_shared<ZpoEventHdr>(data, (const ipv6_event_h*)data);
            break;
        default:
            return nullptr;
    }
}

ZpoEventHdr::ZpoEventHdr(const uint8_t* data, const eth_event_h* hdr)
    : data(data), eth_event_hdr(hdr), hdr_size(ETH_EVENT_HEADER_SIZE), payload(data + hdr_size) {
    packet_number = ntohl(hdr->pkt_num);
    l3_protocol = ntohs(hdr->protocol_l3);
    event_type = ntohs(hdr->event_type);
}

ZpoEventHdr::ZpoEventHdr(const uint8_t* data, const ipv4_event_h* hdr)
    : data(data), ipv4_event_hdr(hdr), hdr_size(IPV4_EVENT_HEADER_SIZE), payload(data + hdr_size) {
    packet_number = ntohl(hdr->pkt_num);
    l3_protocol = ETH_P_IP;
    event_type = ntohs(hdr->event_type);
    src_port = ntohs(hdr->src_port);
    dst_port = ntohs(hdr->dst_port);
    ip_hdr = std::make_shared<IP_Hdr>(&hdr->ip_hdr, false, false);
}

ZpoEventHdr::ZpoEventHdr(const uint8_t* data, const ipv6_event_h* hdr)
    : data(data), ipv6_event_hdr(hdr), hdr_size(IPV6_EVENT_HEADER_SIZE), payload(data + hdr_size) {
    packet_number = ntohl(hdr->pkt_num);
    l3_protocol = ETH_P_IPV6;
    event_type = ntohs(hdr->event_type);
    src_port = ntohs(hdr->src_port);
    dst_port = ntohs(hdr->dst_port);
    ip_hdr = std::make_shared<IP_Hdr>(&hdr->ipv6_hdr, false, false);
}

IPAddr ZpoEventHdr::GetSrcAddress() const { return ip_hdr->SrcAddr(); }

IPAddr ZpoEventHdr::GetDstAddress() const { return ip_hdr->DstAddr(); }

uint16_t ZpoEventHdr::GetLayer3Protocol() const { return l3_protocol; }

uint8_t ZpoEventHdr::GetLayer4Protocol() const { return (uint8_t)ip_hdr->NextProto(); }

uint16_t ZpoEventHdr::GetSrcPort() const { return src_port; }

uint16_t ZpoEventHdr::GetDstPort() const { return dst_port; }

uint16_t ZpoEventHdr::GetEventType() const { return event_type; }

std::shared_ptr<IP_Hdr> ZpoEventHdr::GetIPHdr() const { return ip_hdr; }

uint32_t ZpoEventHdr::GetHdrSize() const { return hdr_size; }

bool ZpoEventHdr::IsIPv4() const { return l3_protocol == ETH_P_IP; }

bool ZpoEventHdr::IsIPv6() const { return l3_protocol == ETH_P_IPV6; }

Layer3Proto ZpoEventHdr::GetLayer3Proto() const {
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

TransportProto ZpoEventHdr::GetTransportProto() const {
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

const uint8_t* ZpoEventHdr::GetPayload() const { return payload; }

Connection* ZpoEventHdr::GetOrCreateConnection(const Packet* packet) {
    ConnTuple tuple = {
        GetSrcAddress(),    GetDstAddress(), htons(GetSrcPort()), htons(GetDstPort()), true,
        GetTransportProto()};
    return GetOrCreateConnection(packet, tuple);
}

Connection* ZpoEventHdr::GetOrCreateConnection(const Packet* packet, const ConnTuple& tuple) {
    detail::ConnKey key(tuple);

    Connection* conn = session_mgr->FindConnection(key);

    if (!conn) {
        conn = NewConn(&tuple, key, packet);

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

    return conn;
}

Connection* ZpoEventHdr::NewConn(const ConnTuple* id, const ConnKey& key, const Packet* packet) {
    // TODO: add timeout and memory deallocation.
    Connection* conn = new Connection(key, run_state::processing_start_time, id, 0, packet);
    conn->SetTransport(id->proto);

    if (new_connection) {
        conn->Event(new_connection, nullptr);
    }

    return conn;
}
