#include "ZPOEventHdr.h"

#include <netinet/ether.h>
#include <netinet/in.h>

#include <iostream>

#include "zeek/net_util.h"

using namespace zeek::packet_analysis::BR_INF_UFRGS_ZPO;
using ::zeek::IP_Hdr;
using ::zeek::IPAddr;
using ::zeek::Layer3Proto;

std::shared_ptr<ZPOEventHdr> ZPOEventHdr::InitEventHdr(const uint16_t l3_protocol,
                                                       const uint8_t* data) {
    switch (l3_protocol) {
        case ETH_P_EVENT:
            return std::make_shared<ZPOEventHdr>(data, (const eth_event_h*)data);
        case ETH_P_EVENT_IP:
            return std::make_shared<ZPOEventHdr>(data, (const ip_event_h*)data);
        default:
            return nullptr;
    }
}

ZPOEventHdr::ZPOEventHdr(const uint8_t* data, const eth_event_h* hdr)
    : data(data), eth_event_hdr(hdr), hdr_size(ETH_EVENT_HEADER_SIZE), payload(data + hdr_size) {
    packet_number = ntohl(hdr->pkt_num);
    l3_protocol = ntohs(hdr->protocol_l3);
    event_type = ntohs(hdr->event_type);
}

ZPOEventHdr::ZPOEventHdr(const uint8_t* data, const ip_event_h* hdr)
    : data(data), ip_event_hdr(hdr), hdr_size(IP_EVENT_HEADER_SIZE), payload(data + hdr_size) {
    packet_number = ntohl(hdr->pkt_num);
    l3_protocol = ETH_P_IP;
    event_type = ntohs(hdr->event_type);
    src_port = ntohs(hdr->src_port);
    dst_port = ntohs(hdr->dst_port);
    ip_hdr = std::make_shared<IP_Hdr>(&hdr->ip_hdr, false, false);
}

IPAddr ZPOEventHdr::GetSrcAddress() const { return ip_hdr->SrcAddr(); }

IPAddr ZPOEventHdr::GetDstAddress() const { return ip_hdr->DstAddr(); }

uint16_t ZPOEventHdr::GetLayer3Protocol() const { return l3_protocol; }

uint8_t ZPOEventHdr::GetLayer4Protocol() const { return (uint8_t)ip_hdr->NextProto(); }

uint16_t ZPOEventHdr::GetSrcPort() const { return src_port; }

uint16_t ZPOEventHdr::GetDstPort() const { return dst_port; }

uint16_t ZPOEventHdr::GetEventType() const { return event_type; }

std::shared_ptr<IP_Hdr> ZPOEventHdr::GetIPHdr() const { return ip_hdr; }

uint32_t ZPOEventHdr::GetHdrSize() const { return hdr_size; }

bool ZPOEventHdr::IsIPv4() const { return l3_protocol == ETH_P_IP; }

Layer3Proto ZPOEventHdr::GetLayer3Proto() const {
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

TransportProto ZPOEventHdr::GetTransportProto() const {
    switch (GetLayer4Protocol()) {
        case IPPROTO_TCP:
            return TRANSPORT_TCP;
        case IPPROTO_UDP:
            return TRANSPORT_UDP;
        case IPPROTO_ICMP:
            return TRANSPORT_ICMP;
        default:
            return TRANSPORT_UNKNOWN;
    }
}

const uint8_t* ZPOEventHdr::GetPayload() const { return payload; }
