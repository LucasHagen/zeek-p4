#include "ZPOEventHdr.h"

#include <netinet/ether.h>
#include <netinet/in.h>

#include <iostream>

#include "zeek/net_util.h"

using namespace zeek::packet_analysis::BR_INF_UFRGS_ZPO;
using ::zeek::IPAddr;
using ::zeek::Layer3Proto;

ZPOEventHdr::ZPOEventHdr(const uint8_t* data)
    : data(data),
      hdr((const event_t*)data),
      packet_number(ntohl(hdr->pkt_num)),
      l3_protocol(ntohs(hdr->protocol_l3)),
      l4_protocol(hdr->protocol_l4),
      src_addr(IPAddr(IPv4, &hdr->src_addr, IPAddr::ByteOrder::Network)),
      dst_addr(IPAddr(IPv4, &hdr->dst_addr, IPAddr::ByteOrder::Network)),
      src_port(ntohs(hdr->src_port)),
      dst_port(ntohs(hdr->dst_port)),
      event_type(ntohs(hdr->type)) {}

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
    switch (l4_protocol) {
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

const uint8_t* ZPOEventHdr::Payload() const { return data + HEADER_SIZE; }
