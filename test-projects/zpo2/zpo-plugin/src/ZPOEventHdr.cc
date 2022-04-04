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
      event_type(ntohs(hdr->type)) {
    std::cout << "ZPO_EVENT_HEADER[uint32_t pkt_num] "
              << (uint64_t)(void*)&hdr->pkt_num - (uint64_t)(void*)hdr << std::endl;
    std::cout << "ZPO_EVENT_HEADER[uint16_t protocol_l3] "
              << (uint64_t)(void*)&hdr->protocol_l3 - (uint64_t)(void*)hdr << std::endl;
    std::cout << "ZPO_EVENT_HEADER[uint8_t protocol_l4] "
              << (uint64_t)(void*)&hdr->protocol_l4 - (uint64_t)(void*)hdr << std::endl;
    std::cout << "ZPO_EVENT_HEADER[uint32_t src_addr] "
              << (uint64_t)(void*)&hdr->src_addr - (uint64_t)(void*)hdr << std::endl;
    std::cout << "ZPO_EVENT_HEADER[uint32_t dst_addr] "
              << (uint64_t)(void*)&hdr->dst_addr - (uint64_t)(void*)hdr << std::endl;
    std::cout << "ZPO_EVENT_HEADER[uint16_t src_port] "
              << (uint64_t)(void*)&hdr->src_port - (uint64_t)(void*)hdr << std::endl;
    std::cout << "ZPO_EVENT_HEADER[uint16_t dst_port] "
              << (uint64_t)(void*)&hdr->dst_port - (uint64_t)(void*)hdr << std::endl;
    std::cout << "ZPO_EVENT_HEADER[uint16_t type] "
              << (uint64_t)(void*)&hdr->type - (uint64_t)(void*)hdr << std::endl;
}

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

const uint8_t* ZPOEventHdr::Payload() const { return data + PACKET_SIZE; }
