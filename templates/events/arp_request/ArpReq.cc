#include "ArpReq.h"

#include <iostream>

#include "RnaPacket.h"
#include "constants.h"
#include "zeek/Conn.h"
#include "zeek/Event.h"
#include "zeek/IPAddr.h"
#include "zeek/packet_analysis/protocol/arp/events.bif.h"

using namespace zeek::packet_analysis::BR_UFRGS_INF::RNA::ARP;

using ::zeek::AddrVal;
using ::zeek::AddrValPtr;
using ::zeek::IPAddr;
using ::zeek::Layer3Proto;
using ::zeek::Packet;
using ::zeek::StringVal;
using ::zeek::StringValPtr;
using ::zeek::packet_analysis::Analyzer;

RnaArpReqAnalyzer::RnaArpReqAnalyzer() : Analyzer("RNA_ARP_REQ") {}

AddrValPtr ToIPv4AddrValReq(const struct in_addr& addr) {
    return zeek::make_intrusive<AddrVal>(ntohl(addr.s_addr));
}

StringValPtr ToEthAddrStrReq(const struct ether_addr& addr) {
    const uint8_t* ptr = addr.ether_addr_octet;
    char buf[1024];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", ptr[0], ptr[1], ptr[2], ptr[3],
             ptr[4], ptr[5]);
    return zeek::make_intrusive<StringVal>(buf);
}

bool RnaArpReqAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    auto arp_hdr = (const arp_ipv4_request*)data;

// #define ARP_REQUEST_DEBUG
#ifdef ARP_REQUEST_DEBUG
    std::cout << "ARP REQUEST:" << std::endl;
    std::cout << " - SrcIp: "
              << IPAddr(IPv4, (const uint32_t*)&arp_hdr->src_proto_addr, IPAddr::ByteOrder::Network)
                     .AsString()
              << std::endl;
    std::cout << " - DstIp: "
              << IPAddr(IPv4, (const uint32_t*)&arp_hdr->src_proto_addr, IPAddr::ByteOrder::Network)
                     .AsString()
              << std::endl;
#endif

    event_mgr.Enqueue(arp_request, ToEthAddrStrReq(arp_hdr->mac_src), ToEthAddrStrReq(arp_hdr->mac_dst),
                      ToIPv4AddrValReq(arp_hdr->src_proto_addr), ToEthAddrStrReq(arp_hdr->src_hw_addr),
                      ToIPv4AddrValReq(arp_hdr->target_proto_addr),
                      ToEthAddrStrReq(arp_hdr->target_hw_addr));

    return true;
}
