#include "ArpReq.h"

#include <iostream>

#include "ZpoPacket.h"
#include "event_ids.h"
#include "zeek/Conn.h"
#include "zeek/Event.h"
#include "zeek/IPAddr.h"
#include "zeek/packet_analysis/protocol/arp/events.bif.h"

using namespace zeek::packet_analysis::BR_UFRGS_INF_ZPO::ARP;

using ::zeek::AddrVal;
using ::zeek::AddrValPtr;
using ::zeek::EventHandlerPtr;
using ::zeek::IPAddr;
using ::zeek::Layer3Proto;
using ::zeek::Packet;
using ::zeek::StringVal;
using ::zeek::StringValPtr;
using ::zeek::packet_analysis::Analyzer;

ZpoArpReqAnalyzer::ZpoArpReqAnalyzer() : Analyzer("ZPO_ARP_REQ") {}

AddrValPtr ToIPv4AddrVal(const struct in_addr& addr) {
    return zeek::make_intrusive<AddrVal>(ntohl(addr.s_addr));
}

StringValPtr ToEthAddrStr(const struct ether_addr& addr) {
    const uint8_t* ptr = addr.ether_addr_octet;
    char buf[1024];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", ptr[0], ptr[1], ptr[2], ptr[3],
             ptr[4], ptr[5]);
    return zeek::make_intrusive<StringVal>(buf);
}

bool ZpoArpReqAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    auto event_hdr = static_cast<ZpoPacket*>(packet)->event_hdr;
    auto arp_hdr = (const arp_ipv4_req_or_reply*)data;

    std::cout << "ARP REQUEST/REPLY:" << std::endl;
    std::cout << " - SrcIp: "
              << IPAddr(IPv4, (const uint32_t*)&arp_hdr->src_proto_addr, IPAddr::ByteOrder::Network)
                     .AsString()
              << std::endl;
    std::cout << " - DstIp: "
              << IPAddr(IPv4, (const uint32_t*)&arp_hdr->src_proto_addr, IPAddr::ByteOrder::Network)
                     .AsString()
              << std::endl;

    EventHandlerPtr e;

    switch (event_hdr->GetEventType()) {
        case TYPE_ARP_REQUEST_EVENT:
            e = arp_request;
            break;
        case TYPE_ARP_REPLY_EVENT:
            e = arp_reply;
            break;
        case TYPE_ARP_BAD_EVENT:
            // TODO: add arp_bad event
            return false;
        default:
            return false;
    }

    event_mgr.Enqueue(e, ToEthAddrStr(arp_hdr->mac_src), ToEthAddrStr(arp_hdr->mac_dst),
                      ToIPv4AddrVal(arp_hdr->src_proto_addr), ToEthAddrStr(arp_hdr->src_hw_addr),
                      ToIPv4AddrVal(arp_hdr->target_proto_addr),
                      ToEthAddrStr(arp_hdr->target_hw_addr));

    return true;
}
