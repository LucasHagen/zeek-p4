#include "ZpoEth.h"

#include <netinet/ether.h>

#include <iostream>
#include <memory>

#include "ZPOPacket.h"
#include "zeek/Conn.h"
#include "zeek/IPAddr.h"

using namespace zeek::packet_analysis::BR_INF_UFRGS_ZPO;
using ::zeek::IPAddr;
using ::zeek::Layer3Proto;
using ::zeek::Packet;
using ::zeek::packet_analysis::Analyzer;

// #define ZPO_DEBUG

ZpoEth::ZpoEth() : Analyzer("ZPO_ETH") {}

bool ZpoEth::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    std::shared_ptr<ZpoEventHdr> hdr = ZpoEventHdr::InitEventHdr(ETH_P_EVENT, data);
    std::shared_ptr<ZPOPacket> zpo_packet = std::make_shared<ZPOPacket>(packet, hdr);

#ifdef ZPO_DEBUG
    std::cout << std::endl;
    std::cout << "[ZPO] START ETH AnalyzePacket!!! \\/ \\/ \\/" << std::endl;
    std::cout << "[ZPO] |- l3_proto = " << hdr->GetLayer3Protocol() << std::endl;
    std::cout << "[ZPO] |- event_id = " << hdr->GetEventType() << std::endl;
    std::cout << "[ZPO] END ETH AnalyzePacket!!!   /\\ /\\ /\\" << std::endl;
    std::cout << std::endl;
#endif

    return ForwardPacket(len - hdr->GetHdrSize(), hdr->GetPayload(), zpo_packet.get(), hdr->GetEventType());
}
