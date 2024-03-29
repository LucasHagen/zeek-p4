#include "ZpoIp.h"

#include <netinet/ether.h>

#include <iostream>
#include <memory>

#include "ZpoPacket.h"
#include "zeek/Conn.h"
#include "zeek/IPAddr.h"

using namespace zeek::packet_analysis::BR_INF_UFRGS_ZPO;
using ::zeek::IPAddr;
using ::zeek::Layer3Proto;
using ::zeek::Packet;
using ::zeek::packet_analysis::Analyzer;

// #define ZPO_DEBUG

ZpoIp::ZpoIp() : Analyzer("ZPO_IP") {}

bool ZpoIp::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    std::shared_ptr<ZpoEventHdr> hdr = ZpoEventHdr::InitIpEventHdr(data);
    std::shared_ptr<ZpoPacket> zpo_packet = std::make_shared<ZpoPacket>(packet, hdr);

#ifdef ZPO_DEBUG
    std::cout << std::endl;
    std::cout << "[ZPO] START AnalyzePacket!!! \\/ \\/ \\/" << std::endl;
    std::cout << "[ZPO] |- src_addr = " << hdr->GetSrcAddress().AsString() << std::endl;
    std::cout << "[ZPO] |- dst_addr = " << hdr->GetDstAddress().AsString() << std::endl;
    std::cout << "[ZPO] |- src_port = " << hdr->GetSrcPort() << std::endl;
    std::cout << "[ZPO] |- dst_port = " << hdr->GetDstPort() << std::endl;
    std::cout << "[ZPO] |- l3_proto = " << hdr->GetLayer3Protocol() << std::endl;
    std::cout << "[ZPO] |- l4_proto = " << (uint16_t)hdr->GetLayer4Protocol() << std::endl;
    std::cout << "[ZPO] |- event_id = " << hdr->GetEventType() << std::endl;
    std::cout << "[ZPO] END AnalyzePacket!!!   /\\ /\\ /\\" << std::endl;
    std::cout << std::endl;
#endif

    return ForwardPacket(len - hdr->GetHdrSize(), hdr->GetPayload(), zpo_packet.get(), hdr->GetEventType());
}
