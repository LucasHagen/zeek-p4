#include "ZPO.h"

#include <netinet/ether.h>

#include <iostream>

#include "zeek/Conn.h"
#include "zeek/IPAddr.h"

using namespace zeek::packet_analysis::BR_INF_UFRGS_ZPO;
using ::zeek::IPAddr;
using ::zeek::Layer3Proto;
using ::zeek::Packet;
using ::zeek::packet_analysis::Analyzer;

// #define ZPO_DEBUG

ZPO::ZPO() : Analyzer("ZPO") {}

bool ZPO::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    ZPOEventHdr hdr = ZPOEventHdr(data);
    packet->l3_proto = hdr.GetLayer3Proto();

#ifdef ZPO_DEBUG
    std::cout << std::endl;
    std::cout << "[ZPO] START AnalyzePacket!!! \\/ \\/ \\/" << std::endl;
    std::cout << "[ZPO] |- src_addr = " << hdr.src_addr.AsString() << std::endl;
    std::cout << "[ZPO] |- dst_addr = " << hdr.dst_addr.AsString() << std::endl;
    std::cout << "[ZPO] |- src_port = " << hdr.src_port << std::endl;
    std::cout << "[ZPO] |- dst_port = " << hdr.dst_port << std::endl;
    std::cout << "[ZPO] |- l3_proto = " << hdr.l3_protocol << std::endl;
    std::cout << "[ZPO] |- l4_proto = " << hdr.l4_protocol << std::endl;
    std::cout << "[ZPO] |- event_id = " << hdr.event_type << std::endl;
    std::cout << "[ZPO] END AnalyzePacket!!!   /\\ /\\ /\\" << std::endl;
    std::cout << std::endl;
#endif

    return ForwardPacket(len, data, packet, hdr.event_type);
}
