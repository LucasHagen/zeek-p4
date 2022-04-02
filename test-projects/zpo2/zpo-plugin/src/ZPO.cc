#include "ZPO.h"

#include <netinet/ether.h>

#include <iostream>

#include "packets.h"
#include "zeek/Conn.h"
#include "zeek/Desc.h"
#include "zeek/Event.h"
#include "zeek/IPAddr.h"
#include "zeek/RunState.h"
#include "zeek/Val.h"
#include "zeek/net_util.h"
#include "zeek/packet_analysis/protocol/icmp/events.bif.h"
#include "zeek/packet_analysis/protocol/ip/SessionAdapter.h"
#include "zeek/session/Manager.h"

using namespace zeek::packet_analysis::BR_INF_UFRGS_ZPO;
using ::zeek::Connection;
using ::zeek::ConnTuple;
using ::zeek::IPAddr;
using ::zeek::make_intrusive;
using ::zeek::Packet;
using ::zeek::RecordType;
using ::zeek::val_mgr;
using ::zeek::detail::ConnKey;

ZPO::ZPO() : zeek::packet_analysis::Analyzer("ZPO") {}

in4_addr ip(const uint8_t* ptr) {
    return in4_addr{
        (uint32_t)(ptr[3] << 24 | ptr[2] << 16 | ptr[1] << 8 | ptr[0])};
}

bool ZPO::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    const event_t* event_hdr = (const event_t*)data;

    IPAddr src_addr = IPAddr(ip(event_hdr->src_addr));
    IPAddr dst_addr = IPAddr(ip(event_hdr->dst_addr));
    uint16_t src_port = ntohs(event_hdr->src_port);
    uint16_t dst_port = ntohs(event_hdr->dst_port);
    uint16_t l3_protocol = ntohs(event_hdr->protocol_l3);
    uint16_t l4_protocol = ntohs(event_hdr->protocol_l4);
    uint16_t event_type = ntohs(event_hdr->type);

    std::cout << std::endl
              << "[ZPO] AnalyzePacket!!!     \\/ \\/ \\/" << std::endl;

    printf("[ZPO] |- src_addr = %s\n", src_addr.AsString().c_str());
    printf("[ZPO] |- dst_addr = %s\n", dst_addr.AsString().c_str());
    printf("[ZPO] |- src_port = %hu\n", src_port);
    printf("[ZPO] |- dst_port = %hu\n", dst_port);
    printf("[ZPO] |- l3_proto = %hu (%s)\n", l3_protocol,
           (l3_protocol == ETH_P_IP ? "IP" : "other"));
    printf("[ZPO] |- l4_proto = %hu (%s)\n", l4_protocol,
           (l4_protocol == IPPROTO_ICMP ? "ICMP" : "other"));
    printf("[ZPO] |- event_id = %hu\n", event_type);

    std::cout << "[ZPO] END AnalyzePacket!!! /\\ /\\ /\\" << std::endl
              << std::endl;

    // return ForwardPacket(len - layer_size, data + layer_size, packet,
    // 0x0800);
    return false;
}
