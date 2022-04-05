#include "ICMP.h"

#include <netinet/ether.h>

#include <iostream>

#include "event_ids.h"
#include "zeek/Conn.h"
#include "zeek/IPAddr.h"

using namespace zeek::packet_analysis::BR_INF_UFRGS_ZPO::ICMP;

using ::zeek::IPAddr;
using ::zeek::Layer3Proto;
using ::zeek::Packet;
using ::zeek::packet_analysis::Analyzer;

ZpoIcmpAnalyzer::ZpoIcmpAnalyzer() : Analyzer("ZPO_ICMP") {}

bool ZpoIcmpAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    ZPOEventHdr event_hdr = ZPOEventHdr(data);
    auto icmp_hdr = (const z_icmp_echo_and_reply_event_t*)event_hdr.Payload();

    std::cout << std::endl;
    std::cout << "[ZPO] START ICMP!!! \\/ \\/ \\/" << std::endl;
    std::cout << "[ZPO] |- LEN = " << len << std::endl;
    std::cout << "[ZPO] |- l3proto = " << packet->l3_proto << std::endl;

    switch (event_hdr.event_type) {
        case TYPE_ICMP_ECHO_REPLY_EVENT:
            std::cout << "[ZPO] |- event = ECHO_REPLY" << std::endl;
            break;
        case TYPE_ICMP_ECHO_REQ_EVENT:
            std::cout << "[ZPO] |- event = ECHO_REQ" << std::endl;
            break;
        default:
            std::cout << "[ZPO] |- event = NO_EVENT" << std::endl;
            break;
    }

    std::cout << "[ZPO] |- src_addr = " << event_hdr.src_addr.AsString() << std::endl;
    std::cout << "[ZPO] |- dst_addr = " << event_hdr.dst_addr.AsString() << std::endl;
    std::cout << "[ZPO] |- id       = " << ntohll(icmp_hdr->id) << std::endl;
    std::cout << "[ZPO] |- seq      = " << ntohll(icmp_hdr->seq) << std::endl;
    std::cout << "[ZPO] |- v6       = " << ntohs(icmp_hdr->v6) << std::endl;
    std::cout << "[ZPO] |- itype    = " << ntohll(icmp_hdr->itype) << std::endl;
    std::cout << "[ZPO] |- icode    = " << ntohll(icmp_hdr->icode) << std::endl;
    std::cout << "[ZPO] |- len      = " << ntohll(icmp_hdr->len) << std::endl;
    std::cout << "[ZPO] |- ttl      = " << ntohll(icmp_hdr->ttl) << std::endl;
    std::cout << "[ZPO] END ICMP!!!   /\\ /\\ /\\" << std::endl;
    std::cout << std::endl;

    return true;
}
