#include "Icmp.h"

#include <netinet/ether.h>

#include <iostream>

#include "ZpoPacket.h"
#include "event_ids.h"
#include "zeek/Conn.h"
#include "zeek/Desc.h"
#include "zeek/Reporter.h"
#include "zeek/RunState.h"
#include "zeek/Val.h"
#include "zeek/ZeekString.h"
#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/protocol/conn-size/ConnSize.h"
#include "zeek/packet_analysis/protocol/icmp/events.bif.h"
#include "zeek/session/Manager.h"

enum ICMP_EndpointState {
    ICMP_INACTIVE,  // no packet seen
    ICMP_ACTIVE,    // packets seen
};

using namespace zeek::packet_analysis::BR_INF_UFRGS_ZPO::ICMP;
using namespace zeek::packet_analysis::IP;
using ::zeek::make_intrusive;
using ::zeek::ntohll;
using ::zeek::RecordType;
using ::zeek::RecordVal;
using ::zeek::RecordValPtr;
using ::zeek::val_mgr;
using ::zeek::packet_analysis::IP::SessionAdapter;

ZpoIcmpAnalyzer::ZpoIcmpAnalyzer() : Analyzer("ZPO_ICMP") {}

RecordValPtr BuildInfo(const icmp_echo_and_reply_event_h* icmp) {
    static auto icmp_info = zeek::id::find_type<RecordType>("icmp_info");
    auto rval = make_intrusive<RecordVal>(icmp_info);
    rval->Assign(0, val_mgr->Bool(icmp->v6));
    rval->Assign(1, val_mgr->Count(ntohll(icmp->itype)));
    rval->Assign(2, val_mgr->Count(ntohll(icmp->icode)));
    rval->Assign(3, val_mgr->Count(ntohll(icmp->len)));
    rval->Assign(4, val_mgr->Count(ntohll(icmp->ttl)));
    return rval;
}

bool ZpoIcmpAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    auto zpo_packet = static_cast<ZpoPacket*>(packet);
    auto event_hdr = zpo_packet->event_hdr;
    auto icmp_hdr = (const icmp_echo_and_reply_event_h*)event_hdr->GetPayload();

    auto payload = event_hdr->GetPayload() + sizeof(icmp_echo_and_reply_event_h);
    auto payload_len = ntohll(icmp_hdr->len);
    String* payloadStr = new String(payload, payload_len, false);

    auto conn = event_hdr->GetOrCreateConnection(packet);

// #define ZPO_ICMP_DEBUG
#ifdef ZPO_ICMP_DEBUG

    std::cout << std::endl;
    std::cout << "[ZPO] START ICMP!!! \\/ \\/ \\/" << std::endl;

    switch (event_hdr->GetEventType()) {
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

    std::cout << "[ZPO] |- src_addr = " << packet->ip_hdr->SrcAddr().AsString() << std::endl;
    std::cout << "[ZPO] |- dst_addr = " << packet->ip_hdr->DstAddr().AsString() << std::endl;
    std::cout << "[ZPO] |- src_port = " << event_hdr->GetSrcPort() << std::endl;
    std::cout << "[ZPO] |- dst_port = " << event_hdr->GetDstPort() << std::endl;
    std::cout << "[ZPO] |- id       = " << ntohll(icmp_hdr->id) << std::endl;
    std::cout << "[ZPO] |- seq      = " << ntohll(icmp_hdr->seq) << std::endl;
    std::cout << "[ZPO] |- v6       = " << ntohs(icmp_hdr->v6) << std::endl;
    std::cout << "[ZPO] |- itype    = " << ntohll(icmp_hdr->itype) << std::endl;
    std::cout << "[ZPO] |- icode    = " << ntohll(icmp_hdr->icode) << std::endl;
    std::cout << "[ZPO] |- len      = " << ntohll(icmp_hdr->len) << std::endl;
    std::cout << "[ZPO] |- ttl      = " << ntohll(icmp_hdr->ttl) << std::endl;
    std::cout << "[ZPO] END ICMP!!!   /\\ /\\ /\\" << std::endl;
    std::cout << std::endl;

#endif

    EventHandlerPtr e;
    switch (event_hdr->GetEventType()) {
        case TYPE_ICMP_ECHO_REQ_EVENT:
            e = icmp_echo_request;
            break;
        case TYPE_ICMP_ECHO_REPLY_EVENT:
            e = icmp_echo_reply;
            break;
        default:
            return false;
    }

    event_mgr.Enqueue(e, conn->GetVal(), BuildInfo(icmp_hdr), val_mgr->Count(ntohll(icmp_hdr->id)),
                      val_mgr->Count(ntohll(icmp_hdr->seq)), make_intrusive<StringVal>(payloadStr));

    return true;
}
