#include "Icmp.h"

#include <netinet/ether.h>

#include <iostream>

#include "RnaPacket.h"
#include "constants.h"
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

using namespace zeek::packet_analysis::BR_UFRGS_INF::RNA::ICMP;
using namespace zeek::packet_analysis::IP;
using ::zeek::make_intrusive;
using ::zeek::ntohll;
using ::zeek::RecordType;
using ::zeek::RecordVal;
using ::zeek::RecordValPtr;
using ::zeek::val_mgr;
using ::zeek::packet_analysis::IP::SessionAdapter;

RnaIcmpReqAnalyzer::RnaIcmpReqAnalyzer() : Analyzer("RNA_ICMP_REQ") {}

RecordValPtr BuildInfo(const icmp_echo_request_event_h* icmp) {
    static auto icmp_info = zeek::id::find_type<RecordType>("icmp_info");
    auto rval = make_intrusive<RecordVal>(icmp_info);
    rval->Assign(0, val_mgr->Bool(icmp->v6));
    rval->Assign(1, val_mgr->Count(ntohll(icmp->itype)));
    rval->Assign(2, val_mgr->Count(ntohll(icmp->icode)));
    rval->Assign(3, val_mgr->Count(ntohll(icmp->len)));
    rval->Assign(4, val_mgr->Count(ntohll(icmp->ttl)));
    return rval;
}

bool RnaIcmpReqAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    auto rna_packet = static_cast<RnaPacket*>(packet);
    auto event_hdr = rna_packet->GetEventHdr();
    auto icmp_hdr = (const icmp_echo_request_event_h*)event_hdr->GetPayload();

    auto payload = event_hdr->GetPayload() + sizeof(icmp_echo_request_event_h);
    auto payload_len = ntohll(icmp_hdr->len);
    String* payloadStr = new String(payload, payload_len, false);

    auto conn = event_hdr->GetOrCreateConnection(packet);

// #define RNA_ICMP_REQUEST_DEBUG
#ifdef RNA_ICMP_REQUEST_DEBUG
    std::cout << std::endl;
    std::cout << "[RNA] START ICMP REQ!!! \\/ \\/ \\/" << std::endl;
    std::cout << "[RNA] |- event = ECHO_REQ" << std::endl;
    std::cout << "[RNA] |- src_addr = " << packet->ip_hdr->SrcAddr().AsString() << std::endl;
    std::cout << "[RNA] |- dst_addr = " << packet->ip_hdr->DstAddr().AsString() << std::endl;
    std::cout << "[RNA] |- src_port = " << event_hdr->GetSrcPort() << std::endl;
    std::cout << "[RNA] |- dst_port = " << event_hdr->GetDstPort() << std::endl;
    std::cout << "[RNA] |- id       = " << ntohll(icmp_hdr->id) << std::endl;
    std::cout << "[RNA] |- seq      = " << ntohll(icmp_hdr->seq) << std::endl;
    std::cout << "[RNA] |- v6       = " << ntohs(icmp_hdr->v6) << std::endl;
    std::cout << "[RNA] |- itype    = " << ntohll(icmp_hdr->itype) << std::endl;
    std::cout << "[RNA] |- icode    = " << ntohll(icmp_hdr->icode) << std::endl;
    std::cout << "[RNA] |- len      = " << ntohll(icmp_hdr->len) << std::endl;
    std::cout << "[RNA] |- ttl      = " << ntohll(icmp_hdr->ttl) << std::endl;
    std::cout << "[RNA] END ICMP REQ!!!   /\\ /\\ /\\" << std::endl;
    std::cout << std::endl;
#endif

    packet->processed = true;

    event_mgr.Enqueue(icmp_echo_request, conn->GetVal(), BuildInfo(icmp_hdr), val_mgr->Count(ntohll(icmp_hdr->id)),
                      val_mgr->Count(ntohll(icmp_hdr->seq)), make_intrusive<StringVal>(payloadStr));

    return true;
}
