#include "RnaIcmpEchoAnalyzer.h"

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

// #define RNA_ICMP_ECHO_DEBUG

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

RnaIcmpEchoAnalyzer::RnaIcmpEchoAnalyzer() : Analyzer("RNA_ICMP_ECHO") {}

RecordValPtr BuildInfo(const icmp_echo_message_h* icmp) {
    static auto icmp_info = zeek::id::find_type<RecordType>("icmp_info");
    auto rval = make_intrusive<RecordVal>(icmp_info);
    rval->Assign(0, val_mgr->Bool(false));
    rval->Assign(1, val_mgr->Count(icmp->itype));
    rval->Assign(2, val_mgr->Count(icmp->icode));
    rval->Assign(3, val_mgr->Count(ntohs(icmp->len)));
    rval->Assign(4, val_mgr->Count(icmp->ttl));
    return rval;
}

bool RnaIcmpEchoAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    auto rna_packet = static_cast<RnaPacket*>(packet);
    auto offloader_hdr = rna_packet->GetOffloaderHdr();
    auto icmp_hdr = (const icmp_echo_message_h*)offloader_hdr->GetPayload();

    int payload_len = len - sizeof(icmp_echo_message_h);
    const u_char* payload = (const u_char*)(data + sizeof(icmp_echo_message_h));
    String* payloadStr = new String(payload, payload_len, false);

    auto conn = offloader_hdr->GetOrCreateConnection(packet);

#ifdef RNA_ICMP_ECHO_DEBUG
    std::cout << std::endl;
    std::cout << "[RNA] START ICMP ECHO MESSAGE!!! \\/ \\/ \\/" << std::endl;
    std::cout << "[RNA] |- src_addr = " << packet->ip_hdr->SrcAddr().AsString() << std::endl;
    std::cout << "[RNA] |- dst_addr = " << packet->ip_hdr->DstAddr().AsString() << std::endl;
    std::cout << "[RNA] |- src_port = " << offloader_hdr->GetSrcPort() << std::endl;
    std::cout << "[RNA] |- dst_port = " << offloader_hdr->GetDstPort() << std::endl;
    std::cout << "[RNA] |- id       = " << ntohs(icmp_hdr->id) << std::endl;
    std::cout << "[RNA] |- seq      = " << ntohs(icmp_hdr->seq) << std::endl;
    std::cout << "[RNA] |- itype    = " << (uint)icmp_hdr->itype << std::endl;
    std::cout << "[RNA] |- icode    = " << (uint)icmp_hdr->icode << std::endl;
    std::cout << "[RNA] |- len      = " << ntohs(icmp_hdr->len) << std::endl;
    std::cout << "[RNA] |- ttl      = " << (uint)icmp_hdr->ttl << std::endl;
    std::cout << "[RNA] END   ICMP ECHO MESSAGE!!!   /\\ /\\ /\\" << std::endl;
    std::cout << std::endl;
#endif

    EventHandlerPtr e;
    switch (icmp_hdr->itype) {
        case ICMP_ECHOREPLY:
            e = icmp_echo_reply;
            break;
        case ICMP_ECHO:
            e = icmp_echo_request;
            break;
        default:
            return false;
    }

    packet->processed = true;

    if (e) {
        event_mgr.Enqueue(e, conn->GetVal(), BuildInfo(icmp_hdr),
                          val_mgr->Count(ntohs(icmp_hdr->id)), val_mgr->Count(ntohs(icmp_hdr->seq)),
                          make_intrusive<StringVal>(payloadStr));
    }

    return true;
}
