#include "Icmp.h"

#include <netinet/ether.h>

#include <iostream>

#include "IcmpSessionAdapter.h"
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

ZpoIcmpAnalyzer::ZpoIcmpAnalyzer()
    : IPBasedAnalyzer("ZPO_ICMP", TRANSPORT_ICMP, ICMP_PORT_MASK, false) {}

SessionAdapter* ZpoIcmpAnalyzer::MakeSessionAdapter(Connection* conn) {
    auto* root = new IcmpSessionAdapter(conn);
    root->SetParent(this);
    conn->SetInactivityTimeout(zeek::detail::icmp_inactivity_timeout);

    return root;
}

bool ZpoIcmpAnalyzer::BuildConnTuple(size_t len, const uint8_t* data, Packet* packet,
                                     ConnTuple& tuple) {
    if (!CheckHeaderTrunc(sizeof(icmp_echo_and_reply_event_h), len, packet)) {
        return false;
    }

    auto event_hdr = static_cast<ZpoPacket*>(packet)->event_hdr;

    tuple.proto = TRANSPORT_ICMP;
    tuple.src_addr = packet->ip_hdr->SrcAddr();
    tuple.dst_addr = packet->ip_hdr->DstAddr();
    tuple.src_port = event_hdr->GetSrcPort();
    tuple.dst_port = event_hdr->GetDstPort();

    std::cout << std::endl;
    std::cout << "CONNECTION KEY:" << std::endl;
    std::cout << " |- proto: " << tuple.proto << std::endl;
    std::cout << " |- src_addr: " << tuple.src_addr.AsString() << std::endl;
    std::cout << " |- dst_addr: " << tuple.dst_addr.AsString() << std::endl;
    std::cout << " |- src_port: " << tuple.src_port << std::endl;
    std::cout << " |- dst_port: " << tuple.dst_port << std::endl;
    std::cout << std::endl;

    return true;
}

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

void ZpoIcmpAnalyzer::DeliverPacket(Connection* conn, double t, bool is_orig, int remaining,
                                    Packet* packet) {
    auto adapter = static_cast<IcmpSessionAdapter*>(conn->GetSessionAdapter());
    auto zpo_packet = static_cast<ZpoPacket*>(packet);
    auto event_hdr = zpo_packet->event_hdr;
    auto icmp_hdr = (const icmp_echo_and_reply_event_h*)event_hdr->GetPayload();
    auto payload = event_hdr->GetPayload() + sizeof(icmp_echo_and_reply_event_h);
    auto payload_len = ntohll(icmp_hdr->len);

    String* payloadStr = new String(payload, payload_len, false);

    EventHandlerPtr e;
    switch (event_hdr->GetEventType()) {
        case TYPE_ICMP_ECHO_REQ_EVENT:
            e = icmp_echo_request;
            break;
        case TYPE_ICMP_ECHO_REPLY_EVENT:
            e = icmp_echo_reply;
            break;
        default:
            return;
    }

    std::cout << "ZPO 1" << std::endl;

    conn->SetLastTime(run_state::current_timestamp);
    std::cout << "ZPO 2" << std::endl;

    adapter->InitEndpointMatcher(zpo_packet->ip_hdr.get(), remaining, is_orig);
    std::cout << "ZPO 3" << std::endl;


    // Move past common portion of ICMP header.
    adapter->UpdateLength(is_orig, payload_len);
    std::cout << "ZPO 4" << std::endl;


#define ZPO_ICMP_DEBUG
#ifdef ZPO_ICMP_DEBUG

    std::cout << std::endl;
    std::cout << "[ZPO] START ICMP!!! \\/ \\/ \\/" << std::endl;
    std::cout << "[ZPO] |- l3proto = " << packet->l3_proto << std::endl;

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

    std::cout << "[ZPO] |- conn     = " << (conn == nullptr ? "nullptr" : "OK") << std::endl;
    std::cout << "[ZPO] |- adapter  = " << (adapter == nullptr ? "nullptr" : "OK") << std::endl;
    // if (adapter != nullptr) {
    //     std::cout << "[ZPO]     |- conn = " << (adapter->Conn() == nullptr ? "nullptr" : "OK")
    //               << std::endl;
    // } else {
    //     std::cout << "[ZPO]     |- conn = " << nullptr << std::endl;
    // }
    std::cout << "[ZPO] |- src_addr = " << packet->ip_hdr->SrcAddr().AsString() << std::endl;
    std::cout << "[ZPO] |- dst_addr = " << packet->ip_hdr->DstAddr().AsString() << std::endl;
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

    // if (adapter != nullptr) {
    //     adapter->EnqueueConnEvent(
    //         e, adapter->ConnVal(), BuildInfo(icmp_hdr), val_mgr->Count(ntohll(icmp_hdr->id)),
    //         val_mgr->Count(ntohll(icmp_hdr->seq)), make_intrusive<StringVal>(payload));
    // }

    // Store the session in the packet in case we get an encapsulation here. We need it for
    // handling those properly.
    packet->session = conn;
    adapter->MatchEndpoint(payload, payload_len, is_orig);
}
