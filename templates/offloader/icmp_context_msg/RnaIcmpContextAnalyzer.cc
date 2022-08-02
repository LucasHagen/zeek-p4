#include "RnaIcmpContextAnalyzer.h"

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

// #define RNA_ICMP_CONTEXT_DEBUG

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

RnaIcmpContextAnalyzer::RnaIcmpContextAnalyzer() : Analyzer("RNA_ICMP_CONTEXT") {}

// Code from `deps/zeek/src/packet_analysis/protocol/icmp/ICMP.cc`
RecordValPtr RnaIcmpContextAnalyzer::BuildInfo(const icmp_context_msg_h* icmp, size_t len,
                                               uint8_t ttl) {
    static auto icmp_info = zeek::id::find_type<RecordType>("icmp_info");
    auto rval = make_intrusive<RecordVal>(icmp_info);
    rval->Assign(0, val_mgr->Bool(false));
    rval->Assign(1, val_mgr->Count(icmp->itype));
    rval->Assign(2, val_mgr->Count(icmp->icode));
    rval->Assign(3, val_mgr->Count(len));
    rval->Assign(4, val_mgr->Count(ttl));
    return rval;
}

// Code from `deps/zeek/src/packet_analysis/protocol/icmp/ICMP.cc`
int RnaIcmpContextAnalyzer::ICMP4_counterpart(int icmp_type, int icmp_code, bool& is_one_way) {
    is_one_way = false;

    // Return the counterpart type if one exists.  This allows us
    // to track corresponding ICMP requests/replies.
    // Note that for the two-way ICMP messages, icmp_code is
    // always 0 (RFC 792).
    switch (icmp_type) {
        case ICMP_ECHO:
            return ICMP_ECHOREPLY;
        case ICMP_ECHOREPLY:
            return ICMP_ECHO;

        case ICMP_TSTAMP:
            return ICMP_TSTAMPREPLY;
        case ICMP_TSTAMPREPLY:
            return ICMP_TSTAMP;

        case ICMP_IREQ:
            return ICMP_IREQREPLY;
        case ICMP_IREQREPLY:
            return ICMP_IREQ;

        case ICMP_ROUTERSOLICIT:
            return ICMP_ROUTERADVERT;
        case ICMP_ROUTERADVERT:
            return ICMP_ROUTERSOLICIT;

        case ICMP_MASKREQ:
            return ICMP_MASKREPLY;
        case ICMP_MASKREPLY:
            return ICMP_MASKREQ;

        default:
            is_one_way = true;
            return icmp_code;
    }
}

// Code from `deps/zeek/src/packet_analysis/protocol/icmp/ICMP.cc`
TransportProto RnaIcmpContextAnalyzer::GetContextProtocol(const IP_Hdr* ip_hdr, uint32_t* src_port,
                                                          uint32_t* dst_port) {
    const u_char* transport_hdr;
    uint32_t ip_hdr_len = ip_hdr->HdrLen();

    transport_hdr = ((u_char*)ip_hdr->IP4_Hdr() + ip_hdr_len);

    TransportProto proto;

    switch (ip_hdr->NextProto()) {
        case 1:
            proto = TRANSPORT_ICMP;
            break;
        case 6:
            proto = TRANSPORT_TCP;
            break;
        case 17:
            proto = TRANSPORT_UDP;
            break;
        default:
            proto = TRANSPORT_UNKNOWN;
            break;
    }

    switch (proto) {
        case TRANSPORT_ICMP: {
            const struct icmp* icmpp = (const struct icmp*)transport_hdr;
            bool is_one_way;  // dummy
            *src_port = ntohs(icmpp->icmp_type);
            *dst_port = ntohs(ICMP4_counterpart(icmpp->icmp_type, icmpp->icmp_code, is_one_way));

            break;
        }

        case TRANSPORT_TCP: {
            const struct tcphdr* tp = (const struct tcphdr*)transport_hdr;
            *src_port = ntohs(tp->th_sport);
            *dst_port = ntohs(tp->th_dport);
            break;
        }

        case TRANSPORT_UDP: {
            const struct udphdr* up = (const struct udphdr*)transport_hdr;
            *src_port = ntohs(up->uh_sport);
            *dst_port = ntohs(up->uh_dport);
            break;
        }

        default:
            *src_port = *dst_port = ntohs(0);
            break;
    }

    return proto;
}

// Code from `deps/zeek/src/packet_analysis/protocol/icmp/ICMP.cc`
zeek::RecordValPtr RnaIcmpContextAnalyzer::ExtractICMP4Context(int len, const u_char*& data) {
    const IP_Hdr ip_hdr_data((const struct ip*)data, false);
    const IP_Hdr* ip_hdr = &ip_hdr_data;

    uint32_t ip_hdr_len = ip_hdr->HdrLen();

    uint32_t ip_len, frag_offset;
    TransportProto proto = TRANSPORT_UNKNOWN;
    int DF, MF, bad_hdr_len, bad_checksum;
    IPAddr src_addr, dst_addr;
    uint32_t src_port, dst_port;

    if (len < (int)sizeof(struct ip) || ip_hdr_len > uint32_t(len)) {
        // We don't have an entire IP header.
        bad_hdr_len = 1;
        ip_len = frag_offset = 0;
        DF = MF = bad_checksum = 0;
        src_port = dst_port = 0;
    } else {
        bad_hdr_len = 0;
        ip_len = ip_hdr->TotalLen();
        // bad_checksum = !run_state::current_pkt->l3_checksummed &&
        //                (detail::in_cksum(reinterpret_cast<const uint8_t*>(ip_hdr->IP4_Hdr()),
        //                                  ip_hdr_len) != 0xffff);

        src_addr = ip_hdr->SrcAddr();
        dst_addr = ip_hdr->DstAddr();

        DF = ip_hdr->DF();
        MF = ip_hdr->MF();
        frag_offset = ip_hdr->FragOffset();

        if (uint32_t(len) >= ip_hdr_len + 4) {
            proto = GetContextProtocol(ip_hdr, &src_port, &dst_port);
        } else {
            // 4 above is the magic number meaning that both
            // port numbers are included in the ICMP.
            src_port = dst_port = 0;
            bad_hdr_len = 1;
        }
    }

    static auto icmp_context = id::find_type<RecordType>("icmp_context");
    auto iprec = make_intrusive<zeek::RecordVal>(icmp_context);
    auto id_val = make_intrusive<zeek::RecordVal>(id::conn_id);

    id_val->Assign(0, make_intrusive<AddrVal>(src_addr));
    id_val->Assign(1, val_mgr->Port(src_port, proto));
    id_val->Assign(2, make_intrusive<AddrVal>(dst_addr));
    id_val->Assign(3, val_mgr->Port(dst_port, proto));

    iprec->Assign(0, std::move(id_val));
    iprec->Assign(1, val_mgr->Count(ip_len));
    iprec->Assign(2, val_mgr->Count(proto));
    iprec->Assign(3, val_mgr->Count(frag_offset));
    iprec->Assign(4, val_mgr->Bool(bad_hdr_len));
    iprec->Assign(5, val_mgr->Bool(bad_checksum));
    iprec->Assign(6, val_mgr->Bool(MF));
    iprec->Assign(7, val_mgr->Bool(DF));

    return iprec;
}

bool RnaIcmpContextAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    auto rna_packet = static_cast<RnaPacket*>(packet);
    auto offloader_hdr = rna_packet->GetOffloaderHdr();
    auto icmp_hdr = (const icmp_context_msg_h*)offloader_hdr->GetPayload();

    auto conn = offloader_hdr->GetOrCreateConnection(packet);

    EventHandlerPtr e;
    switch (icmp_hdr->itype) {
        case ICMP_DEST_UNREACH:
            e = icmp_unreachable;
            break;
        case ICMP_TIME_EXCEEDED:
            e = icmp_time_exceeded;
            break;
        default:
            return false;
    }

    const uint8_t* context = data + 2;

#ifdef RNA_ICMP_CONTEXT_DEBUG
    std::cout << std::endl;
    std::cout << "[RNA] START ICMP Context Msg!!! \\/ \\/ \\/" << std::endl;
    std::cout << "[RNA] |- src_addr = " << packet->ip_hdr->SrcAddr().AsString() << std::endl;
    std::cout << "[RNA] |- dst_addr = " << packet->ip_hdr->DstAddr().AsString() << std::endl;
    std::cout << "[RNA] |- src_port = " << offloader_hdr->GetSrcPort() << std::endl;
    std::cout << "[RNA] |- dst_port = " << offloader_hdr->GetDstPort() << std::endl;
    std::cout << "[RNA] |- itype    = " << (uint)icmp_hdr->itype << std::endl;
    std::cout << "[RNA] |- icode    = " << (uint)icmp_hdr->icode << std::endl;
    std::cout << "[RNA] |- ttl      = " << (uint)offloader_hdr->GetIPHdr()->TTL() << std::endl;
    std::cout << "[RNA] END   ICMP Context Msg!!!   /\\ /\\ /\\" << std::endl;
    std::cout << std::endl;
#endif

    if (e) {
        event_mgr.Enqueue(
            e, conn->GetVal(),
            BuildInfo(icmp_hdr, len - sizeof(icmp_context_msg_h), offloader_hdr->GetIPHdr()->TTL()),
            val_mgr->Count(icmp_hdr->icode), ExtractICMP4Context(len - 2, context));
    }

    packet->processed = true;

    return true;
}
