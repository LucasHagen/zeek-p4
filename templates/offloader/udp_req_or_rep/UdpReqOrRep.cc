#include "UdpReqOrRep.h"

#include <iostream>

#include "RnaOffloaderHdr.h"
#include "RnaPacket.h"
#include "constants.h"
#include "zeek/Conn.h"
#include "zeek/Event.h"
#include "zeek/IPAddr.h"
#include "zeek/packet_analysis/protocol/udp/events.bif.h"

using namespace zeek::packet_analysis::BR_UFRGS_INF::RNA::UDP;

using ::zeek::AddrVal;
using ::zeek::AddrValPtr;
using ::zeek::IPAddr;
using ::zeek::Layer3Proto;
using ::zeek::Packet;
using ::zeek::StringVal;
using ::zeek::StringValPtr;
using ::zeek::packet_analysis::Analyzer;

constexpr uint32_t RNA_HIST_ORIG_DATA_PKT = 0x1;
constexpr uint32_t RNA_HIST_RESP_DATA_PKT = 0x2;

UdpRequestOrReplyAnalyzer::UdpRequestOrReplyAnalyzer() : Analyzer("REP_UDP_REP_REQ") {}

bool UdpRequestOrReplyAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    auto rna_packet = static_cast<RnaPacket*>(packet);
    auto offloader_hdr = rna_packet->GetOffloaderHdr();

    auto conn = offloader_hdr->GetOrCreateConnection(packet);

// #define RNA_UDP_DEBUG
#ifdef RNA_UDP_DEBUG
    std::cout << "[RNA] UDP Message:" << std::endl;
    std::cout << " |_ src_addr = " << packet->ip_hdr->SrcAddr().AsString() << std::endl;
    std::cout << " |_ dst_addr = " << packet->ip_hdr->DstAddr().AsString() << std::endl;
    std::cout << " |_ src_port = " << offloader_hdr->GetSrcPort() << std::endl;
    std::cout << " |_ dst_port = " << offloader_hdr->GetDstPort() << std::endl;
    std::cout << " |_ type     = " << (packet->is_orig ? "request" : "reply") << std::endl;
#endif

    if (packet->is_orig) {
        conn->CheckHistory(RNA_HIST_ORIG_DATA_PKT, 'D');
        event_mgr.Enqueue(udp_request, conn->GetVal());
    } else {
        conn->CheckHistory(RNA_HIST_RESP_DATA_PKT, 'd');
        event_mgr.Enqueue(udp_reply, conn->GetVal());
    }

    packet->processed = true;

    return true;
}
