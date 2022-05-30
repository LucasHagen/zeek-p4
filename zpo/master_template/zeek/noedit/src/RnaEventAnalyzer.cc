#include "RnaEventAnalyzer.h"

#include <netinet/ether.h>

#include <iostream>
#include <memory>

#include "RnaPacket.h"
#include "zeek/Conn.h"
#include "zeek/IPAddr.h"

using namespace zeek::packet_analysis::BR_UFRGS_INF::RNA;
using ::zeek::IPAddr;
using ::zeek::Layer3Proto;
using ::zeek::Packet;
using ::zeek::packet_analysis::Analyzer;

// #define RNA_EVENT_DEBUG

RnaEventAnalyzer::RnaEventAnalyzer() : Analyzer("RNA_EVENT") {}

std::shared_ptr<RnaEventHdr> RnaEventAnalyzer::MakeEventHdr(std::shared_ptr<RnaHdr> rna_hdr,
                                                            const uint8_t* data) {
    switch (rna_hdr->GetRnaType()) {
        case RNA_P_ETH_EVENT:
            return RnaEventHdr::InitEthEventHdr(data);
        case RNA_P_IPV4_EVENT:
            return RnaEventHdr::InitIpv4EventHdr(data);
        case RNA_P_IPV6_EVENT:
            return RnaEventHdr::InitIpv6EventHdr(data);
        default:
            return nullptr;
    }
}

bool RnaEventAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    RnaPacket* rna_packet = static_cast<RnaPacket*>(packet);

    std::shared_ptr<RnaHdr> rna_hdr = rna_packet->GetRnaHdr();
    std::shared_ptr<RnaEventHdr> event_hdr = MakeEventHdr(rna_hdr, data);

    if (!event_hdr) {
        std::cerr << "[RNA_Event] Received Packet without a EventHdr!" << std::endl;
        // Not an event packet
        return false;
    }

    rna_packet->SetEventHdr(event_hdr);

#ifdef RNA_EVENT_DEBUG
    std::cout << "[RNA_Event] RnaEventAnalyzer Received:" << std::endl;
    std::cout << "[RNA_Event] |_ src_addr = " << event_hdr->GetSrcAddress().AsString() << std::endl;
    std::cout << "[RNA_Event] |_ dst_addr = " << event_hdr->GetDstAddress().AsString() << std::endl;
    std::cout << "[RNA_Event] |_ src_port = " << event_hdr->GetSrcPort() << std::endl;
    std::cout << "[RNA_Event] |_ dst_port = " << event_hdr->GetDstPort() << std::endl;
    std::cout << "[RNA_Event] |_ l3_proto = " << event_hdr->GetLayer3Protocol() << std::endl;
    std::cout << "[RNA_Event] |_ l4_proto = " << (uint16_t)event_hdr->GetLayer4Protocol()
              << std::endl;
    std::cout << "[RNA_Event] |_ event_id = " << event_hdr->GetEventType() << std::endl;
    std::cout << std::endl;
#endif

    return ForwardPacket(len - event_hdr->GetHdrSize(), event_hdr->GetPayload(), rna_packet,
                         event_hdr->GetEventType());
}
