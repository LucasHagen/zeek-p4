#include "RnaOffloaderAnalyzer.h"

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

// #define RNA_OFFLOADER_DEBUG

RnaOffloaderAnalyzer::RnaOffloaderAnalyzer() : Analyzer("RNA_OFFLOADER") {}

std::shared_ptr<RnaOffloaderHdr> RnaOffloaderAnalyzer::MakeOffloaderHdr(std::shared_ptr<RnaHdr> rna_hdr,
                                                            const uint8_t* data) {
    switch (rna_hdr->GetRnaType()) {
        case RNA_P_ETH_OFFLOADER:
            return RnaOffloaderHdr::InitEthOffloaderHdr(data);
        case RNA_P_IPV4_OFFLOADER:
            return RnaOffloaderHdr::InitIpv4OffloaderHdr(data);
        case RNA_P_IPV6_OFFLOADER:
            return RnaOffloaderHdr::InitIpv6OffloaderHdr(data);
        default:
            return nullptr;
    }
}

bool RnaOffloaderAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    RnaPacket* rna_packet = static_cast<RnaPacket*>(packet);

    std::shared_ptr<RnaHdr> rna_hdr = rna_packet->GetRnaHdr();
    std::shared_ptr<RnaOffloaderHdr> offloader_hdr = MakeOffloaderHdr(rna_hdr, data);

    if (!offloader_hdr) {
        std::cerr << "[RNA_Offloader] Received Packet without a OffloaderHdr!" << std::endl;
        // Not an offloader packet
        return false;
    }

    rna_packet->SetOffloaderHdr(offloader_hdr);

#ifdef RNA_OFFLOADER_DEBUG
    std::cout << "[RNA_Offloader] RnaOffloaderAnalyzer Received:" << std::endl;
    std::cout << "[RNA_Offloader] |_ src_addr = " << offloader_hdr->GetSrcAddress().AsString() << std::endl;
    std::cout << "[RNA_Offloader] |_ dst_addr = " << offloader_hdr->GetDstAddress().AsString() << std::endl;
    std::cout << "[RNA_Offloader] |_ src_port = " << offloader_hdr->GetSrcPort() << std::endl;
    std::cout << "[RNA_Offloader] |_ dst_port = " << offloader_hdr->GetDstPort() << std::endl;
    std::cout << "[RNA_Offloader] |_ l3_proto = " << offloader_hdr->GetLayer3Protocol() << std::endl;
    std::cout << "[RNA_Offloader] |_ l4_proto = " << (uint16_t)offloader_hdr->GetLayer4Protocol()
              << std::endl;
    std::cout << "[RNA_Offloader] |_ offloader_id = " << offloader_hdr->GetOffloaderType() << std::endl;
    std::cout << std::endl;
#endif

    return ForwardPacket(len - offloader_hdr->GetHdrSize(), offloader_hdr->GetPayload(), rna_packet,
                         offloader_hdr->GetOffloaderType());
}
