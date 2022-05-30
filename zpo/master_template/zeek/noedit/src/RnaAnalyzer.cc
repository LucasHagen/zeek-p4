#include "RnaAnalyzer.h"

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

// #define RNA_DEBUG

RnaAnalyzer::RnaAnalyzer() : Analyzer("RNA") {}

bool RnaAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {

    std::shared_ptr<RnaHdr> hdr = std::make_shared<RnaHdr>(data, (const rna_header*)data);

#ifdef RNA_DEBUG
    std::cout << "[RNA] Received RNA Packet:" << std::endl;
    std::cout << "[RNA] |_ version  = " << hdr->GetVersion() << std::endl;
    std::cout << "[RNA] |_ rna_type = " << hdr->GetRnaType() << std::endl;
    std::cout << std::endl;
#endif

    std::shared_ptr<RnaPacket> rna_packet = std::make_shared<RnaPacket>(packet, hdr);
    return ForwardPacket(len - hdr->GetHdrSize(), hdr->GetPayload(), rna_packet.get(),
                         hdr->GetRnaType());
}
