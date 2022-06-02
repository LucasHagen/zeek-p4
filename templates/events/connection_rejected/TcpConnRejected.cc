#include <iostream>

#include "RnaEventHdr.h"
#include "RnaPacket.h"
#include "UdpReqOrRep.h"
#include "constants.h"
#include "zeek/Conn.h"
#include "zeek/Event.h"
#include "zeek/IPAddr.h"
#include "zeek/analyzer/protocol/tcp/events.bif"

using namespace zeek::packet_analysis::BR_UFRGS_INF::RNA::TCP;

using ::zeek::AddrVal;
using ::zeek::AddrValPtr;
using ::zeek::IPAddr;
using ::zeek::Layer3Proto;
using ::zeek::Packet;
using ::zeek::StringVal;
using ::zeek::StringValPtr;
using ::zeek::packet_analysis::Analyzer;


TcpConnRejected::TcpConnRejected() : Analyzer("TCP_CONN_REJ") {}

bool TcpConnRejected::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    auto rna_packet = static_cast<RnaPacket*>(packet);
    auto event_hdr = rna_packet->GetEventHdr();

    auto conn = event_hdr->GetOrCreateConnection(packet);

// #define RNA_UDP_DEBUG
#ifdef RNA_UDP_DEBUG
    std::cout << "[RNA] TCP Connection Rejected:" << std::endl;
    std::cout << " |_ src_addr = " << packet->ip_hdr->SrcAddr().AsString() << std::endl;
    std::cout << " |_ dst_addr = " << packet->ip_hdr->DstAddr().AsString() << std::endl;
    std::cout << " |_ src_port = " << event_hdr->GetSrcPort() << std::endl;
    std::cout << " |_ dst_port = " << event_hdr->GetDstPort() << std::endl;
#endif

    event_mgr.Enqueue(udp_request, conn->GetVal());

    packet->processed = true;

    return true;
}
