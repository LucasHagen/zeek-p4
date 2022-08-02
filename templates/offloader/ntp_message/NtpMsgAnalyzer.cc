#include "NtpMsgAnalyzer.h"

#include <iostream>

#include "RnaOffloaderHdr.h"
#include "RnaPacket.h"
#include "constants.h"
#include "zeek/Conn.h"
#include "zeek/Event.h"
#include "zeek/IPAddr.h"
#include "zeek/analyzer/protocol/ntp/events.bif.h"

using namespace zeek::packet_analysis::BR_UFRGS_INF::RNA::NTP;

using ::zeek::AddrVal;
using ::zeek::AddrValPtr;
using ::zeek::IPAddr;
using ::zeek::Layer3Proto;
using ::zeek::Packet;
using ::zeek::StringVal;
using ::zeek::StringValPtr;
using ::zeek::packet_analysis::Analyzer;

NtpMsgAnalyzer::NtpMsgAnalyzer() : Analyzer("RNA_NTP") { interp = new binpac::NTP::NTP_Conn(this); }

NtpMsgAnalyzer::~NtpMsgAnalyzer() { delete interp; }

bool NtpMsgAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    auto rna_packet = static_cast<RnaPacket*>(packet);
    auto event_hdr = rna_packet->GetOffloaderHdr();
    auto ntp_message_hdr = (const ntp_message_h*)data;
    auto payload = data + sizeof(ntp_message_h);
    auto payload_len = len - sizeof(ntp_message_h);

    bool should_flip = ntp_message_hdr->type == RNA_NTP_MESSAGE_REPLY;

    // auto conn = event_hdr->GetOrCreateConnection(packet,
    //                                              /* is_one_way = */ false,
    //                                              /* flip_roles = */ should_flip);

    bool is_request;
    switch (ntp_message_hdr->type) {
        case RNA_NTP_MESSAGE_REQUEST:
            is_request = true;
            break;
        case RNA_NTP_MESSAGE_REPLY:
            is_request = false;
            break;
        default:
            // is_request = packet->is_orig;
            break;
    }

#define RNA_UDP_DEBUG
#ifdef RNA_UDP_DEBUG
    std::cout << "[RNA] NTP Message:" << std::endl;
    std::cout << " |_ type     = " << (is_request ? "request" : "reply") << std::endl;
    std::cout << " |_ src_addr = " << packet->ip_hdr->SrcAddr().AsString() << std::endl;
    std::cout << " |_ dst_addr = " << packet->ip_hdr->DstAddr().AsString() << std::endl;
    std::cout << " |_ src_port = " << event_hdr->GetSrcPort() << std::endl;
    std::cout << " |_ dst_port = " << event_hdr->GetDstPort() << std::endl;
    // std::cout << " |_ packet->is_orig = " << packet->is_orig << std::endl;
#endif

    // Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

    try {
        interp->NewData(orig, data, data + len);
    } catch (const binpac::Exception& e) {
        AnalyzerViolation(util::fmt("Binpac exception: %s", e.c_msg()));
    }

    std::cout << "[RNA] END NTP" << std::endl;

    return true;
}

// return ForwardPacket(payload_len, payload, packet, 123);
}
