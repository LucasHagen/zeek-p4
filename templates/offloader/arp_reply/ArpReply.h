#pragma once

#include <netinet/ether.h>
#include <netinet/ip.h>

#include "RnaOffloaderHdr.h"
#include "zeek/packet_analysis/Analyzer.h"

namespace zeek::packet_analysis::BR_UFRGS_INF::RNA::ARP {

using namespace zeek::packet_analysis;

#pragma pack(1)
typedef struct arp_ipv4_reply_struct {
    struct ether_addr mac_src;
    struct ether_addr mac_dst;
    struct ether_addr src_hw_addr;
    struct in_addr src_proto_addr;
    struct ether_addr target_hw_addr;
    struct in_addr target_proto_addr;
} arp_ipv4_reply;

class RnaArpReplyAnalyzer : public Analyzer {
public:
    RnaArpReplyAnalyzer();
    ~RnaArpReplyAnalyzer() override = default;

    static zeek::packet_analysis::AnalyzerPtr Instantiate() {
        return std::make_shared<RnaArpReplyAnalyzer>();
    }

    bool AnalyzePacket(size_t len, const uint8_t* data, zeek::Packet* packet) override;
};

}  // namespace zeek::packet_analysis::BR_UFRGS_INF::RNA::ARP
