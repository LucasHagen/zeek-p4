#pragma once

#include "zeek/packet_analysis/Analyzer.h"

namespace zeek::packet_analysis::BR_UFRGS_INF::RNA::ICMP {

#pragma pack(1)
typedef struct icmp_echo_message_struct {
    uint16_t id;    // 2 bytes
    uint16_t seq;   // 2 bytes
    uint8_t  itype; // 1 bytes
    uint8_t  icode; // 1 bytes
    uint16_t len;   // 2 bytes
    uint8_t  ttl;   // 1 bytes

    // Total: 9 bytes
} icmp_echo_message_h;

using AnalyzerPtr = std::shared_ptr<Analyzer>;
class IcmpSessionAdapter;

class RnaIcmpEchoAnalyzer : public Analyzer {
public:
    RnaIcmpEchoAnalyzer();
    ~RnaIcmpEchoAnalyzer() override = default;

    static AnalyzerPtr Instantiate() { return std::make_shared<RnaIcmpEchoAnalyzer>(); }

    bool AnalyzePacket(size_t len, const uint8_t* data, zeek::Packet* packet) override;
};

}  // namespace zeek::packet_analysis::BR_UFRGS_INF::RNA::ICMP
