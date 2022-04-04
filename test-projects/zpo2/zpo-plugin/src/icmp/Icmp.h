#pragma once

#include "zeek/analyzer/Analyzer.h"
#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/ip/IPBasedAnalyzer.h"
#include "zeek/packet_analysis/protocol/ip/SessionAdapter.h"

namespace zeek::packet_analysis::BR_INF_UFRGS_ZPO::ICMP {

#pragma pack(1)
typedef struct icmp_echo_and_reply_event_struct {
    uint64_t id;     // 8
    uint64_t seq;    // 8
    uint8_t v6;      // 1
    uint64_t itype;  // 8
    uint64_t icode;  // 8
    uint64_t len;    // 8
    uint64_t ttl;    // 8

    // Total: 49 bytes
} icmp_echo_and_reply_event_h;

using AnalyzerPtr = std::shared_ptr<Analyzer>;
class IcmpSessionAdapter;

class ZpoIcmpAnalyzer : public Analyzer {
public:
    ZpoIcmpAnalyzer();
    ~ZpoIcmpAnalyzer() override = default;

    static AnalyzerPtr Instantiate() { return std::make_shared<ZpoIcmpAnalyzer>(); }

    bool AnalyzePacket(size_t len, const uint8_t* data, zeek::Packet* packet) override;
};

}  // namespace zeek::packet_analysis::BR_INF_UFRGS_ZPO::ICMP
