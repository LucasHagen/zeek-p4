#pragma once

#include "zeek/packet_analysis/Analyzer.h"
#include "ZpoEventHdr.h"

namespace zeek::packet_analysis::BR_INF_UFRGS_ZPO::ICMP {

using namespace zeek::packet_analysis;

#pragma pack(1)
typedef struct z_icmp_info_struct {
    uint8_t  v6;     // 1
    uint64_t itype;  // 8
    uint64_t icode;  // 8
    uint64_t len;    // 8
    uint64_t ttl;    // 8

    // Total bytes: 33 bytes
} z_icmp_info;

#pragma pack(1)
typedef struct z_icmp_echo_and_reply_event_struct  {
    uint64_t id;     // 8
    uint64_t seq;    // 8
    uint8_t  v6;     // 1
    uint64_t itype;  // 8
    uint64_t icode;  // 8
    uint64_t len;    // 8
    uint64_t ttl;    // 8

    // Total: 49 bytes
} z_icmp_echo_and_reply_event_t;

/**
 * @brief Analyzer for the ZPO Event Header (ZpoEventHdr).
 *
 */
class ZpoIcmpAnalyzer : public Analyzer {
public:
    ZpoIcmpAnalyzer();
    ~ZpoIcmpAnalyzer() override = default;

    static zeek::packet_analysis::AnalyzerPtr Instantiate() { return std::make_shared<ZpoIcmpAnalyzer>(); }

    bool AnalyzePacket(size_t len, const uint8_t* data, zeek::Packet* packet) override;
};

}  // namespace zeek::packet_analysis::BR_INF_UFRGS_ZPO
