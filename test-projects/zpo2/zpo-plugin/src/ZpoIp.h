#pragma once

#include "zeek/packet_analysis/Analyzer.h"
#include "ZpoEventHdr.h"

namespace zeek::packet_analysis::BR_INF_UFRGS_ZPO {

using namespace zeek::packet_analysis;

/**
 * @brief Analyzer for the ZPO Event Header (ZpoEventHdr).
 */
class ZpoIp : public Analyzer {
public:
    ZpoIp();
    ~ZpoIp() override = default;

    static zeek::packet_analysis::AnalyzerPtr Instantiate() { return std::make_shared<ZpoIp>(); }

    bool AnalyzePacket(size_t len, const uint8_t* data, zeek::Packet* packet) override;
};

}  // namespace zeek::packet_analysis::BR_INF_UFRGS_ZPO
