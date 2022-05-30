#pragma once

#include "zeek/packet_analysis/Analyzer.h"
#include "RnaHdr.h"

namespace zeek::packet_analysis::BR_UFRGS_INF::RNA {

using namespace zeek::packet_analysis;

/**
 * @brief Analyzer for RNA.
 */
class RnaAnalyzer : public Analyzer {
public:
    RnaAnalyzer();
    ~RnaAnalyzer() override = default;

    static zeek::packet_analysis::AnalyzerPtr Instantiate() {
        return std::make_shared<RnaAnalyzer>();
    }

    bool AnalyzePacket(size_t len, const uint8_t* data, zeek::Packet* packet) override;
};

}  // namespace zeek::packet_analysis::BR_UFRGS_INF::RNA
