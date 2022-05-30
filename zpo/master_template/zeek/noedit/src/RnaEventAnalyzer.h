#pragma once

#include <memory>

#include "zeek/packet_analysis/Analyzer.h"
#include "RnaEventHdr.h"
#include "RnaHdr.h"

namespace zeek::packet_analysis::BR_UFRGS_INF::RNA {

using namespace zeek::packet_analysis;

/**
 * @brief Analyzer for the RNA Event Header (RnaEventHdr).
 */
class RnaEventAnalyzer : public Analyzer {
public:
    RnaEventAnalyzer();
    ~RnaEventAnalyzer() override = default;

    static zeek::packet_analysis::AnalyzerPtr Instantiate() {
        return std::make_shared<RnaEventAnalyzer>();
    }

    bool AnalyzePacket(size_t len, const uint8_t* data, zeek::Packet* packet) override;

protected:
    std::shared_ptr<RnaEventHdr> MakeEventHdr(std::shared_ptr<RnaHdr> rna_hdr, const uint8_t* data);
};

}  // namespace zeek::packet_analysis::BR_UFRGS_INF::RNA
