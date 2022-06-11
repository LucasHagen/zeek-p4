#pragma once

#include <memory>

#include "zeek/packet_analysis/Analyzer.h"
#include "RnaOffloaderHdr.h"
#include "RnaHdr.h"

namespace zeek::packet_analysis::BR_UFRGS_INF::RNA {

using namespace zeek::packet_analysis;

/**
 * @brief Analyzer for the RNA Offloader Header (RnaOffloaderHdr).
 */
class RnaOffloaderAnalyzer : public Analyzer {
public:
    RnaOffloaderAnalyzer();
    ~RnaOffloaderAnalyzer() override = default;

    static zeek::packet_analysis::AnalyzerPtr Instantiate() {
        return std::make_shared<RnaOffloaderAnalyzer>();
    }

    bool AnalyzePacket(size_t len, const uint8_t* data, zeek::Packet* packet) override;

protected:
    std::shared_ptr<RnaOffloaderHdr> MakeOffloaderHdr(std::shared_ptr<RnaHdr> rna_hdr, const uint8_t* data);
};

}  // namespace zeek::packet_analysis::BR_UFRGS_INF::RNA
