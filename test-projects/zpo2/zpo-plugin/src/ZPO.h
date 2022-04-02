#pragma once

#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/Component.h"

namespace zeek::packet_analysis::BR_INF_UFRGS_ZPO {

using namespace zeek::packet_analysis;

class ZPO : public Analyzer {
public:
    ZPO();
    ~ZPO() override = default;

    static zeek::packet_analysis::AnalyzerPtr Instantiate() {
        return std::make_shared<ZPO>();
    }

    bool AnalyzePacket(size_t len, const uint8_t* data,
                       zeek::Packet* packet) override;
};

}  // namespace zeek::packet_analysis::BR_INF_UFRGS_ZPO
