#pragma once

#include <netinet/ether.h>
#include <netinet/ip.h>

#include "zeek/Conn.h"
#include "zeek/packet_analysis/Analyzer.h"

namespace zeek::packet_analysis::BR_UFRGS_INF::RNA::UDP {

using namespace zeek::packet_analysis;

#pragma pack(1)
typedef struct udp_req_or_rep_event_struct {
    uint8_t _ignored;
} udp_req_or_rep_event_h;

class TcpConnRejected : public Analyzer {
public:
    TcpConnRejected();
    ~TcpConnRejected() override = default;

    static zeek::packet_analysis::AnalyzerPtr Instantiate() {
        return std::make_shared<TcpConnRejected>();
    }

    bool AnalyzePacket(size_t len, const uint8_t* data, zeek::Packet* packet) override;
};

}  // namespace zeek::packet_analysis::BR_UFRGS_INF::RNA::UDP
