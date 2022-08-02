#pragma once

#include <netinet/ether.h>
#include <netinet/ip.h>

#include "zeek/Conn.h"
#include "zeek/packet_analysis/Analyzer.h"

#include "zeek/analyzer/protocol/ntp/events.bif.h"
#include "zeek/analyzer/protocol/ntp/types.bif.h"
#include "zeek/analyzer/protocol/ntp/ntp_pac.h"

namespace zeek::packet_analysis::BR_UFRGS_INF::RNA::NTP {

using namespace zeek::packet_analysis;

#define RNA_NTP_MESSAGE_REQUEST 0
#define RNA_NTP_MESSAGE_REPLY 1
#define RNA_NTP_MESSAGE_CONN 2  // both use port 123 - decide based on connection origin

#pragma pack(1)
typedef struct ntp_message_struct {
    uint8_t type;
} ntp_message_h;

class NtpMsgAnalyzer : public Analyzer {
public:
    NtpMsgAnalyzer();
    ~NtpMsgAnalyzer() override = default;

    static zeek::packet_analysis::AnalyzerPtr Instantiate() {
        return std::make_shared<NtpMsgAnalyzer>();
    }

    bool AnalyzePacket(size_t len, const uint8_t* data, zeek::Packet* packet) override;

protected:
	binpac::NTP::NTP_Conn* interp;
};

}  // namespace zeek::packet_analysis::BR_UFRGS_INF::RNA::NTP
