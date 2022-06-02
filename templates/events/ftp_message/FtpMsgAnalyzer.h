#pragma once

#include <netinet/ether.h>
#include <netinet/ip.h>

#include "zeek/Conn.h"
#include "zeek/packet_analysis/Analyzer.h"

namespace zeek::packet_analysis::BR_UFRGS_INF::RNA::UDP {

using namespace zeek::packet_analysis;

#define RNA_FTP_MESSAGE_REQUEST 0
#define RNA_FTP_MESSAGE_REPLY   1
#define RNA_FTP_MESSAGE_CONN  2 // both use port 21 - decide based on connection origin

#pragma pack(1)
typedef struct ftp_message_event_struct {
    uint8_t type;
} ftp_message_event_h;

class FtpMsgAnalyzer : public Analyzer {
public:
    FtpMsgAnalyzer();
    ~FtpMsgAnalyzer() override = default;

    static zeek::packet_analysis::AnalyzerPtr Instantiate() {
        return std::make_shared<FtpMsgAnalyzer>();
    }

    bool AnalyzePacket(size_t len, const uint8_t* data, zeek::Packet* packet) override;
};

}  // namespace zeek::packet_analysis::BR_UFRGS_INF::RNA::UDP
