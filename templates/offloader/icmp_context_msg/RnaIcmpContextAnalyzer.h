#pragma once

#include "zeek/packet_analysis/Analyzer.h"

namespace zeek::packet_analysis::BR_UFRGS_INF::RNA::ICMP {

#pragma pack(1)
typedef struct icmp_context_msg_struct {
    uint8_t itype;
    uint8_t icode;
    struct ip context_ipv4;
} icmp_context_msg_h;

using AnalyzerPtr = std::shared_ptr<Analyzer>;
class IcmpSessionAdapter;

class RnaIcmpContextAnalyzer : public Analyzer {
public:
    RnaIcmpContextAnalyzer();
    ~RnaIcmpContextAnalyzer() override = default;

    static AnalyzerPtr Instantiate() { return std::make_shared<RnaIcmpContextAnalyzer>(); }

    bool AnalyzePacket(size_t len, const uint8_t* data, zeek::Packet* packet) override;

private:
    RecordValPtr BuildInfo(const icmp_context_msg_h* icmp, size_t len, uint8_t ttl);
    int ICMP4_counterpart(int icmp_type, int icmp_code, bool& is_one_way);
    TransportProto GetContextProtocol(const IP_Hdr* ip_hdr, uint32_t* src_port, uint32_t* dst_port);
    zeek::RecordValPtr ExtractICMP4Context(int len, const u_char*& data);
};

}  // namespace zeek::packet_analysis::BR_UFRGS_INF::RNA::ICMP
