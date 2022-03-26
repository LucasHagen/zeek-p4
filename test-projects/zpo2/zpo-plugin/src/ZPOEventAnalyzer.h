#pragma once

#include "zeek/packet_analysis/protocol/ip/IPBasedAnalyzer.h"

namespace plugin {
namespace BR_INF_UFRGS_ZPO {

using namespace zeek::packet_analysis;

typedef struct event_t_struct {
    uint32_t pkt_num; 	// 4 bytes
    uint16_t protocol;	// 2
    uint32_t src_addr;	// 4
    uint32_t dst_addr;	// 4
    uint16_t src_port;	// 2
    uint16_t dst_port;	// 2
    uint16_t type;    	// 2
} event_t;

class ZPOEventAnalyzer : IPBasedAnalyzer {

public:
	ZPOEventAnalyzer();
	~ZPOEventAnalyzer() override = default;

	// bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

	static zeek::packet_analysis::AnalyzerPtr Instantiate()
    {
		return std::make_shared<ZPOEventAnalyzer>();
    }


protected:
	/**
	 * Parse the header from the packet into a ConnTuple object.
	 */
	bool BuildConnTuple(size_t len, const uint8_t* data, Packet* packet, ConnTuple& tuple) override;

	void DeliverPacket(Connection* c, double t, bool is_orig, int remaining, Packet* pkt) override;
};

}
