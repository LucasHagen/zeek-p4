#include "ZPOEventAnalyzer.h"

#include "zeek/Event.h"
#include "zeek/Val.h"
#include "zeek/Sessions.h"

using namespace zeek::packet_analysis::BR_INF_UFRGS_ZPO;

using ::zeek::packet_analysis;

typedef struct event_t_struct {
    uint32_t pkt_num; 	// 4 bytes
    uint16_t protocol;	// 2
    uint32_t src_addr;	// 4
    uint32_t dst_addr;	// 4
    uint16_t src_port;	// 2
    uint16_t dst_port;	// 2
    uint16_t type;    	// 2
} event_t;

ZPOEventAnalyzer::ZPOEventAnalyzer() : Analyzer("ZPOEventAnalyzer") {
}

bool BuildConnTuple(size_t len, const uint8_t* data, Packet* packet, ConnTuple& tuple)
{
	const event_t* event_hdr = (const event_t*)data;
	const in4_addr* src_addr = (const in4_addr*)event_hdr->src_addr;
	const in4_addr* dst_addr = (const in4_addr*)event_hdr->src_addr;

	tuple.src_addr = IPAddr(*src_addr);
	tuple.dst_addr = IPAddr(*dst_addr);
	tuple.src_port = htons(event_hdr->src_port);
	tuple.dst_port = htons(event_hdr->dst_port);

	// TODO: properly set transport protocol
	tuple.proto = TRANSPORT_UNKNOWN;

	return true;
}

bool ZPOEventAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, zeek::Packet* packet) {
	std::cout << "[ZPO] AnalyzePacket!!!     \\/ \\/ \\/";

	const event_t* event_hdr = (const event_t*)data;
	const in4_addr* src_addr = (const in4_addr*)event_hdr->src_addr;
	const in4_addr* dst_addr = (const in4_addr*)event_hdr->src_addr;

	tuple.src_addr = IPAddr(*src_addr);
	tuple.dst_addr = IPAddr(*dst_addr);
	tuple.src_port = htons(event_hdr->src_port);
	tuple.dst_port = htons(event_hdr->dst_port);

	std::cout << "[ZPO] src_addr = " << tuple.src_addr << std::endl;
	std::cout << "[ZPO] dst_addr = " << tuple.dst_addr << std::endl;
	std::cout << "[ZPO] src_port = " << tuple.src_port << std::endl;
	std::cout << "[ZPO] dst_port = " << tuple.dst_port << std::endl;


	std::cout << "[ZPO] END AnalyzePacket!!! /\\ /\\ /\\";

	// return ForwardPacket(len - layer_size, data + layer_size, packet, 0x0800);
	return false;
}
