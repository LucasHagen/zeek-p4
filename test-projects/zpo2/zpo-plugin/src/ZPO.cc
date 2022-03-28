#include "ZPO.h"

#include <iostream>

#include "zeek/Event.h"
#include "zeek/Val.h"
#include "zeek/Sessions.h"
#include "zeek/IPAddr.h"

using namespace zeek::packet_analysis::BR_INF_UFRGS_ZPO;

typedef struct event_t_struct {
    uint32_t pkt_num; 	// 4 bytes
    uint16_t protocol;	// 2
    uint32_t src_addr;	// 4
    uint32_t dst_addr;	// 4
    uint16_t src_port;	// 2
    uint16_t dst_port;	// 2
    uint16_t type;    	// 2
} event_t;

ZPO::ZPO() : zeek::packet_analysis::Analyzer("ZPO") {
}

bool ZPO::AnalyzePacket(size_t len, const uint8_t* data, zeek::Packet* packet) {
	std::cout << "[ZPO] AnalyzePacket!!!     \\/ \\/ \\/";

	const event_t* event_hdr = (const event_t*)data;

	IPAddr src_addr = IPAddr(in4_addr { event_hdr->src_addr });
	IPAddr dst_addr = IPAddr(in4_addr { event_hdr->dst_addr });
	uint16_t src_port = htons(event_hdr->src_port);
	uint16_t dst_port = htons(event_hdr->dst_port);

	std::cout << "[ZPO] src_addr = " << src_addr.AsString() << std::endl;
	std::cout << "[ZPO] dst_addr = " << dst_addr.AsString() << std::endl;
	std::cout << "[ZPO] src_port = " << src_port << std::endl;
	std::cout << "[ZPO] dst_port = " << dst_port << std::endl;


	std::cout << "[ZPO] END AnalyzePacket!!! /\\ /\\ /\\";

	// return ForwardPacket(len - layer_size, data + layer_size, packet, 0x0800);
	return false;
}


/*
bool BuildConnTuple(size_t len, const uint8_t* data, Packet* packet, ConnTuple& tuple)
{
	const event_t* event_hdr = (const event_t*)data;

	tuple.src_addr = IPAddr(in4_addr { event_hdr->src_addr });
	tuple.dst_addr = IPAddr(in4_addr { event_hdr->dst_addr });
	tuple.src_port = htons(event_hdr->src_port);
	tuple.dst_port = htons(event_hdr->dst_port);

	// TODO: properly set transport protocol
	tuple.proto = TRANSPORT_UNKNOWN;

	return true;
}
*/
