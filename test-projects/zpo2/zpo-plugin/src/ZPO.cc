#include "ZPO.h"

#include <iostream>

#include "zeek/Conn.h"
#include "zeek/Desc.h"
#include "zeek/Event.h"
#include "zeek/Val.h"
#include "zeek/IPAddr.h"
#include "zeek/net_util.h"
#include "zeek/session/Manager.h"

using namespace zeek::packet_analysis::BR_INF_UFRGS_ZPO;
using ::zeek::ConnTuple;
using ::zeek::IPAddr;

typedef struct event_t_struct {
    uint32_t pkt_num; 		// 4
    uint16_t protocol;		// 2
    uint8_t  src_addr[4];	// 4
    uint8_t  dst_addr[4];	// 4
    uint16_t src_port;		// 2
    uint16_t dst_port;		// 2
    uint16_t type;    		// 2
} event_t;

ZPO::ZPO() : zeek::packet_analysis::Analyzer("ZPO") { }

in4_addr ip(const uint8_t* ptr) {
	return in4_addr { (uint32_t) ( ptr[3] << 24 | ptr[2] << 16 | ptr[1] << 8 | ptr[0] ) };
}

bool ZPO::AnalyzePacket(size_t len, const uint8_t* data, zeek::Packet* packet) {
	std::cout << std::endl << "[ZPO] AnalyzePacket!!!     \\/ \\/ \\/" << std::endl;

	const event_t* event_hdr = (const event_t*)data;

	IPAddr src_addr = IPAddr(ip(event_hdr->src_addr));
	IPAddr dst_addr = IPAddr(ip(event_hdr->dst_addr));
	uint16_t src_port = htons(event_hdr->src_port);
	uint16_t dst_port = htons(event_hdr->dst_port);

	std::cout << "[ZPO] |- src_addr = " << src_addr.AsString() << std::endl;
	std::cout << "[ZPO] |- dst_addr = " << dst_addr.AsString() << std::endl;
	std::cout << "[ZPO] |- src_port = " << src_port << std::endl;
	std::cout << "[ZPO] |- dst_port = " << dst_port << std::endl;


	std::cout << "[ZPO] END AnalyzePacket!!! /\\ /\\ /\\" << std::endl << std::endl;

	// return ForwardPacket(len - layer_size, data + layer_size, packet, 0x0800);
	return false;
}

ConnTuple BuildConnTuple(const IPAddr& src_addr, const zeek::IPAddr& dst_addr,
						 const uint32_t& src_port, const uint32_t& dst_port,
						 const TransportProto& transportProto)
{
	ConnTuple tuple;
	tuple.src_addr = src_addr;
	tuple.dst_addr = dst_addr;
	tuple.src_port = src_port;
	tuple.dst_port = dst_port;
	tuple.proto = transportProto;

	return tuple;
}
