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
using ::detail::ConnKey;
using ::zeek::Packet;

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

bool ZPO::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
	const event_t* event_hdr = (const event_t*)data;

	IPAddr src_addr = IPAddr(ip(event_hdr->src_addr));
	IPAddr dst_addr = IPAddr(ip(event_hdr->dst_addr));
	uint16_t src_port = htons(event_hdr->src_port);
	uint16_t dst_port = htons(event_hdr->dst_port);

	std::cout << std::endl << "[ZPO] AnalyzePacket!!!     \\/ \\/ \\/" << std::endl;
	std::cout << "[ZPO] |- src_addr = " << src_addr.AsString() << std::endl;
	std::cout << "[ZPO] |- dst_addr = " << dst_addr.AsString() << std::endl;
	std::cout << "[ZPO] |- src_port = " << src_port << std::endl;
	std::cout << "[ZPO] |- dst_port = " << dst_port << std::endl;
	std::cout << "[ZPO] END AnalyzePacket!!! /\\ /\\ /\\" << std::endl << std::endl;

	// TODO: use proper transport protocol
	ConnKey key = BuildConnKey(src_addr, dst_addr, src_port, dst_port, TRANSPORT_UNKNOWN);

	Connection* conn = session_mgr->FindConnection(key);

	if (!conn) {
		conn = NewConn(&tuple, key, pkt);

		if (conn) {
			session_mgr->Insert(conn, false);
		}
	} else {
		if (conn->IsReuse(run_state::processing_start_time, ip_hdr->Payload())) {
			conn->Event(connection_reused, nullptr);

			session_mgr->Remove(conn);
			conn = NewConn(&tuple, key, pkt);
			if (conn) {
				session_mgr->Insert(conn, false);
			}
		} else {
			conn->CheckEncapsulation(pkt->encap);
		}
	}

	if (!conn) {
		return false;
	}

	// If we successfuly made a connection for this packet that means it'll eventually
	// get logged, which means we can mark this packet as having been processed.
	pkt->processed = true;

	bool is_orig = (tuple.src_addr == conn->OrigAddr()) && (tuple.src_port == conn->OrigPort());
	pkt->is_orig = is_orig;

	conn->CheckFlowLabel(is_orig, ip_hdr->FlowLabel());

	zeek::ValPtr pkt_hdr_val;

	if (ipv6_ext_headers && ip_hdr->NumHeaders() > 1) {
		pkt_hdr_val = ip_hdr->ToPktHdrVal();
		conn->EnqueueEvent(ipv6_ext_headers, nullptr, conn->GetVal(), pkt_hdr_val);
	}

	if (new_packet) {
		conn->EnqueueEvent(new_packet, nullptr, conn->GetVal(),
		                   pkt_hdr_val ? std::move(pkt_hdr_val) : ip_hdr->ToPktHdrVal());
	}

	conn->SetRecordPackets(true);
	conn->SetRecordContents(true);

	const u_char* payload = pkt->ip_hdr->Payload();

	run_state::current_timestamp = run_state::processing_start_time;
	run_state::current_pkt = pkt;

	// TODO: Does this actually mean anything?
	if (conn->GetSessionAdapter()->Skipping()) {
		return true;
	}

	// return ForwardPacket(len - layer_size, data + layer_size, packet, 0x0800);
	return false;
}

ConnKey BuildConnKey(const IPAddr& src_addr, const zeek::IPAddr& dst_addr,
						 const uint32_t& src_port, const uint32_t& dst_port,
						 const TransportProto& transportProto)
{
	ConnTuple tuple;
	tuple.src_addr = src_addr;
	tuple.dst_addr = dst_addr;
	tuple.src_port = src_port;
	tuple.dst_port = dst_port;
	tuple.proto = transportProto;

	return ConnKey(tuple);
}
