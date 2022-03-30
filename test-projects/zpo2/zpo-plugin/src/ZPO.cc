#include "ZPO.h"

#include <iostream>

#include "zeek/Conn.h"
#include "zeek/Desc.h"
#include "zeek/Event.h"
#include "zeek/Val.h"
#include "zeek/IPAddr.h"
#include "zeek/net_util.h"
#include "zeek/session/Manager.h"
#include "zeek/RunState.h"
#include "zeek/packet_analysis/protocol/ip/SessionAdapter.h"

#include "zeek/packet_analysis/protocol/icmp/events.bif.h"

using namespace zeek::packet_analysis::BR_INF_UFRGS_ZPO;
using ::zeek::ConnTuple;
using ::zeek::IPAddr;
using ::zeek::detail::ConnKey;
using ::zeek::Packet;
using ::zeek::Connection;
using ::zeek::make_intrusive;
using ::zeek::RecordType;
using ::zeek::val_mgr;

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

Connection* NewConn(const ConnTuple* id, const ConnKey& key,
                    const Packet* pkt, TransportProto transportProto) {
	int src_h = ntohs(id->src_port);
	int dst_h = ntohs(id->dst_port);

	Connection* conn = new Connection(key, zeek::run_state::processing_start_time, id,
	                                  /* flow=*/ 0, pkt);
	conn->SetTransport(transportProto);

	// BuildSessionAnalyzerTree(conn);

	if ( new_connection )
		conn->Event(new_connection, nullptr);

	return conn;
}

in4_addr ip(const uint8_t* ptr) {
	return in4_addr { (uint32_t) ( ptr[3] << 24 | ptr[2] << 16 | ptr[1] << 8 | ptr[0] ) };
}

zeek::RecordValPtr BuildInfo(int type, int code, int len, int ttl)
{
	static auto icmp_info = zeek::id::find_type<RecordType>("icmp_info");
	auto rval = make_intrusive<zeek::RecordVal>(icmp_info);
	rval->Assign(0, val_mgr->Bool(false));
	rval->Assign(1, val_mgr->Count(type));
	rval->Assign(2, val_mgr->Count(code));
	rval->Assign(3, val_mgr->Count(len));
	rval->Assign(4, val_mgr->Count(ttl));
	return rval;
}

bool ZPO::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
	const event_t* event_hdr = (const event_t*)data;

	IPAddr src_addr = IPAddr(ip(event_hdr->src_addr));
	IPAddr dst_addr = IPAddr(ip(event_hdr->dst_addr));
	uint16_t src_port = htons(event_hdr->src_port);
	uint16_t dst_port = htons(event_hdr->dst_port);
	// TODO: use proper transport protocol
	TransportProto transportProto = TRANSPORT_ICMP;

	std::cout << std::endl << "[ZPO] AnalyzePacket!!!     \\/ \\/ \\/" << std::endl;
	std::cout << "[ZPO] |- src_addr = " << src_addr.AsString() << std::endl;
	std::cout << "[ZPO] |- dst_addr = " << dst_addr.AsString() << std::endl;
	std::cout << "[ZPO] |- src_port = " << src_port << std::endl;
	std::cout << "[ZPO] |- dst_port = " << dst_port << std::endl;
	std::cout << "[ZPO] END AnalyzePacket!!! /\\ /\\ /\\" << std::endl << std::endl;

	ConnTuple tuple = BuildConnTuple(src_addr, dst_addr, src_port, dst_port, transportProto);
	ConnKey key(tuple);

	Connection* conn = session_mgr->FindConnection(key);

	if (!conn) {
		conn = NewConn(&tuple, key, packet, transportProto);

		if (conn) {
			session_mgr->Insert(conn, false);
		}
	} else {
		if (conn->IsReuse(run_state::processing_start_time, packet->ip_hdr->Payload())) {
			conn->Event(connection_reused, nullptr);

			session_mgr->Remove(conn);
			conn = NewConn(&tuple, key, packet, transportProto);
			if (conn) {
				session_mgr->Insert(conn, false);
			}
		} else {
			conn->CheckEncapsulation(packet->encap);
		}
	}

	if (!conn) {
		return false;
	}

	// If we successfuly made a connection for this packet that means it'll eventually
	// get logged, which means we can mark this packet as having been processed.
	packet->processed = true;

	bool is_orig = (tuple.src_addr == conn->OrigAddr()) && (tuple.src_port == conn->OrigPort());
	packet->is_orig = is_orig;

	zeek::ValPtr pkt_hdr_val;

	if (new_packet) {
		conn->EnqueueEvent(new_packet, nullptr, conn->GetVal(),
		                   pkt_hdr_val ? std::move(pkt_hdr_val) : packet->ip_hdr->ToPktHdrVal());
	}

	conn->SetRecordPackets(true);
	conn->SetRecordContents(true);

	const u_char* payload = packet->ip_hdr->Payload();

	run_state::current_timestamp = run_state::processing_start_time;
	run_state::current_pkt = packet;

	// TODO: Does this actually mean anything?
	if (conn->GetSessionAdapter()->Skipping()) {
		return true;
	}

	if (event_hdr->type == 1 /* TYPE_ICMP_ECHO_REPLY_EVENT */) {
		conn->EnqueueEvent(icmp_echo_reply,
			BuildInfo(1, 2, 3, 4),
			val_mgr->Count(5), val_mgr->Count(6), make_intrusive<StringVal>("ZPO PAYLOAD")
		);
	} else if(event_hdr->type == 2 /* TYPE_ICMP_ECHO_REQ_EVENT */) {
		conn->EnqueueEvent(icmp_echo_request,
			BuildInfo(1, 2, 3, 4),
			val_mgr->Count(5), val_mgr->Count(6), make_intrusive<StringVal>("ZPO PAYLOAD")
		);
	}



	// return ForwardPacket(len - layer_size, data + layer_size, packet, 0x0800);
	return false;
}
