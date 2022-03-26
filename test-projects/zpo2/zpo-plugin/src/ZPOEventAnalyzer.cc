#include "ZPOEventAnalyzer.h"

#include "zeek/Event.h"
#include "zeek/Val.h"
#include "zeek/Sessions.h"

using namespace plugin::BR_INF_UFRGS_ZPO;

ZPOEventAnalyzer::ZPOEventAnalyzer()
	: zeek::packet_analysis::IP::IPBasedAnalyzer(
    		"ZPOEventAnalyzer", TRANSPORT_UNKNOWN, PORT_SPACE_MASK, false
		) {

}

bool ZPOEventAnalyzer::BuildConnTuple(size_t len, const uint8_t* data, Packet* packet, ConnTuple& tuple)
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

void ZPOEventAnalyzer::DeliverPacket(Connection* conn, double t, bool is_orig, int remaining, Packet* pkt) {
	std::cout << "[ZPO] DeliverPacket!!!";
}

// bool ZPOEventAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
// {
//	constexpr auto layer_size = 18;	// See rna_headers.p4 ; this is the size of the event_t header.
//	if ( len <= layer_size )
//    {
//		sessions->Weird("truncated_event_header", packet);
//		return false;
//    }
//
//	// These are the event_t header fields and its corresponding CPP types.:
//	// uint32_t pkt_num  = *(data + 0);       // 4
//	// uint16_t protocol = *(data + 4);       // 2
//	// uint32_t src_addr = *(data + 6);       // 4
//	// uint32_t dst_addr = *(data + 10);      // 4
//	// uint16_t src_port = *(data + 14);      // 2
//	// uint16_t dst_port = *(data + 16);      // 2
//
//	// Raw pointers.
//	// zeek::AddrVal* src_addr = new zeek::AddrVal((uint32_t) (data[6]  << 24 | data[7]  << 16 | data[8]  << 8 | data[9]));
//	// zeek::AddrVal* dst_addr = new zeek::AddrVal((uint32_t) (data[10] << 24 | data[11] << 16 | data[12] << 8 | data[13]));
//
//	// Smart pointers.
//	auto src_addr = zeek::make_intrusive<zeek::AddrVal>((uint32_t)(data[9] << 24 | data[8] << 16 | data[7] << 8 | data[6]));
//	auto dst_addr = zeek::make_intrusive<zeek::AddrVal>((uint32_t)(data[13] << 24 | data[12] << 16 | data[11] << 8 | data[10]));
//
//		/*
//	case 0x01:
//			protocol_name = "ICMPv4";
//			break;
//		case 0x3a:
//			protocol_name = "ICMPv6";
//			break;
//		case 0x0800:
//			protocol_name = "IPv4";
//			break;
//		case 0x86dd:
//			protocol_name = "IPv6";
//			break;
//		case 0x06:
//			protocol_name = "TCP";
//			break;
//		case 0x11:
//			protocol_name = "UDP";
//			break;
//		default:
//*/
//
//		TransportProto transport;
//		switch (data[4] << 8 | data[5])
//			{
//			case 0x01:
//				transport = TRANSPORT_ICMP;
//				break;
//			case 0x06:
//				transport = TRANSPORT_TCP;
//				break;
//			case 0x11:
//				transport = TRANSPORT_UDP;
//				break;
//			default:
//				transport = TRANSPORT_UNKNOWN;
//			}
//
//	// See rna.sink/rna-plugin/build/rna.bif.cc
//	zeek::event_mgr.Enqueue(::rna_message, zeek::Args{
//				zeek::val_mgr->Count(data[0]  << 24 | data[1]  << 16 | data[2]  << 8 | data[3]), // pkt_num
//				zeek::val_mgr->Count(data[4]  << 8  | data[5]), 			// protocol
//				src_addr, 			// src_addr
//				dst_addr, 			// dst_addr
//				zeek::val_mgr->Port((uint32_t) data[14] << 8  | data[15], transport), 	// src_port
//				zeek::val_mgr->Port((uint32_t) data[16] << 8  | data[17], transport) 	// dst_port
//				},
//			zeek::util::detail::SOURCE_LOCAL); // this->zeek::analyzer::Analyzer::GetID());
//			// Remember: this is expensive!
//
//	// return true; // Without forwarding anything.
//
//	// We want to forward the packet to the next Analyzer in the chain.
//	// See src/packet_analysis/protocol/ethernet/Ethernet.cc.
//
//	// uint32_t protocol = (data[4]  << 8  | data[5]); // Converts from two 'uint8_t' to one 'uint16_t', then casts to 'uint32_t'.
//	// return ForwardPacket(len - layer_size, data + layer_size, packet, protocol); // Bug: This forwards the IP header to the ICMP Analyzer.
//	return ForwardPacket(len - layer_size, data + layer_size, packet, 0x0800); 					// There's probably a constant or enum for the 0x0800.
//	// return ForwardPacket(len - layer_size, data + layer_size, packet, zeek::Layer3Proto::L3_IPV4); 	// Got it! enum zeek::Layer3Proto defined in src/iosource/Packet.h.
//
// }
