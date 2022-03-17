module PacketAnalyzer::ETHERNET;

@load-plugin Zeek::TCP
@load-plugin Zeek::UDP
@load-plugin Zeek::ICMP

export {

}

event zeek_init()
	{
	print "Initializing rna.zeek...";
	print "Initialized rna.zeek.";
	}

event icmp_echo_request(C: connection, info: icmp_info, id: count, seq: count, payload: string)
	{
	print "Echo Request", C$id$orig_h, C$id$resp_h, id, seq;
	# print C;
	}

event icmp_echo_reply(C: connection, info: icmp_info, id: count, seq: count, payload: string)
	{
	print "Echo Reply", C$id$orig_h, C$id$resp_h, id, seq;
	}

# TODO: Add ICMP Unreachable event handler.
# See doc/scripts/base/bif/plugins/Zeek_ICMP.events.bif.zeek.rst, line 509.
event icmp_unreachable(c: connection , info: icmp_info , code: count , context: icmp_context )
	{
	#print "ICMP Unreachable", c$id$orig_h, c$id$resp_h, info, code, context;
	print "ICMP Unreachable", context;
	}

event tcp_packet(C: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string)
	{
	print "TCP Packet", C$id$orig_h, C$id$resp_h, flags, seq;
	}

event udp_request(C: connection)
	{
	print "UDP Packet", C$id$orig_h, C$id$resp_h, C$id$orig_p, C$id$resp_p;
	}

event udp_reply(C: connection)
	{
	print "UDP Reply", C$id$orig_h, C$id$resp_h, C$id$orig_p, C$id$resp_p;
	}

event zeek_done()
	{
	print "Done!";
	}
