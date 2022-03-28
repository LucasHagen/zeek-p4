@load-plugin Zeek::ICMP
@load-plugin Zeek::TCP
@load-plugin Zeek::UDP

export {}


event zeek_init() &priority=20
{
    print "Initializing ZPO Script...";
    print "Registering PacketAnalyzer...";
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERNET, 0x6606, PacketAnalyzer::ANALYZER_ZPO);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ZPO, 0x0800, PacketAnalyzer::ANALYZER_IP);
    print "Registered PacketAnalyzer.";
	print "Initialized ZPO Plugin.";
}

event icmp_echo_request(C: connection, icmp: icmp_conn, info: icmp_info, id: count, seq: count, payload: string)
{
	print "Echo Request", C$id$orig_h, C$id$resp_h, id, seq;
}

event icmp_echo_reply(C: connection, icmp: icmp_conn, info: icmp_info, id: count, seq: count, payload: string)
{
	print "Echo Reply", C$id$orig_h, C$id$resp_h, id, seq;
}
