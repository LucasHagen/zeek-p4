module PacketAnalyzer::ETHERNET;

@load-plugin Zeek::TCP
@load-plugin Zeek::UDP
@load-plugin Zeek::ICMP
@load base/frameworks/files
@load base/frameworks/notice
@load frameworks/files/hash-all-files

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

event icmp_echo_request(c: connection, info: icmp_info, id: count, seq: count, payload: string)
{
	print "Echo Request", c$id$orig_h, c$id$resp_h, id, seq;
}

event icmp_echo_reply(c: connection, info: icmp_info, id: count, seq: count, payload: string)
{
	print "Echo Reply", c$id$orig_h, c$id$resp_h, id, seq;
}
