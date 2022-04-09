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
    print "Initializing ZPO Plugin...";

	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERNET, 0x6601, PacketAnalyzer::ANALYZER_ZPO_ETH);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERNET, 0x6602, PacketAnalyzer::ANALYZER_ZPO_IP);
    print "Registered Main PacketAnalyzers.";

	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ZPO_IP, 0x0001, PacketAnalyzer::ANALYZER_ZPO_ICMP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ZPO_IP, 0x0002, PacketAnalyzer::ANALYZER_ZPO_ICMP);
    print "Registered Event PacketAnalyzers.";

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
