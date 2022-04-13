module PacketAnalyzer::ETHERNET;

@load-plugin Zeek::TCP
@load-plugin Zeek::UDP
@load-plugin Zeek::ICMP
@load-plugin Zeek::ARP
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
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ZPO_ETH, 0x0003, PacketAnalyzer::ANALYZER_ZPO_ARP);
    print "Registered Event PacketAnalyzers.";

    print "Initialized ZPO Plugin.";
}

event icmp_echo_request(c: connection, info: icmp_info, id: count, seq: count, payload: string)
{
    if(!("n" in c$history)) {
        c$history += "n";
        print "-- New Connection.";
    }
	print "ICMP Echo Request", c$id$orig_h, c$id$resp_h, id, seq;
    print " |_ conn$history", c$history;
}

event icmp_echo_reply(c: connection, info: icmp_info, id: count, seq: count, payload: string)
{
	print "ICMP Echo Reply", c$id$orig_h, c$id$resp_h, id, seq;
}

event arp_request(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr,
                  THA: string)
{
	print "ARP Request", SHA, SPA, THA, TPA;
}

event arp_reply(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
{
	print "ARP Reply", SHA, SPA, THA, TPA;
}
