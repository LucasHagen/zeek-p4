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
    print "Initializing RNA Plugin...";

	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERNET, 0x6606, PacketAnalyzer::ANALYZER_RNA);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_RNA, 1, PacketAnalyzer::ANALYZER_RNA_OFFLOADER);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_RNA, 2, PacketAnalyzer::ANALYZER_RNA_OFFLOADER);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_RNA, 3, PacketAnalyzer::ANALYZER_RNA_OFFLOADER);

    print "Registered Main PacketAnalyzers.";

@@REGISTER_OFFLOADERS@@

    print "Registered Event PacketAnalyzers.";

    print "Initialized RNA Plugin.";
}

event icmp_echo_request(c: connection, info: icmp_info, id: count, seq: count, payload: string)
{
	print "ICMP Echo Request", c$id$orig_h, c$id$resp_h, id, seq;
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

event udp_request(c: connection)
{
    print "UDP Request",  c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, c$history;
}

event udp_reply(c: connection)
{
    print "UDP Reply",  c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, c$history;
}
