module PacketAnalyzer::ETHERNET;
module NTP;

@load-plugin Zeek::TCP
@load-plugin Zeek::UDP
@load-plugin Zeek::ICMP
@load-plugin Zeek::ARP
@load base/utils/exec.zeek
@load base/frameworks/files
@load base/frameworks/notice
@load frameworks/files/hash-all-files


export
{
	redef enum Notice::Type += {
		NTP_Monlist_Queries,
	};

	# The code value maps to the NTP mode type - for now I am mostly
	#  interested in control messages.
	#
	# Mode	Description
	# 0	reserved.
	# 1	Symmetric active.
	# 2	Symmetric passive.
	# 3	Client.
	# 4	Server.
	# 5	Broadcast.
	# 6	NTP control message.
	# 7	private use.
	const NTP_RESERVED = 0;
	const NTP_SYM_ACTIVE = 1;
	const NTP_SYM_PASSIVE = 2;
	const NTP_CLIENT = 3;
	const NTP_SERVER = 4;
	const NTP_BROADCAST = 5;
	const NTP_CONTROL = 6;
	const NTP_PRIVATE = 7;

} # end export

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

event icmp_time_exceeded(c: connection, info: icmp_info, code: count, context: icmp_context)
{
    print "ICMP Time Exceeded", c$id$orig_h, c$id$resp_h, code;
}

event icmp_unreachable(c: connection, info: icmp_info, code: count, context: icmp_context)
{
	print "ICMP Unreachable", context;
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

event ftp_request(c: connection, command: string, arg: string)
{
    print fmt("FTP Request (%s:%s -> %s:%s)", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
    print fmt(" |_ CMD: %s", command);
    print fmt(" |_ ARG: %s", arg);
}

event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool)
{
    print fmt("FTP Reply (%s:%s -> %s:%s)", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
    print fmt(" |_ CODE: %s", code);
    print fmt(" |_ MSG:  %s", msg);
    print fmt(" |_ CONT: %s", cont_resp);
}

event ntp_message(c: connection, is_orig: bool, msg: NTP::Message)
{
    print fmt("NTP Message (%s:%s -> %s:%s)", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);

	if ((msg$mode == NTP_PRIVATE) || (msg$mode == NTP_CONTROL)) {

		if ( ! Site::is_neighbor_addr(c$id$resp_h) && ! Site::is_local_addr(c$id$resp_h)) {

            print " -> Monlist";

			NOTICE([$note=NTP::NTP_Monlist_Queries,
				$conn=c,
				$suppress_for=6hrs,
				$msg=fmt("NTP monlist queries"),
				$identifier=cat(c$id$orig_h)]);
        } else {
            print " -> NO Monlist";
        }
	} else {
        print " -> NO Monlist";
    }
}
