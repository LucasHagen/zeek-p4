export
    {
	redef enum Notice::Type += {
		ZPO::My_Test_Notice,	# An extra Notice type.
		};
    }

event zeek_init() &priority=20
	{
    print "Initializing ZPO Test Plugin...";

    # TODO: register packet analyzers

	print "Initialized ZPO Test Plugin.";
	}



event icmp_echo_request(c: connection, info: icmp_info, id: count, seq: count, payload: string) &priority=20
    {
	print fmt("[ZPO] Message Received. Packet #: %s. IP Orig: %s|%s. Payload: %s", id, c$id$orig_h, c$orgi$l2_addr, payload);

		NOTICE([$note=ZPO::My_Test_Notice,
				$conn=c,
				$suppress_for=0hrs,
				$msg=fmt("ZPO TEST: plugin detected!"),
				$identifier=cat(c$id$orig_h)]);
    }


# From rna_headers.p4:

# const bit<16> TYPE_IPV4      = 0x0800;
# const bit<16> TYPE_IPV6      = 0x86DD;
# const bit<16> TYPE_EVENT     = 0x6606;
# const bit<8>  TYPE_ICMP      = 0x01;
# const bit<8>  TYPE_ICMPV6    = 0x3A;
# const bit<8>  TYPE_TCP       = 0x06;
# const bit<8>  TYPE_UDP       = 0x11;
# const bit<16> TYPE_NTP       = 123;    // L7
