module PacketAnalyzer::ETHERNET;

@load-plugin Zeek::TCP
@load-plugin Zeek::UDP
@load-plugin Zeek::ICMP
@load base/frameworks/files
@load base/frameworks/notice
@load frameworks/files/hash-all-files

export {

}

event zeek_init() &priority=20
	{
    print "Initializing ZPO Test Plugin...";

    # TODO: register packet analyzers


	print "Initialized ZPO Test Plugin.";
	}

event icmp_echo_request(c: connection, info: icmp_info, id: count, seq: count, payload: string) &priority=20
	{
	print fmt("[ZPO] Message Received. Packet #: %s. IP s->d: %s|%s. Payload: %s", id, c$id$orig_h, c$id$resp_h, payload);
 	}

# Example only event
event icmp_echo_reply(c: connection, info: icmp_info, id: count, seq: count, payload: string) &priority=20
	{
	print fmt("[ZPO] Message Received. Packet #: %s. IP s->d: %s|%s. Payload: %s", id, c$id$orig_h, c$id$resp_h, payload);
 	}


# opt-p4-zeek [-t <pasta-de-templates>] <eventos...> -> Código P4 + Código C++ Zeek
#
# opt-p4-zeek -t ./templates icmp_echo_request icmp_echo_reply
#   - Achar template P4 que identifica: icmp_echo_request, icmp_echo_reply
#   - Gerar código P4 que faz "empacotamento" do evento (combinando todos templates)
#   - Gerar código C++ (Zeek Plugin) capturando protocolo "custom"
#

# Template:
# (pasta):
#   - template.json:
# "icmp_echo_request": {
#    "p4_code": "path para o arquivo p4",
#    "encapsulation": [eth, ip, icmp]
#    "event_def": "icmp_events.bif"
# }
#
# Obs: reutilização de código P4
