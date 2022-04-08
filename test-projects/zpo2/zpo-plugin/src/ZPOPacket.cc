#include "ZPOPacket.h"

using namespace zeek::packet_analysis::BR_INF_UFRGS_ZPO;
using ::zeek::IP_Hdr;
using ::zeek::Packet;

ZPOPacket::ZPOPacket(Packet* packet, const std::shared_ptr<ZPOEventHdr> event_hdr)
    : Packet(packet->link_type, &(packet->ts), packet->cap_len, packet->len, packet->data,
             /* copy = */ false, packet->tag),
      event_hdr(event_hdr) {
    l3_proto = event_hdr->GetLayer3Proto();
    ip_hdr = event_hdr->GetIPHdr();
}

ZPOPacket::~ZPOPacket() {}
