#include "RnaPacket.h"

using namespace zeek::packet_analysis::BR_UFRGS_INF::RNA;
using ::zeek::IP_Hdr;
using ::zeek::Packet;

RnaPacket::RnaPacket(Packet* packet, const std::shared_ptr<RnaHdr> rna_hdr)
    : Packet(packet->link_type, &(packet->ts), packet->cap_len, packet->len, packet->data,
             /* copy = */ false, packet->tag),
      rna_hdr(rna_hdr) {}

RnaPacket::RnaPacket(Packet* packet, const std::shared_ptr<RnaEventHdr> event_hdr)
    : Packet(packet->link_type, &(packet->ts), packet->cap_len, packet->len, packet->data,
             /* copy = */ false, packet->tag),
      event_hdr(event_hdr) {
    l3_proto = event_hdr->GetLayer3Proto();
    ip_hdr = event_hdr->GetIPHdr();
}

RnaPacket::~RnaPacket() {}

std::shared_ptr<RnaHdr> RnaPacket::GetRnaHdr() const { return rna_hdr; }

std::shared_ptr<RnaEventHdr> RnaPacket::GetEventHdr() const { return event_hdr; }

void RnaPacket::SetRnaHdr(std::shared_ptr<RnaHdr> hdr) { rna_hdr = hdr; }

void RnaPacket::SetEventHdr(std::shared_ptr<RnaEventHdr> hdr) {
    event_hdr = hdr;
    l3_proto = hdr->GetLayer3Proto();
    ip_hdr = hdr->GetIPHdr();
}
