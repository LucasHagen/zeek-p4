#include "RnaHdr.h"

#include <netinet/in.h>

using namespace zeek::packet_analysis::BR_UFRGS_INF::RNA;

RnaHdr::RnaHdr(const uint8_t* data, const rna_header* header)
    : payload(data + sizeof(rna_header)),
      version(ntohs(header->version)),
      rna_type(ntohs(header->rna_type)) {}

uint16_t RnaHdr::GetRnaType() const { return rna_type; }

uint16_t RnaHdr::GetVersion() const { return version; }

int RnaHdr::GetHdrSize() const { return sizeof(rna_header); }

const uint8_t* RnaHdr::GetPayload() const { return payload; }
