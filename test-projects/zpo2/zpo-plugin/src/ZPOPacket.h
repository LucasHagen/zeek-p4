#pragma once

#include <memory>

#include "ZPOEventHdr.h"
#include "zeek/Packet.h"

namespace zeek::packet_analysis::BR_INF_UFRGS_ZPO {

class ZPOPacket : public zeek::Packet {
public:
    /**
     * @brief Construct a new ZPOPacket object.
     *
     * @param packet Original Packet object.
     */
    ZPOPacket(const Packet& packet, std::shared_ptr<ZPOEventHdr> event_hdr);

    /**
     * Destructor.
     */
    ~ZPOPacket();

protected:
    std::shared_ptr<ZPOEventHdr> event_hdr;
};

}  // namespace zeek::packet_analysis::BR_INF_UFRGS_ZPO
