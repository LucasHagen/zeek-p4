#pragma once

#include <memory>

#include "ZpoEventHdr.h"
#include "zeek/iosource/Packet.h"

namespace zeek::packet_analysis::BR_INF_UFRGS_ZPO {

class ZPOPacket : public zeek::Packet {
public:
    /**
     * @brief Construct a new ZPOPacket object.
     *
     * @param packet Original Packet object.
     */
    ZPOPacket(Packet* packet, const std::shared_ptr<ZpoEventHdr> event_hdr);

    /**
     * Destructor.
     */
    ~ZPOPacket();

    const std::shared_ptr<ZpoEventHdr> event_hdr = nullptr;
};

}  // namespace zeek::packet_analysis::BR_INF_UFRGS_ZPO
