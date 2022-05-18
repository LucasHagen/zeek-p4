#pragma once

#include <memory>

#include "ZpoEventHdr.h"
#include "zeek/iosource/Packet.h"

namespace zeek::packet_analysis::BR_UFRGS_INF_ZPO {

class ZpoPacket : public zeek::Packet {
public:
    /**
     * @brief Construct a new ZpoPacket object.
     *
     * @param packet Original Packet object.
     */
    ZpoPacket(Packet* packet, const std::shared_ptr<ZpoEventHdr> event_hdr);

    /**
     * Destructor.
     */
    ~ZpoPacket();

    const std::shared_ptr<ZpoEventHdr> event_hdr = nullptr;
};

}  // namespace zeek::packet_analysis::BR_UFRGS_INF_ZPO
