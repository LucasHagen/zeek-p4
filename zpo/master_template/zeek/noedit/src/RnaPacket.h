#pragma once

#include <memory>

#include "RnaEventHdr.h"
#include "RnaHdr.h"
#include "zeek/iosource/Packet.h"

namespace zeek::packet_analysis::BR_UFRGS_INF::RNA {

class RnaPacket : public zeek::Packet {
public:
    /**
     * @brief Construct a new RnaPacket object.
     *
     * @param packet Original Packet object.
     */
    RnaPacket(Packet* packet, const std::shared_ptr<RnaHdr> event_hdr);

    /**
     * @brief Construct a new RnaPacket object.
     *
     * @param packet Original Packet object.
     */
    RnaPacket(Packet* packet, const std::shared_ptr<RnaEventHdr> event_hdr);

    /**
     * Destructor.
     */
    ~RnaPacket();

    /**
     * @brief Gets the RnaHdr, if it was set.
     *
     * @return std::shared_ptr<RnaHdr> or nullptr
     */
    std::shared_ptr<RnaHdr> GetRnaHdr() const;

    /**
     * @brief Gets the RnaEventHdr, if it was set.
     *
     * @return std::shared_ptr<RnaEventHdr> or nullptr
     */
    std::shared_ptr<RnaEventHdr> GetEventHdr() const;

    /**
     * @brief Sets the RnaHdr.
     *
     * @param hdr The RnaHdr.
     */
    void SetRnaHdr(std::shared_ptr<RnaHdr> hdr);

    /**
     * @brief Sets the RnaEventHdr.
     *
     * Also updates the IP header and the L3 Proto for the packet according to the provided header.
     *
     * @param hdr The RnaEventHdr.
     */
    void SetEventHdr(std::shared_ptr<RnaEventHdr> hdr);

protected:
    std::shared_ptr<RnaHdr> rna_hdr = nullptr;
    std::shared_ptr<RnaEventHdr> event_hdr = nullptr;
};

}  // namespace zeek::packet_analysis::BR_UFRGS_INF::RNA
