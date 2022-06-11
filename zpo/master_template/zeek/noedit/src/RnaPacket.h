#pragma once

#include <memory>

#include "RnaOffloaderHdr.h"
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
    RnaPacket(Packet* packet, const std::shared_ptr<RnaHdr> offloader_hdr);

    /**
     * @brief Construct a new RnaPacket object.
     *
     * @param packet Original Packet object.
     */
    RnaPacket(Packet* packet, const std::shared_ptr<RnaOffloaderHdr> offloader_hdr);

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
     * @brief Gets the RnaOffloaderHdr, if it was set.
     *
     * @return std::shared_ptr<RnaOffloaderHdr> or nullptr
     */
    std::shared_ptr<RnaOffloaderHdr> GetOffloaderHdr() const;

    /**
     * @brief Sets the RnaHdr.
     *
     * @param hdr The RnaHdr.
     */
    void SetRnaHdr(std::shared_ptr<RnaHdr> hdr);

    /**
     * @brief Sets the RnaOffloaderHdr.
     *
     * Also updates the IP header and the L3 Proto for the packet according to the provided header.
     *
     * @param hdr The RnaOffloaderHdr.
     */
    void SetOffloaderHdr(std::shared_ptr<RnaOffloaderHdr> hdr);

protected:
    std::shared_ptr<RnaHdr> rna_hdr = nullptr;
    std::shared_ptr<RnaOffloaderHdr> offloader_hdr = nullptr;
};

}  // namespace zeek::packet_analysis::BR_UFRGS_INF::RNA
