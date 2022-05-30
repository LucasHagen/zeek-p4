#pragma once

#include <inttypes.h>

#define ETH_P_RNA 0x6606

#define RNA_P_DEBUG 0
#define RNA_P_ETH_EVENT 1
#define RNA_P_IPV4_EVENT 2
#define RNA_P_IPV6_EVENT 3

namespace zeek::packet_analysis::BR_UFRGS_INF::RNA {

#pragma pack(1)
typedef struct {
    uint16_t version;
    uint16_t rna_type;
} rna_header;

/**
 * @brief Representation of the RNA Event Header.
 *
 * All data available in this object is already in Host ByteOrder, unless otherwise specified.
 */
class RnaHdr {
public:
    RnaHdr(const uint8_t* data, const rna_header* header);
    ~RnaHdr() = default;

    /**
     * @brief Gets the RNA Version (already in host byte order).
     */
    uint16_t GetVersion() const;

    /**
     * @brief Gets the RNA Type (already in host byte order).
     */
    uint16_t GetRnaType() const;

    int GetHdrSize() const;

    /**
     * @brief Pointer to the Payload of the packet.
     *
     * This adds the size of the event header to the pointer, returning the next segment of
     * data.
     *
     * @return const uint8_t* Pointer to the payload.
     */
    const uint8_t* GetPayload() const;

protected:
    const uint8_t* payload;
    const uint16_t version;
    const uint16_t rna_type;
};

}  // namespace zeek::packet_analysis::BR_UFRGS_INF::RNA
