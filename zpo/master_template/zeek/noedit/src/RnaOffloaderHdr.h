#pragma once

#include <netinet/ip.h>

#include <memory>

#include "zeek/Conn.h"
#include "zeek/IP.h"
#include "zeek/IPAddr.h"

#define RNA_P_ETH_OFFLOADER 1
#define RNA_P_IPV4_OFFLOADER 2
#define RNA_P_IPV6_OFFLOADER 3

namespace zeek::packet_analysis::BR_UFRGS_INF::RNA {

#pragma pack(1)
typedef struct eth_offloader_h_struct {
    uint16_t next_header;
    uint16_t protocol_l3;
} eth_offloader_h;

#pragma pack(1)
typedef struct ipv4_offloader_h_struct {
    uint16_t next_header;
    uint16_t src_port;
    uint16_t dst_port;
    struct ip ip_hdr;
} ipv4_offloader_h;

#pragma pack(1)
typedef struct ipv6_offloader_h_struct {
    uint16_t next_header;
    uint16_t src_port;
    uint16_t dst_port;
    struct ip6_hdr ipv6_hdr;
} ipv6_offloader_h;

/**
 * @brief Representation of the RNA Offloader Header.
 *
 * All data available in this object is already in Host ByteOrder, unless otherwise specified.
 */
class RnaOffloaderHdr {
public:
    const static int ETH_OFFLOADER_HEADER_SIZE = sizeof(eth_offloader_h);
    const static int IPV4_OFFLOADER_HEADER_SIZE = sizeof(ipv4_offloader_h);
    const static int IPV6_OFFLOADER_HEADER_SIZE = sizeof(ipv6_offloader_h);

    /**
     * @brief Creates an instance of a ethernet-based RnaOffloaderHdr.
     *
     * @param data Pointer to the beginning of the offloader header.
     * @return std::shared_ptr<RnaOffloaderHdr> A new instance.
     */
    static std::shared_ptr<RnaOffloaderHdr> InitEthOffloaderHdr(const uint8_t* data);

    /**
     * @brief Creates an instance of a ipv4-based RnaOffloaderHdr.
     *
     * @param data Pointer to the beginning of the offloader header.
     * @return std::shared_ptr<RnaOffloaderHdr> A new instance.
     */
    static std::shared_ptr<RnaOffloaderHdr> InitIpv4OffloaderHdr(const uint8_t* data);

    /**
     * @brief Creates an instance of a ipv6-based RnaOffloaderHdr.
     *
     * @param data Pointer to the beginning of the offloader header.
     * @return std::shared_ptr<RnaOffloaderHdr> A new instance.
     */
    static std::shared_ptr<RnaOffloaderHdr> InitIpv6OffloaderHdr(const uint8_t* data);

    ~RnaOffloaderHdr() = default;

    uint16_t GetLayer3Protocol() const;
    uint8_t GetLayer4Protocol() const;
    zeek::IPAddr GetSrcAddress() const;
    zeek::IPAddr GetDstAddress() const;
    uint16_t GetSrcPort() const;
    uint16_t GetDstPort() const;
    uint16_t GetOffloaderType() const;

    uint32_t GetHdrSize() const;

    std::shared_ptr<zeek::IP_Hdr> GetIPHdr() const;

    bool IsIPv4() const;
    bool IsIPv6() const;

    TransportProto GetTransportProto() const;
    zeek::Layer3Proto GetLayer3Proto() const;

    /**
     * @brief Pointer to the Payload of the packet.
     *
     * This adds the size of the offloader header to the pointer, returning the next segment of
     * data.
     *
     * @return const uint8_t* Pointer to the payload.
     */
    const uint8_t* GetPayload() const;

    /**
     * @brief Construct a new RnaOffloaderHdr for a **NOT**-ip based offloader.
     */
    RnaOffloaderHdr(const uint8_t* data, const eth_offloader_h* hdr);

    /**
     * @brief Construct a new RnaOffloaderHdr for a ipv4-based offloader.
     */
    RnaOffloaderHdr(const uint8_t* data, const ipv4_offloader_h* hdr);

    /**
     * @brief Construct a new RnaOffloaderHdr for a ipv6-based offloader.
     */
    RnaOffloaderHdr(const uint8_t* data, const ipv6_offloader_h* hdr);

    zeek::Connection* GetOrCreateConnection(Packet* packet);
    zeek::Connection* GetOrCreateConnection(Packet* packet, bool is_one_way, bool flip_roles);
    zeek::Connection* GetOrCreateConnection(Packet* packet, const zeek::ConnTuple& tuple,
                                            bool flip_roles);

protected:
    const uint8_t* data = nullptr;
    const eth_offloader_h* eth_offloader_hdr = nullptr;
    const ipv4_offloader_h* ipv4_offloader_hdr = nullptr;
    const ipv6_offloader_h* ipv6_offloader_hdr = nullptr;

    const uint32_t hdr_size = 0;
    const uint8_t* payload = nullptr;

    uint16_t offloader_type = 0;
    uint16_t l3_protocol = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;

    std::shared_ptr<zeek::IP_Hdr> ip_hdr = nullptr;

    Connection* NewConn(const zeek::ConnTuple* id, const zeek::detail::ConnKey& key,
                        const Packet* packet, bool flip_roles);
};

}  // namespace zeek::packet_analysis::BR_UFRGS_INF::RNA
