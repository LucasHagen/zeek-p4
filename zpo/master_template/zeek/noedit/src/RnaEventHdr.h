#pragma once

#include <netinet/ip.h>

#include <memory>

#include "zeek/Conn.h"
#include "zeek/IP.h"
#include "zeek/IPAddr.h"

#define RNA_P_ETH_EVENT  1
#define RNA_P_IPV4_EVENT 2
#define RNA_P_IPV6_EVENT 3

namespace zeek::packet_analysis::BR_UFRGS_INF::RNA {

#pragma pack(1)
typedef struct eth_event_h_struct {
    uint16_t next_header;
    uint16_t protocol_l3;
} eth_event_h;

#pragma pack(1)
typedef struct ipv4_event_h_struct {
    uint16_t next_header;
    uint16_t src_port;
    uint16_t dst_port;
    struct ip ip_hdr;
} ipv4_event_h;

#pragma pack(1)
typedef struct ipv6_event_h_struct {
    uint16_t next_header;
    uint16_t src_port;
    uint16_t dst_port;
    struct ip6_hdr ipv6_hdr;
} ipv6_event_h;

/**
 * @brief Representation of the RNA Event Header.
 *
 * All data available in this object is already in Host ByteOrder, unless otherwise specified.
 */
class RnaEventHdr {
public:
    const static int ETH_EVENT_HEADER_SIZE = sizeof(eth_event_h);
    const static int IPV4_EVENT_HEADER_SIZE = sizeof(ipv4_event_h);
    const static int IPV6_EVENT_HEADER_SIZE = sizeof(ipv6_event_h);

    /**
     * @brief Creates an instance of a ethernet-based RnaEventHdr.
     *
     * @param data Pointer to the beginning of the event header.
     * @return std::shared_ptr<RnaEventHdr> A new instance.
     */
    static std::shared_ptr<RnaEventHdr> InitEthEventHdr(const uint8_t* data);

    /**
     * @brief Creates an instance of a ipv4-based RnaEventHdr.
     *
     * @param data Pointer to the beginning of the event header.
     * @return std::shared_ptr<RnaEventHdr> A new instance.
     */
    static std::shared_ptr<RnaEventHdr> InitIpv4EventHdr(const uint8_t* data);

    /**
     * @brief Creates an instance of a ipv6-based RnaEventHdr.
     *
     * @param data Pointer to the beginning of the event header.
     * @return std::shared_ptr<RnaEventHdr> A new instance.
     */
    static std::shared_ptr<RnaEventHdr> InitIpv6EventHdr(const uint8_t* data);

    ~RnaEventHdr() = default;

    uint16_t GetLayer3Protocol() const;
    uint8_t GetLayer4Protocol() const;
    zeek::IPAddr GetSrcAddress() const;
    zeek::IPAddr GetDstAddress() const;
    uint16_t GetSrcPort() const;
    uint16_t GetDstPort() const;
    uint16_t GetEventType() const;

    uint32_t GetHdrSize() const;

    std::shared_ptr<zeek::IP_Hdr> GetIPHdr() const;

    bool IsIPv4() const;
    bool IsIPv6() const;

    TransportProto GetTransportProto() const;
    zeek::Layer3Proto GetLayer3Proto() const;

    /**
     * @brief Pointer to the Payload of the packet.
     *
     * This adds the size of the event header to the pointer, returning the next segment of
     * data.
     *
     * @return const uint8_t* Pointer to the payload.
     */
    const uint8_t* GetPayload() const;

    /**
     * @brief Construct a new RnaEventHdr for a **NOT**-ip based event.
     *
     * This
     *
     * @param data
     * @param hdr
     */
    RnaEventHdr(const uint8_t* data, const eth_event_h* hdr);
    RnaEventHdr(const uint8_t* data, const ipv4_event_h* hdr);
    RnaEventHdr(const uint8_t* data, const ipv6_event_h* hdr);

    zeek::Connection* GetOrCreateConnection(const Packet* packet);
    zeek::Connection* GetOrCreateConnection(const Packet* packet, const zeek::ConnTuple& tuple);

protected:
    const uint8_t* data = nullptr;
    const eth_event_h* eth_event_hdr = nullptr;
    const ipv4_event_h* ipv4_event_hdr = nullptr;
    const ipv6_event_h* ipv6_event_hdr = nullptr;

    const uint32_t hdr_size = 0;
    const uint8_t* payload = nullptr;

    uint16_t event_type = 0;
    uint16_t l3_protocol = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;

    std::shared_ptr<zeek::IP_Hdr> ip_hdr = nullptr;

    Connection* NewConn(const zeek::ConnTuple* id, const zeek::detail::ConnKey& key,
                        const Packet* packet);
};

}  // namespace zeek::packet_analysis::BR_UFRGS_INF::RNA
