#pragma once

#include <netinet/ip.h>

#include <memory>

#include "zeek/Conn.h"
#include "zeek/IP.h"
#include "zeek/IPAddr.h"

#define ETH_P_EVENT 0x6601
#define ETH_P_EVENT_IP 0x6602

namespace zeek::packet_analysis::BR_INF_UFRGS_ZPO {

#pragma pack(1)
typedef struct eth_event_h_struct {
    uint32_t pkt_num;
    uint16_t protocol_l3;
    uint16_t event_type;
} eth_event_h;

#pragma pack(1)
typedef struct ip_event_h_struct {
    uint32_t pkt_num;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t event_type;
    struct ip ip_hdr;
} ip_event_h;

/**
 * @brief Representation of the ZPO Event Header.
 *
 * All data available in this object is already in Host ByteOrder, unless otherwise specified.
 */
class ZpoEventHdr {
public:
    const static int ETH_EVENT_HEADER_SIZE = sizeof(eth_event_h);
    const static int IP_EVENT_HEADER_SIZE = sizeof(ip_event_h);

    /**
     * @brief Creates an instance of a ZpoEventHdr.
     *
     * Using the `l3_protocol` as base to decide which header should be used. If l3_protocol is:
     *  - ETH_P_EVENT_IP: `ip_event_h` will be used, meaning an ip-based event was seen on the switch, and
     * it possibly requires an instance of a`zeek::Connection`.
     *  - ETH_P_EVENT: `eth_event_h` will be used.
     *
     * @param l3_protocol L3 Protocol code of the packet received on the **HOST**.
     * @param data Pointer to the beginning of the event header.
     * @return std::shared_ptr<ZpoEventHdr> A new instance.
     */
    static std::shared_ptr<ZpoEventHdr> InitEventHdr(const uint16_t l3_protocol,
                                                     const uint8_t* data);

    ~ZpoEventHdr() = default;

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
     * @brief Construct a new ZpoEventHdr for a **NOT**-ip based event.
     *
     * This
     *
     * @param data
     * @param hdr
     */
    ZpoEventHdr(const uint8_t* data, const eth_event_h* hdr);
    ZpoEventHdr(const uint8_t* data, const ip_event_h* hdr);

    zeek::Connection* GetOrCreateConnection(const Packet* packet);
    zeek::Connection* GetOrCreateConnection(const Packet* packet, const zeek::ConnTuple& tuple);

protected:
    const uint8_t* data = nullptr;
    const eth_event_h* eth_event_hdr = nullptr;
    const ip_event_h* ip_event_hdr = nullptr;

    const uint32_t hdr_size = 0;
    const uint8_t* payload = nullptr;

    uint32_t packet_number = 0;
    uint16_t l3_protocol = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint16_t event_type = 0;

    std::shared_ptr<zeek::IP_Hdr> ip_hdr = nullptr;

    Connection* NewConn(const zeek::ConnTuple* id, const zeek::detail::ConnKey& key,
                        const Packet* packet);
};

}  // namespace zeek::packet_analysis::BR_INF_UFRGS_ZPO
