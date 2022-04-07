#ifndef ZPO_CONSTANTS
#define ZPO_CONSTANTS

// L3 PROTOCOL CODES
const bit<16>   ETH_P_EVENT     = 0x6601;
const bit<16>   ETH_P_EVENT_IP  = 0x6602;
const bit<16>   ETH_P_IPV4      = 0x0800;
const bit<16>   ETH_P_IPV6      = 0x86DD;

// L4 PROTOCOL CODES
const bit<8>    IPPROTO_ICMP    = 0x01;
const bit<8>    IPPROTO_ICMPV6  = 0x3A;
const bit<8>    IPPROTO_TCP     = 0x06;
const bit<8>    IPPROTO_UDP     = 0x11;

// L7 PROTOCOL CODES
const bit<16>   TYPE_NTP        = 123;

// EVENT CODES
const bit<16> TYPE_NO_EVENT                 = 0;
const bit<16> TYPE_ICMP_ECHO_REPLY_EVENT    = 1;
const bit<16> TYPE_ICMP_ECHO_REQ_EVENT      = 2;

#endif /* ZPO_CONSTANTS */
