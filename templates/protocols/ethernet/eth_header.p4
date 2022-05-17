// L3 PROTOCOL CODES
const bit<16>   ETH_P_EVENT     = 0x6601;
const bit<16>   ETH_P_EVENT_IP  = 0x6602;
const bit<16>   ETH_P_IPV4      = 0x0800;
const bit<16>   ETH_P_IPV6      = 0x86DD;
const bit<16>   ETH_P_ARP       = 0x0806;

typedef bit<48>  mac_addr_t;

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16>   ethertype;
}
