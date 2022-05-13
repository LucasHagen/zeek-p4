#ifndef ZPO_TYPES
#define ZPO_TYPES

typedef bit<48>  mac_addr_t;
typedef bit<32>  ipv4_addr_t;
typedef bit<128> ipv6_addr_t;

// ZEEK TYPES:

typedef bit<8>  z_bool;     // boolean      (1 byte)
typedef bit<64> z_int;      // signed int   (8 bytes)
typedef bit<64> z_count;    // unsigned int (8 bytes)

#endif /* ZPO_TYPES */

