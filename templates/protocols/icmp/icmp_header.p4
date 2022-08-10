// ICMP Types

#define ICMP_ECHOREPLY 0        /* Echo Reply			    */
#define ICMP_DEST_UNREACH 3     /* Destination Unreachable	*/
#define ICMP_SOURCE_QUENCH 4    /* Source Quench		    */
#define ICMP_REDIRECT 5         /* Redirect (change route)	*/
#define ICMP_ECHO 8             /* Echo Request			    */
#define ICMP_ROUTER_ADVERT 9    /* Router Advertisement     */
#define ICMP_ROUTER_SOLICIT 10  /* Router Solicitation      */
#define ICMP_TIME_EXCEEDED 11   /* Time Exceeded		    */
#define ICMP_PARAMETERPROB 12   /* Parameter Problem		*/
#define ICMP_TIMESTAMP 13       /* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY 14  /* Timestamp Reply		    */
#define ICMP_INFO_REQUEST 15    /* Information Request		*/
#define ICMP_INFO_REPLY 16      /* Information Reply		*/
#define ICMP_ADDR_MASK_REQ 17   /* Address Mask Request		*/
#define ICMP_ADDR_MASK_REPLY 18 /* Address Mask Reply		*/

header icmp_h {
    bit<8>    type_;
    bit<8>    code;
    bit<16>   hdr_checksum;
}
