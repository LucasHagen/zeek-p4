#define ICMP_ECHOREPLY 0    /* Echo Reply			    */
#define ICMP_DEST_UNREACH 3    /* Destination Unreachable	*/
#define ICMP_SOURCE_QUENCH 4    /* Source Quench		    */
#define ICMP_REDIRECT 5    /* Redirect (change route)	*/
#define ICMP_ECHO 8    /* Echo Request			    */
#define ICMP_TIME_EXCEEDED 11   /* Time Exceeded		    */
#define ICMP_PARAMETERPROB 12   /* Parameter Problem		*/
#define ICMP_TIMESTAMP 13   /* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY 14   /* Timestamp Reply		    */
#define ICMP_INFO_REQUEST 15   /* Information Request		*/
#define ICMP_INFO_REPLY 16   /* Information Reply		*/
#define ICMP_ADDRESS 17   /* Address Mask Request		*/
#define ICMP_ADDRESSREPLY 18   /* Address Mask Reply		*/

/* Definition of type and code fields. */
/* defined above: ICMP_ECHOREPLY, ICMP_REDIRECT, ICMP_ECHO */
#define ICMP_UNREACH 3 /* dest unreachable, codes: */
#define ICMP_SOURCEQUENCH 4 /* packet lost, slow down */
#define ICMP_ROUTERADVERT 9 /* router advertisement */
#define ICMP_ROUTERSOLICIT 10 /* router solicitation */
#define ICMP_TIMXCEED 11 /* time exceeded, code: */
#define ICMP_PARAMPROB 12 /* ip header bad */
#define ICMP_TSTAMP 13 /* timestamp request */
#define ICMP_TSTAMPREPLY 14 /* timestamp reply */
#define ICMP_IREQ 15 /* information request */
#define ICMP_IREQREPLY 16 /* information reply */
#define ICMP_MASKREQ 17 /* address mask request */
#define ICMP_MASKREPLY 18 /* address mask reply */

#define ICMP_MAXTYPE 18

/* UNREACH codes */
#define ICMP_UNREACH_NET 0 /* bad net */
#define ICMP_UNREACH_HOST 1 /* bad host */
#define ICMP_UNREACH_PROTOCOL 2 /* bad protocol */
#define ICMP_UNREACH_PORT 3 /* bad port */
#define ICMP_UNREACH_NEEDFRAG 4 /* IP_DF caused drop */
#define ICMP_UNREACH_SRCFAIL 5 /* src route failed */
#define ICMP_UNREACH_NET_UNKNOWN 6 /* unknown net */
#define ICMP_UNREACH_HOST_UNKNOWN 7 /* unknown host */
#define ICMP_UNREACH_ISOLATED 8 /* src host isolated */
#define ICMP_UNREACH_NET_PROHIB 9 /* net denied */
#define ICMP_UNREACH_HOST_PROHIB 10 /* host denied */
#define ICMP_UNREACH_TOSNET 11 /* bad tos for net */
#define ICMP_UNREACH_TOSHOST 12 /* bad tos for host */
#define ICMP_UNREACH_FILTER_PROHIB 13 /* admin prohib */
#define ICMP_UNREACH_HOST_PRECEDENCE 14 /* host prec vio. */
#define ICMP_UNREACH_PRECEDENCE_CUTOFF 15 /* prec cutoff */

/* REDIRECT codes */
#define ICMP_REDIRECT_NET 0 /* for network */
#define ICMP_REDIRECT_HOST 1 /* for host */
#define ICMP_REDIRECT_TOSNET 2 /* for tos and net */
#define ICMP_REDIRECT_TOSHOST 3 /* for tos and host */

/* TIMEXCEED codes */
#define ICMP_TIMXCEED_INTRANS 0 /* ttl==0 in transit */
#define ICMP_TIMXCEED_REASS 1 /* ttl==0 in reass */

/* PARAMPROB code */
#define ICMP_PARAMPROB_OPTABSENT 1 /* req. opt. absent */

header icmp_h {
    bit<8>    type_;
    bit<8>    code;
    bit<16>   hdr_checksum;
    bit<16>   id;
    bit<16>   seq;
}
