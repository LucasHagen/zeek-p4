#ifndef ZPO_ICMP_CODES
#define ZPO_ICMP_CODES

const bit<8> ICMP_ECHOREPLY		    = 0;    /* Echo Reply			    */
const bit<8> ICMP_DEST_UNREACH	    = 3;    /* Destination Unreachable	*/
const bit<8> ICMP_SOURCE_QUENCH	    = 4;    /* Source Quench		    */
const bit<8> ICMP_REDIRECT		    = 5;    /* Redirect (change route)	*/
const bit<8> ICMP_ECHO		        = 8;    /* Echo Request			    */
const bit<8> ICMP_TIME_EXCEEDED	    = 11;   /* Time Exceeded		    */
const bit<8> ICMP_PARAMETERPROB	    = 12;   /* Parameter Problem		*/
const bit<8> ICMP_TIMESTAMP		    = 13;   /* Timestamp Request		*/
const bit<8> ICMP_TIMESTAMPREPLY	= 14;   /* Timestamp Reply		    */
const bit<8> ICMP_INFO_REQUEST	    = 15;   /* Information Request		*/
const bit<8> ICMP_INFO_REPLY		= 16;   /* Information Reply		*/
const bit<8> ICMP_ADDRESS		    = 17;   /* Address Mask Request		*/
const bit<8> ICMP_ADDRESSREPLY	    = 18;   /* Address Mask Reply		*/

/* Definition of type and code fields. */
/* defined above: ICMP_ECHOREPLY, ICMP_REDIRECT, ICMP_ECHO */
const bit<8> ICMP_UNREACH = 3; /* dest unreachable, codes: */
const bit<8> ICMP_SOURCEQUENCH = 4; /* packet lost, slow down */
const bit<8> ICMP_ROUTERADVERT = 9; /* router advertisement */
const bit<8> ICMP_ROUTERSOLICIT = 10; /* router solicitation */
const bit<8> ICMP_TIMXCEED = 11; /* time exceeded, code: */
const bit<8> ICMP_PARAMPROB = 12; /* ip header bad */
const bit<8> ICMP_TSTAMP = 13; /* timestamp request */
const bit<8> ICMP_TSTAMPREPLY = 14; /* timestamp reply */
const bit<8> ICMP_IREQ = 15; /* information request */
const bit<8> ICMP_IREQREPLY = 16; /* information reply */
const bit<8> ICMP_MASKREQ = 17; /* address mask request */
const bit<8> ICMP_MASKREPLY = 18; /* address mask reply */

const bit<8> ICMP_MAXTYPE = 18;

/* UNREACH codes */
const bit<8> ICMP_UNREACH_NET = 0; /* bad net */
const bit<8> ICMP_UNREACH_HOST = 1; /* bad host */
const bit<8> ICMP_UNREACH_PROTOCOL = 2; /* bad protocol */
const bit<8> ICMP_UNREACH_PORT = 3; /* bad port */
const bit<8> ICMP_UNREACH_NEEDFRAG = 4; /* IP_DF caused drop */
const bit<8> ICMP_UNREACH_SRCFAIL = 5; /* src route failed */
const bit<8> ICMP_UNREACH_NET_UNKNOWN = 6; /* unknown net */
const bit<8> ICMP_UNREACH_HOST_UNKNOWN = 7; /* unknown host */
const bit<8> ICMP_UNREACH_ISOLATED = 8; /* src host isolated */
const bit<8> ICMP_UNREACH_NET_PROHIB = 9; /* net denied */
const bit<8> ICMP_UNREACH_HOST_PROHIB = 10; /* host denied */
const bit<8> ICMP_UNREACH_TOSNET = 11; /* bad tos for net */
const bit<8> ICMP_UNREACH_TOSHOST = 12; /* bad tos for host */
const bit<8> ICMP_UNREACH_FILTER_PROHIB = 13; /* admin prohib */
const bit<8> ICMP_UNREACH_HOST_PRECEDENCE = 14; /* host prec vio. */
const bit<8> ICMP_UNREACH_PRECEDENCE_CUTOFF = 15; /* prec cutoff */

/* REDIRECT codes */
const bit<8> ICMP_REDIRECT_NET = 0; /* for network */
const bit<8> ICMP_REDIRECT_HOST = 1; /* for host */
const bit<8> ICMP_REDIRECT_TOSNET = 2; /* for tos and net */
const bit<8> ICMP_REDIRECT_TOSHOST = 3; /* for tos and host */

/* TIMEXCEED codes */
const bit<8> ICMP_TIMXCEED_INTRANS = 0; /* ttl==0 in transit */
const bit<8> ICMP_TIMXCEED_REASS = 1; /* ttl==0 in reass */

/* PARAMPROB code */
const bit<8> ICMP_PARAMPROB_OPTABSENT = 1; /* req. opt. absent */

#endif /* ZPO_ICMP_CODES */

