#ifndef SR_ERR_RSP_H
#define SR_ERR_RSP_H

/* Defining standard IP length; (not in sr_protocol.h)  */
#define IP_ADDR_LEN 4

/* IP Protocols */
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 	0x06 /* TCP protocol */
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 	0x11 /* UDP protocol */
#endif

/* #defines for standard error handling and response values */
#define ERR_RSP_ARP_NIL   	0
#define ERR_RSP_ARP_REQ_GWAY   	1
#define ERR_RSP_ARP_REQ_SNET   	2
#define ERR_RSP_ARP_REP   	3
#define ERR_RSP_IP_CHKSUM 	4
#define ERR_RSP_IP_TTL	  	5  
#define ERR_RSP_IP_FWD	  	6
#define ERR_RSP_ICMP_HU      	7
#define ERR_RSP_ICMP_PU		8
#define ERR_RSP_ICMP_TOUT	9
#define ERR_RSP_ICMP_ECHO_REP	10

#endif /* SR_ERR_RSP_H  */
