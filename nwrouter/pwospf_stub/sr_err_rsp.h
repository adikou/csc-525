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
#define ERR_RSP_ARP_NIL   	   0
#define ERR_RSP_ARP_REQ_GWAY   1
#define ERR_RSP_ARP_REQ_SNET   2
#define ERR_RSP_ARP_REP   	   3
#define ERR_RSP_IP_CHKSUM 	   4
#define ERR_RSP_IP_TTL	  	   5  
#define ERR_RSP_IP_FWD	  	   6
#define ERR_RSP_IP_DROP		   7
#define ERR_RSP_ICMP_HU        8
#define ERR_RSP_ICMP_PU		   9
#define ERR_RSP_ICMP_TOUT	  10
#define ERR_RSP_ICMP_ECHO_REP 11

#define ERR_RSP_OSPF_PKT	  12
#define ERR_RSP_OSPF_HELLO	  13
#define ERR_RSP_OSPF_LSU	  14
#define ERR_RSP_OSPF_VER	  15
#define ERR_RSP_OSPF_CSUM	  16
#define ERR_RSP_OSPF_AID	  17
#define ERR_RSP_OSPF_AUTYPE	  18
#define ERR_RSP_OSPF_TYPE	  19
#define ERR_RSP_OSPF_IP_DST	  20
#define ERR_RSP_OSPF_HEL_NM	  21
#define ERR_RSP_OSPF_HEL_HI	  22
#define ERR_RSP_OSPF_LSU_DROP 23 

#endif /* SR_ERR_RSP_H  */
