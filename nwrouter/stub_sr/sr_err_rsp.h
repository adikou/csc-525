#ifndef SR_ERR_RSP_H
#define SR_ERR_RSP_H

/* Defining standard IP length; (not in sr_protocol.h)  */
#define IP_ADDR_LEN 4

/* #defines for standard error handling and response values */
#define ERR_RSP_ARP_NIL   0
#define ERR_RSP_ARP_REQ   1
#define ERR_RSP_ARP_REP   2
#define ERR_RSP_IP_CHKSUM 3
#define ERR_RSP_IP_TTL	  4  
#define ERR_RSP_IP_FWD	  6
#define ERR_RSP_ICMP      7

#endif /* SR_ERR_RSP_H  */
