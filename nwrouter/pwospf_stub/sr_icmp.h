#ifndef SR_ICMP_H
#define SR_ICMP_H

#define ICMP_TYPE_ECHO_REPLY  0
#define ICMP_TYPE_DU          3
#define ICMP_TYPE_ECHO_REQ    8	
#define ICMP_TYPE_TOUT	     11

#define ICMP_CODE_TTLXCD 0
#define ICMP_CODE_DU_HU  1
#define ICMP_CODE_DU_PU  3

struct icmp
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    /* After this, it varies for every type of ICMP message */
    uint16_t id;
    uint16_t seqNum;
} __attribute__ ((packed)) ;

#endif /* SR_ICMP_H  */
