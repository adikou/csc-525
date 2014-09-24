#ifndef SR_ARP_CACHE_H
#define SR_ARP_CACHE_H

#include "sr_protocol.h"

struct sr_arp_cache
{
    uint16_t arp_type;
    uint32_t arp_sip;
    uint8_t  arp_sha[ETHER_ADDR_LEN];
    struct sr_arp_cache *next;
};

#endif /* SR_ARP_CACHE_H */
