#ifndef SR_ARP_CACHE_H
#define SR_ARP_CACHE_H

struct sr_arp_cache
{
    uint16_t       arp_type;
    uint32_t       arp_sip;
    unsigned char  arp_sha[ETHER_ADDR_LEN];
    struct         sr_arp_cache *next;
    struct 		   sr_arp_cache *prev;
} __attribute__ ((packed));

#endif /* SR_ARP_CACHE_H */
