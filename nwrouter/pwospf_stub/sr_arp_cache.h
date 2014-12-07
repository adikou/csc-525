#ifndef SR_ARP_CACHE_H
#define SR_ARP_CACHE_H

#include <pthread.h>

#define ARP_CACHE   1 
#define QUEUE_COUNT 2

struct timeouts
{
	uint32_t ip;
	int timeout_t;
	int type;
};

struct sr_arp_cache
{
    uint16_t       arp_type;
    uint32_t       arp_sip;
    unsigned char  arp_sha[ETHER_ADDR_LEN];
    double		   timestamp;
    pthread_t	   *timeout_thread;
    struct         sr_arp_cache *next;
    struct 		   sr_arp_cache *prev;
} __attribute__ ((packed));

#endif /* SR_ARP_CACHE_H */
