#ifndef SR_FWD_REF_H
#define SR_FWD_REF_H

#include "sr_arp_cache.h"

/* ARP-related methods */
void print_arp_cache();
void add_arp_cache_tuple(struct sr_arp_cache*);
int  walk_arp_cache(struct sr_arp_cache*);
int  sr_lookup_arp_cache(unsigned char*, struct in_addr);

/* IP-related methods */
int compute_checksum(uint16_t*, int, int);
int verify_checksum(uint16_t*, int);
int sr_handle_ethernet_frame(uint8_t*, uint16_t,
			     uint8_t*, struct sr_instance*, char**,
			     struct in_addr*);

/* Packet forwarding methods */ 
int count_umask_bits(uint32_t);
struct sr_rt* sr_rtable_prefix_lookup(struct sr_instance*,
				      struct in_addr);
int  sr_forward_packet(struct sr_instance*, struct sr_ethernet_hdr*,
		    uint8_t*, unsigned int, char*, char*, struct in_addr, int);

uint8_t* sr_construct_new_packet(unsigned char*, uint32_t, uint32_t, uint8_t*, int);


/* Print methods for packet debugging  */
void sr_print_packet_contents(struct sr_instance*, uint8_t*, 
			      unsigned int , char*);
void print_ethernet_address(uint8_t *);

/*PWOSPF methods*/
long int getProperty(char*);
void sr_handle_pwospf(struct sr_instance*, uint8_t*, int, char*);

#endif /* SR_FWD_REF_H  */
