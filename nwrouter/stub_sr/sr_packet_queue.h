#ifndef SR_PACKET_QUEUE_H
#define SR_PACKET_QUEUE_H

#include <netinet/in.h>

struct sr_packet_queue
{
    struct sr_instance* sr;
    uint8_t *root;
    unsigned int len;
    char* interface;
    struct in_addr dst_ip;
    struct sr_packet_queue *next;
    struct sr_packet_queue *prev;
} __attribute__ ((packed));

struct pending_packet_count
{
	uint32_t ip;
	int		 count;
	struct pending_packet_count *next;
	struct pending_packet_count *prev;
} __attribute__ ((packed));


void print_packet_queue();
void enqueue_packet(struct sr_instance*, uint8_t*, 
		    unsigned int, char*, struct in_addr);
int increment_wait_counter(struct in_addr, int);
void dequeue_packet(struct sr_packet_queue*);
void _dump_pending_packets(uint32_t, int);

#endif /* SR_PACKET_QUEUE_H  */
