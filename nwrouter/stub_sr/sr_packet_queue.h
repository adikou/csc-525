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
};

void print_packet_queue();
void enqueue_packet(struct sr_instance*, uint8_t*, 
		    unsigned int, char*, struct in_addr);
int increment_wait_counter(struct in_addr, uint8_t);
struct sr_packet_queue* dequeue_packet();
void _dump_pending_packets(uint32_t);

#endif /* SR_PACKET_QUEUE_H  */
