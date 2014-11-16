#ifndef SR_PACKET_QUEUE_H
#define SR_PACKET_QUEUE_H

#include <netinet/in.h>
#include <pthread.h>

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

struct thread_counter
{
    int id;
    uint32_t ip;
    unsigned char mac_vrhost[ETHER_ADDR_LEN];
    uint32_t ip_vrhost;
    pthread_t *thread;
};

struct pending_packet_count
{
    uint32_t ip;
    int      numPacketsSent;
    int received;
    int sentARPReq;
    int numHostUnreachSent;
    pthread_t *timeout_thread;
    struct thread_counter thread_count;
    struct pending_packet_count *next;
    struct pending_packet_count *prev;
};
void print_packet_queue();
void enqueue_packet(struct sr_instance*, uint8_t*, 
		    unsigned int, char*, struct in_addr);
struct pending_packet_count* increment_wait_counter(struct in_addr, int);
void dequeue_packet(struct sr_packet_queue*);
int _dump_pending_packets(uint32_t, int);

#endif /* SR_PACKET_QUEUE_H  */
