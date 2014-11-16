
/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing. 11
 * 90904102
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"

/* Thread includes */
#include <pthread.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>

/* Local includes  */
#include "sr_arp_cache.h"
#include "sr_err_rsp.h"
#include "sr_fwd_ref.h"
#include "sr_packet_queue.h"
#include "sr_icmp.h"

/* Number of QUEUE_TAIL */
struct pending_packet_count *QUEUE_TAIL = NULL, *QUEUE_HEAD = NULL;

/*Initialise an empty ARP cache */
struct sr_arp_cache *arp_cache_head = NULL; 
struct sr_arp_cache gway;

/* Initialise empty packet queue  */
struct sr_packet_queue *queue_head = NULL;
struct sr_packet_queue *queue_tail = NULL;

int FIRST_PACKET = 1;

/* Global thread counter */
int THREAD_COUNT = 0;
struct thread_counter *p;
pthread_t *thread, *watch_count;
struct timeval tv;
time_t startTime;


pthread_mutex_t count_mutex = PTHREAD_MUTEX_INITIALIZER;    
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t count_threshold_cv = PTHREAD_COND_INITIALIZER;

#define MAX_ARP_REQ 5

/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr) 
{
    /* REQUIRES */
    assert(sr);
    /* Add initialization code here! */

} /* -- sr_init -- */

/*--------------------------------------------------------------------- 
 * Method: print_arp_cache
 * Scope:  Local
 *
 * Print the ARP cache
 *
 * @author : Aditya Kousik
 * @date   : 23-09-2014
 *
 *---------------------------------------------------------------------*/
void print_arp_cache()
{
    struct sr_arp_cache *cur = arp_cache_head;
    struct in_addr ip;
    printf("\nProtocol Type\tIP address \tMAC address");
    while(cur != NULL)
    {
    ip.s_addr = ntohl(cur->arp_sip);
    printf("\n%x\t\t", ntohs(cur->arp_type));
    printf("%s\t    ", inet_ntoa(ip));
    print_ethernet_address(cur->arp_sha);
    cur = cur->next;
   }
}

void *timeout_handler(void *arg)
{
    struct timeouts *p = (struct timeouts*)arg;
    struct sr_arp_cache *cur;
    struct pending_packet_count *curCount;
    int counter = 0;
    while(counter < p->timeout_t)
    {
        sleep(1);
        counter++;
    }

    if(p->type == ARP_CACHE)
    {
        pthread_mutex_lock(&queue_mutex);
        cur = arp_cache_head;
        while(cur)
        {
            if(cur->arp_sip == p->ip)
            {
                if(cur->prev != NULL)
                    cur->prev->next = cur->next;
                else arp_cache_head = cur->next;
                if(cur->next != NULL)
                    cur->next->prev = cur->prev;
                free(cur);           
            }

            cur = cur->next;
        }
        pthread_mutex_unlock(&queue_mutex);
    }
    else
    {
        curCount = QUEUE_HEAD;
        while(curCount)
        {
            curCount = curCount->next;
        }
    }
    pthread_exit(NULL);
    return NULL;
}

/*--------------------------------------------------------------------- 
 * Method: add_arp_cache_tuple
 * Scope:  Local
 *
 * Walk the ARP cache to the end and add entry
 * <protocol_type, protocol_address, s_hw_addr> entries
 *
 * @author : Aditya Kousik
 * @date   : 23-09-2014
 *
 *---------------------------------------------------------------------*/

void add_arp_cache_tuple(struct sr_arp_cache *tuple)
{
    struct sr_arp_cache *new;
    struct timeouts *p;

    new = (struct sr_arp_cache*)malloc(sizeof(struct sr_arp_cache));
    new->arp_type = tuple->arp_type; new->arp_sip = tuple->arp_sip;
    new->timestamp = tuple->timestamp;
    memcpy(new->arp_sha, tuple->arp_sha, ETHER_ADDR_LEN);
    new->timeout_thread = (pthread_t *)malloc(sizeof(pthread_t));
    p = (struct timeouts*)malloc(sizeof(struct timeouts));
    p->ip = tuple->arp_sip; p->timeout_t = 15; p->type = ARP_CACHE;
    pthread_create(&new->timeout_thread[0], NULL, timeout_handler, (void *)(p));
    new->next = arp_cache_head;
    
    if(arp_cache_head != NULL)
        arp_cache_head->prev = new;
    arp_cache_head = new;
    new->prev = NULL;
}

/*--------------------------------------------------------------------- 
 * Method: walk_arp_cache
 * Scope:  Local
 *
 * Walk the ARP cache to search for <protocol_address, s_hw_addr> entries
 *
 * @author : Aditya Kousik
 * @date   : 23-09-2014
 *
 *---------------------------------------------------------------------*/

int walk_arp_cache(struct sr_arp_cache *tuple)
{
    int retval = 0;
    struct sr_arp_cache *cur;

    if(arp_cache_head == NULL) return retval;
    cur = arp_cache_head;

    while(cur != NULL)
    {
        if(cur->arp_type == tuple->arp_type && cur->arp_sip == tuple->arp_sip)
        {
            /*There is a <proto_type,sender_address> present. 
             *Let's update its hw_addr */
            memcpy(cur->arp_sha, tuple->arp_sha,ETHER_ADDR_LEN);
            return ++retval;
        }
        cur = cur->next;
    }
    return retval;
}

/*--------------------------------------------------------------------- 
 * Method: sr_lookup_arp_cache
 * Scope:  Local
 *
 * Walk the ARP cache to search for <dest_address, hw_addr> entries
 * Returns the MAC address if found. NULL otherwise.
 * 
 * @author : Aditya Kousik
 * @date   : 23-09-2014
 *
 *---------------------------------------------------------------------*/

int sr_lookup_arp_cache(unsigned char *buf, struct in_addr ip)
{
    int retval = -1;
    struct sr_arp_cache *cur;

    if(arp_cache_head == NULL) retval = -1;
    cur = arp_cache_head;

    while(cur != NULL)
    {
    if(ntohl(cur->arp_sip) == ip.s_addr)
    {
        /* Assuming that if there is an IP entry, it is also 
         * accompanied by the MAC address; the ARP cache was
         * constructed in this way: as <IP,MAC> pairs */
        memcpy(buf, cur->arp_sha, sizeof(unsigned char) * ETHER_ADDR_LEN);  
        retval = 0;
        
    }
    cur = cur->next;
    }
    return retval;
}

/*--------------------------------------------------------------------- 
 * Method: arp_miss_resolv
 * Scope:  Local
 *
 * resolve ARP miss or default gateway hit.
 *
 * @author : Aditya Kousik
 * @date   : 09-10-2014
 *
 *---------------------------------------------------------------------*/
int arp_miss_resolv(struct sr_instance *sr, struct in_addr ip_dst,
        uint8_t dhost[ETHER_ADDR_LEN])
{

    int byteCount, retval;
    struct sr_rt *routing_entry;
    routing_entry = sr_rtable_prefix_lookup(sr, ip_dst);
    uint8_t buf[ETHER_ADDR_LEN];

    /* ZERO! Default gateway. We know where it is.
     * Just foward it. Do this by performing an ARP table lookup
     * on the gw field of RTable entry. That will definitely 
     * generate a hit (NOTE: We are not going to delete the
     * default gw MAC address). Otherwise, the target IP is somewhere
     * in our subnets. THEN issue an ARP REQ */
    if(routing_entry->dest.s_addr == 0)
    {
        retval = sr_lookup_arp_cache(buf, routing_entry->gw);
        /* We've assumed that the gateway MAC address is always in
         * the ARP cache, which is wrong. Check if ARP cache is a hit
         * and only then set it as ERR_RSP_IP_FWD */ 
        if(!retval)
        {
            byteCount = 0;
            while(byteCount < ETHER_ADDR_LEN) 
            {
            dhost[byteCount] = (uint8_t)(buf[byteCount]);
            byteCount++;
            } 
            return ERR_RSP_IP_FWD;
        }
        else 
            {
             memcpy(dhost, gway.arp_sha, ETHER_ADDR_LEN);
         return ERR_RSP_IP_FWD;
            }
    }
        else return ERR_RSP_ARP_REQ_SNET;
}

int arp_addr_resolv(struct sr_instance *sr,
                    uint8_t dhost[ETHER_ADDR_LEN],
                    struct in_addr ip_dst,
                    unsigned char buf[ETHER_ADDR_LEN])
{
    int retval, err_rsp_no, byteCount;
    retval = sr_lookup_arp_cache(buf, ip_dst);
    if(!retval)
    {
        err_rsp_no = ERR_RSP_IP_FWD;
        byteCount = 0;
        while(byteCount < ETHER_ADDR_LEN) 
        {
            dhost[byteCount] = (uint8_t)(buf[byteCount]);
            byteCount++;
        }
    }
    // ARP cache miss.
    else 
    {
        err_rsp_no = arp_miss_resolv(sr, ip_dst, dhost);
    }
    return err_rsp_no;
}
/*--------------------------------------------------------------------- 
 * Method: compute_checksum
 * Scope:  Local
 *
 * Computer checksum of the IP header.
 *
 * @author : Aditya Kousik
 * @date   : 27-09-2014
 *
 *---------------------------------------------------------------------*/

int compute_checksum (uint16_t *twoByte, int size, int fieldNum)
{
    int twoByteCount = 1;
    unsigned long sum = 0;
    int retval = 0, tmp;

    while(twoByteCount <= size/2)
    {

        if(twoByteCount != fieldNum )
        {
            tmp = *twoByte++;
            sum += ntohs(tmp);
        }
        /* Skip the checksum octet */
        else *twoByte++;    
        /* Carry occurred */
        if(sum & 0xffff0000)
        {
            sum &= 0xffff; 
            sum++;
        }
        twoByteCount++; 
    }
    retval = sum;
    return((uint16_t)(~retval));
}

/*--------------------------------------------------------------------- 
 * Method: verify_checksum
 * Scope:  Local
 *
 * Verify checksum of the IP header.
 *
 * @author : Aditya Kousik
 * @date   : 25-09-2014
 *
 *---------------------------------------------------------------------*/

int verify_checksum (uint16_t *twoByte, int size)
{
    int twoByteCount = 0;
    unsigned long sum = 0;
    int retval = 0;

    while(twoByteCount < size/2)
    {
    sum += *(twoByte++);
        
    /* Carry occurred */
    if(sum & 0xffff0000)
    {
        sum &= 0xffff; 
        sum++;
    }
    twoByteCount++; 
    }
    retval = sum;
    return((uint16_t)(~(retval & 0xffff)));
}

/*--------------------------------------------------------------------- 
 * Method: is_addressed_to_eth
 * Scope:  Local
 *
 * Check if the IP packet is destined for the router's interfaces
 *
 * @author : Aditya Kousik
 * @date   : 09-10-2014
 *
 *---------------------------------------------------------------------*/
int is_addressed_to_eth(uint32_t ip, struct sr_instance *sr)
{
    int retval = 1;
    struct sr_if *if_walker = sr->if_list;
    while(if_walker)
    {
    if(if_walker->ip == ip) retval = 0;
    if_walker = if_walker->next;
    }
    return retval;
}


void dequeue_count(struct pending_packet_count *node)
{
    if(node->prev != NULL)
        node->prev->next = node->next;
    else QUEUE_HEAD = node->next;
    if(node->next != NULL)
        node->next->prev = node->prev;
    if(QUEUE_HEAD == NULL)
        QUEUE_TAIL = NULL;
    free(node);
}

void *thread_handler(void *arg)
{
    // TODO set flag checks here for cache and req signals
    struct thread_counter *p = (struct thread_counter*)arg;
    struct pending_packet_count *cur = QUEUE_HEAD;
    struct sr_packet_queue *curPacket = queue_head;
    uint8_t *newPacket, *root;
    int len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr);
    int packetLen;

    struct sr_ethernet_hdr *ethernet_hdr = 0;
    struct sr_instance *sr;
    char *interface;

    while(cur != NULL && cur->ip != p->ip)
        cur = cur->next;

    cur->thread_count.id = p->id;
    cur->thread_count.ip = p->ip;
    cur->thread_count.thread = p->thread;

    while(curPacket != NULL && curPacket->dst_ip.s_addr != p->ip)
        curPacket = curPacket->next;

    newPacket = sr_construct_new_packet(p->mac_vrhost, p->ip_vrhost, 
                                        p->ip, NULL, ERR_RSP_ARP_REQ_SNET); 
 
    ethernet_hdr = (struct sr_ethernet_hdr*)(curPacket->root);
    sr = curPacket->sr;
    root = curPacket->root;
    packetLen = curPacket->len;
    interface = curPacket->interface;

    while(cur->received == 0 && cur->numPacketsSent <= MAX_ARP_REQ)
    {
            sr_send_packet(curPacket->sr, newPacket, len, curPacket->interface);
            cur->numPacketsSent++;
            usleep(750000);
    }
    if(cur->numPacketsSent >= MAX_ARP_REQ) 
    {
        pthread_mutex_lock(&count_mutex);
        sr_forward_packet(sr, ethernet_hdr, root, packetLen, interface, ERR_RSP_ICMP_HU); 
        dequeue_packet(curPacket); 
        pthread_mutex_unlock(&count_mutex);
        cur->numPacketsSent = 0;
        cur->numHostUnreachSent++;
        if(cur->numHostUnreachSent == MAX_ARP_REQ)
        {
            dequeue_count(cur);
            pthread_mutex_lock(&queue_mutex);
            curPacket = queue_head;
            while(curPacket)
            {
                if(curPacket->dst_ip.s_addr == p->ip)
                    dequeue_packet(curPacket);
                curPacket = curPacket->next;
            }
            pthread_mutex_unlock(&queue_mutex);
        }
        pthread_join(*(p->thread), NULL);
    }
    return NULL;
}

void arp_packets(struct ip *ip_hdr, uint32_t ip_vrhost,
                 unsigned char mac_vrhost[ETHER_ADDR_LEN])
{
    struct pending_packet_count *cur;
    cur = increment_wait_counter(ip_hdr->ip_dst, 0);
    while(cur != NULL && cur->ip != ip_hdr->ip_dst.s_addr)
        cur = cur->next;
                                    
    if(cur != NULL)
    {
        if(cur->numPacketsSent <= 1)
        {
            THREAD_COUNT++;
            thread = (pthread_t *)malloc(sizeof(pthread_t));
            p = (struct thread_counter*)malloc(sizeof(struct thread_counter));
            p->id = THREAD_COUNT;
            p->ip = ip_hdr->ip_dst.s_addr;
            p->thread = thread;
            memcpy(p->mac_vrhost, mac_vrhost, ETHER_ADDR_LEN);
                    p->ip_vrhost = ip_vrhost;                        
            pthread_create(&thread[0], NULL, thread_handler, (void *)(p));
        }
    }
}

int sr_arp_handle(struct sr_instance *sr,
                            uint8_t dhost[ETHER_ADDR_LEN], 
                            uint8_t *payload,
                            char* interface)
{
    unsigned long err_rsp_no = -1;
    struct sr_arphdr* arp_hdr;
    struct sr_arp_cache cur;
    unsigned char buf[ETHER_ADDR_LEN];
    int merge_flag, ips_are_same;
    uint32_t ipbuf;

    /* Interface resolutions */
    struct sr_if *if_packet = 0;
    
    /* VR Host IP address and MAC address */
    struct in_addr ip_vrhost;
    unsigned char mac_vrhost[ETHER_ADDR_LEN];
    
    struct pending_packet_count *curCount =QUEUE_HEAD;

    /* Resolve interfaces - where the packet is coming from */
    if_packet = sr_get_interface(sr, interface);
    
    ip_vrhost.s_addr = if_packet->ip;
    memcpy(mac_vrhost, if_packet->addr, ETHER_ADDR_LEN);
    
    arp_hdr = (struct sr_arphdr*)payload; 
    cur.arp_type = arp_hdr->ar_pro; cur.arp_sip = htonl(arp_hdr->ar_sip);
    memcpy(cur.arp_sha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    gettimeofday(&tv, NULL);
    startTime = tv.tv_sec + (tv.tv_usec/1000000.0);
    cur.timestamp = startTime;
    merge_flag = walk_arp_cache(&cur);

    //If the target IP is really mine
    ips_are_same = arp_hdr->ar_tip == *((uint32_t*)&(ip_vrhost));
    if(ips_are_same)
    {
        if(merge_flag == 0)
        {
            add_arp_cache_tuple(&cur);
            //print_arp_cache();
        }
        //else print_arp_cache();
        if(ntohs(arp_hdr->ar_op) == ARP_REQUEST)
        {
            /* Set OPCODE to ARP_REPLY */
            arp_hdr->ar_op = htons(ARP_REPLY);
                
            /* Swap sha and tha fields */
            memcpy(buf, arp_hdr->ar_sha, ETHER_ADDR_LEN);
            memcpy(arp_hdr->ar_sha,arp_hdr->ar_tha, ETHER_ADDR_LEN);
            memcpy(arp_hdr->ar_tha, buf, ETHER_ADDR_LEN);

            /* Set sha to local address */
            memcpy(arp_hdr->ar_sha, mac_vrhost, ETHER_ADDR_LEN);

            /* Swap the sip and tip fields*/
            ipbuf = arp_hdr->ar_sip;
            arp_hdr->ar_sip = arp_hdr->ar_tip;
            arp_hdr->ar_tip = ipbuf;                
                
            /* Issue a send_REPLY  */
            err_rsp_no = ERR_RSP_ARP_REP;
        }
        /* Do nothing with the REPLY packet. 
         * Drop it (after sending queued packets obviously)  */
        else
        {
            while(curCount != NULL && curCount->ip != arp_hdr->ar_sip)
                curCount = curCount->next;
            if(curCount != NULL)
            {
                curCount->numPacketsSent = 0;
                curCount->received = 1;
                dequeue_count(curCount);
                pthread_join(*(curCount->thread_count.thread), NULL);
            }
            pthread_mutex_lock(&queue_mutex);
            _dump_pending_packets(arp_hdr->ar_sip, 1);
            pthread_mutex_unlock(&queue_mutex);
            err_rsp_no = ERR_RSP_ARP_NIL;
            //print_packet_queue();
        }
    }
    return (int)err_rsp_no;
}

int sr_ip_forwarding(struct sr_instance *sr,
                               uint8_t dhost[ETHER_ADDR_LEN], 
                               uint8_t *payload)
{
    int size, retval;
    unsigned long err_rsp_no = -1;
    unsigned char buf[ETHER_ADDR_LEN];
    struct ip *ip_hdr;
    struct icmp *icmp_hdr;
    uint8_t *byte;
    uint16_t *twoByte;

    ip_hdr = (struct ip*)payload;
    byte = (uint8_t*)payload;
    twoByte = (uint16_t*)payload;
                
    /* Get IHL from the last four bits of the MSB */
    size = (*(byte) & 0x0f) << 2;
    /* Use of byte is over. Let's use it for
     * receiving the MAC address from the ARP lookup */
    /* Verify checksum */
    err_rsp_no = verify_checksum(twoByte, size);
    if(err_rsp_no) 
    { err_rsp_no = ERR_RSP_IP_CHKSUM; }

    /* Check the ARP cache for MAC address */
    err_rsp_no = arp_addr_resolv(sr, dhost, ip_hdr->ip_dst, buf);

    /* Verify TTL validity and decrement only if packet is
     * not addressed to this machine's IP */
    retval = is_addressed_to_eth(ip_hdr->ip_dst.s_addr, sr);
    if(retval)
    {
        if(ip_hdr->ip_ttl <= 1)
        { err_rsp_no = ERR_RSP_ICMP_TOUT; }
        else ip_hdr->ip_ttl--;
    }
    /* The IP packet is addressed to this router's 
     * interface. Read what type of IP message it is */
    else
    {
        if(ip_hdr->ip_p == IPPROTO_TCP || 
           ip_hdr->ip_p == IPPROTO_UDP)
        { err_rsp_no = ERR_RSP_ICMP_PU; }
        else if(ip_hdr->ip_p == IPPROTO_ICMP)
        {
            icmp_hdr = (struct icmp*)(payload + sizeof(struct ip));
            if(icmp_hdr->type == ICMP_TYPE_ECHO_REQ)
                err_rsp_no = ERR_RSP_ICMP_ECHO_REP;         
        }
    }
    /* The code would have broken if it hasn't reached this
     * point. So let's compute the checksum and store it 
     * at offset of 10 bytes */
    retval = compute_checksum(twoByte, size, 6);
    ip_hdr->ip_sum = htons(retval);

    return (int)err_rsp_no;
}

/*--------------------------------------------------------------------- 
 * Method: sr_handle_ether_frame
 * Scope:  Global
 *
 * Based on the type (ARP or IP) calls respective methods
 * Returns ARP payload again? or forwards it to another method
 * that encapsulates it with destination and source Ethernet
 * headers?
 *
 * @author : Aditya Kousik
 * @date   : 23-09-2014
 *
 * \TODO Find a way to set the IP address of the vrhost globally
 *
 *---------------------------------------------------------------------*/

int sr_handle_ether_frame(uint8_t dhost[ETHER_ADDR_LEN], 
              uint16_t type, uint8_t* payload, 
              struct sr_instance* sr, char* interface) 
{

    int err_rsp_no;
    err_rsp_no = -1;
    switch(type)
    {
        case ETHERTYPE_ARP: 
                    err_rsp_no = sr_arp_handle(sr, dhost, payload, interface);
                    break;
        case ETHERTYPE_IP : 
                    err_rsp_no = sr_ip_forwarding(sr, dhost, payload);
                    break;
        default : err_rsp_no = -1; break;
        }

    return(err_rsp_no);
}   


/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 * @addendum - @author Aditya Kousik
 * Yank the MAC addresses of the destination and source, and type
 * and pass it along to sr_handle_ether_frame for further processing.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    struct  sr_instance *tmp;
    struct  sr_ethernet_hdr *ethernet_hdr  = 0;
    struct  sr_arphdr *arp_hdr = NULL;
    uint8_t *payload = 0;    
    uint16_t type;
    int err_rsp_no, result;

    tmp = sr;

    printf("\n*** -> Received packet of length %d \n",len);
 
    // For Debugging. Print contents of packet before processing.
    //sr_print_packet_contents(tmp, packet, len, interface);
    
    /*  Begin traversing the packet list */
    ethernet_hdr = (struct sr_ethernet_hdr *) packet;
    payload = (uint8_t *) (packet + sizeof(struct sr_ethernet_hdr));


    if(FIRST_PACKET)
    {
        arp_hdr = (struct sr_arphdr*)(packet + sizeof(struct sr_ethernet_hdr));
        gway.arp_sip = ntohl(arp_hdr->ar_sip);
        memcpy(gway.arp_sha, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
        FIRST_PACKET = 0;
    }

    //Clear the memory - causing too much segfaults
    type = ethernet_hdr->ether_type;
    type = ntohs(type);
 
    err_rsp_no = sr_handle_ether_frame(ethernet_hdr->ether_dhost, 
                       type, payload,
                       sr, interface);
    
    /* Pass on what to do with the packet */
    pthread_mutex_lock(&count_mutex);
    result = sr_forward_packet(sr, ethernet_hdr, packet, len, interface, err_rsp_no);
    pthread_mutex_unlock(&count_mutex);
}/* end sr_handlepacket */

/*--------------------------------------------------------------------- 
 * Method: dequeue_packet
 * Scope:  Local
 *
 * Remove packet from linked list.
 *
 * @author : Aditya Kousik
 * @date   : 08-10-2014
 *
 *---------------------------------------------------------------------*/

void dequeue_packet(struct sr_packet_queue *node)
{
    if(node->prev != NULL)
        node->prev->next = node->next;
    else queue_head = node->next;
    if(node->next != NULL)
        node->next->prev = node->prev;
    if(queue_head == NULL)
        queue_tail = NULL;
    free(node);
}

/*--------------------------------------------------------------------- 
 * Method: _dump_pending_packets
 * Scope:  Local
 *
 * Flush pending packets to the network.
 *
 * @author : Aditya Kousik
 * @date   : 29-09-2014
 *
 *---------------------------------------------------------------------*/

int _dump_pending_packets(uint32_t ip, int sendFlag)
{
    struct sr_packet_queue *cur = queue_head;
    struct sr_ethernet_hdr *ethernet_hdr = 0;
    unsigned char buf[ETHER_ADDR_LEN];
    int len, result, fwdResult;
    uint8_t *newPacket;
    struct    sr_if *if_packet;
    struct ip * ip_hdr;
    unsigned char mac_vrhost[ETHER_ADDR_LEN];
    struct sr_rt* rt_entry;    
    uint32_t      ip_vrhost;
    char *interface;

    while(cur != NULL)
    {
        ethernet_hdr = (struct sr_ethernet_hdr*)cur->root;
        result = arp_addr_resolv(cur->sr, ethernet_hdr->ether_dhost,
                                 *(struct in_addr*)&ip, buf);
        if(sendFlag)
        {
            if(result == ERR_RSP_IP_FWD)
            {
                    
                ip_hdr = (struct ip*) (cur->root + sizeof(struct sr_ethernet_hdr));
          
                rt_entry = sr_rtable_prefix_lookup(cur->sr, ip_hdr->ip_dst); 
            
                interface = rt_entry->interface;
                if_packet = sr_get_interface(cur->sr, interface);
                memcpy(mac_vrhost, if_packet->addr, ETHER_ADDR_LEN);
                ip_vrhost = if_packet->ip;

                fwdResult = sr_forward_packet(cur->sr, ethernet_hdr, cur->root, 
                                      cur->len, cur->interface, result); 
                dequeue_packet(cur);    
            }
            else
            {
                switch(result)
                {
                    case ERR_RSP_ARP_REQ_SNET: 
                                        newPacket = sr_construct_new_packet(mac_vrhost, ip_vrhost, 
                                        ip_hdr->ip_dst.s_addr, NULL, result); 
                                        len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr);
                                        sr_send_packet(cur->sr, newPacket, len, interface);
                                        fwdResult = -1;
                                        break;
                }
            }
        }
        cur = cur->next;

    }
    return fwdResult;
}

/*--------------------------------------------------------------------- 
 * Method: print_packet_queue
 * Scope:  Local
 *
 * Print the local packet queue
 *
 * @author : Aditya Kousik
 * @date   : 29-09-2014
 *
 *---------------------------------------------------------------------*/
void print_packet_queue()
{
    struct sr_packet_queue *cur = queue_head;
    struct pending_packet_count *curCount;

    curCount = QUEUE_HEAD;
    while(cur != NULL)
    {
        printf("\nIP: %s cur %p", inet_ntoa(cur->dst_ip), cur); 
        cur = cur->next;
    }
    while(curCount != NULL)
    {
        printf("\nIP : %s Count : %d ARP sent %d", 
            inet_ntoa(*(struct in_addr*)&curCount->ip), 
            curCount->numPacketsSent,
            curCount->sentARPReq);
        curCount = curCount->next;
    }
}
/*--------------------------------------------------------------------- 
 * Method: increment_wait_counter
 * Scope:  Global
 *
 * Increment wait count on an IP address. Return updated count.
 * 
 * @author : Aditya Kousik
 * @date   : 10-10-2014
 *
 *---------------------------------------------------------------------*/
struct pending_packet_count* increment_wait_counter(struct in_addr ip, int resetVal)
{
    struct pending_packet_count *new, *cur;
    
    cur = QUEUE_HEAD;

    while(cur != NULL && cur->ip != ip.s_addr)
        cur = cur->next;
    if(cur == NULL)
    {
        new = (struct pending_packet_count*)malloc(sizeof(struct pending_packet_count));
        new->ip = ip.s_addr;
        new->received = 0;
        new->numPacketsSent = 1;
        new->sentARPReq = 0;
        new->numHostUnreachSent = 0;
        new->prev = QUEUE_TAIL;
        if(QUEUE_TAIL != NULL)
            QUEUE_TAIL->next = new;
        else
            QUEUE_HEAD = new;
        
        QUEUE_TAIL = new;
        new->next = NULL;
    }
    else
    {
        if(resetVal)
        {
            cur->numPacketsSent = 1;
            cur->received = 0;
            cur->sentARPReq = 0;
        }
    }
    return cur;
}


/*--------------------------------------------------------------------- 
 * Method: enqueue_packet
 * Scope:  Local
 *
 * Enqueue pending packet, usually because the router is waiting for
 * an ARP Reply from the destination.
 * 
 * @author : Aditya Kousik
 * @date   : 29-09-2014
 *
 *---------------------------------------------------------------------*/

void enqueue_packet(struct sr_instance* sr, uint8_t *tmp, unsigned int len,
            char *interface, struct in_addr ip)
{
    struct sr_packet_queue *new;
    
    new = (struct sr_packet_queue*)malloc(sizeof(struct sr_packet_queue));
    new->sr = sr; new->len = len;
    new->interface = interface; new->dst_ip = ip;
    new->root = (uint8_t*)malloc(sizeof(uint8_t) * len);
    memcpy(new->root, tmp, sizeof(uint8_t) * len);

    new->prev = queue_tail;
    if(queue_tail != NULL)
        queue_tail->next = new;
    else
        queue_head = new;
    queue_tail = new;
    new->next = NULL;

    //print_packet_queue();
}

/*--------------------------------------------------------------------- 
 * Method: count_umask_bits
 * Scope:  Global
 *
 * Count the number of bits not masked by subnet mask. 
 * Works only for values of the order 2^n - 1
 * 
 * @author : Aditya Kousik
 * @date   : 26-09-2014
 *
 *---------------------------------------------------------------------*/

int count_umask_bits(uint32_t num)
{
    int count;

    num = ~num;  
    for(count = 0; num; count++) 
    num = num >> 1;
    return count;
}

/*--------------------------------------------------------------------- 
 * Method: sr_rtable_prefix_lookup
 * Scope:  Global
 *
 * Perform longest prefix match for the given IP address from the 
 * rtable entries. Return the tuple with longest prefix match.
 * Return default gateway or drop packet if nothing is found.
 * 
 * @author : Aditya Kousik
 * @date   : 25-09-2014
 *
 *---------------------------------------------------------------------*/
struct sr_rt* sr_rtable_prefix_lookup(struct sr_instance* sr,
                      struct in_addr ip)
{
    struct sr_rt *rtable_entry = 0, *greatest_match = 0;
    uint32_t buf = 0;
    int numBits;
    
    rtable_entry = sr->routing_table;
    if(rtable_entry == 0) return(0);

    while(rtable_entry)
    {
    /* Number of subnet bits as per CIDR  */
    numBits = count_umask_bits(ntohl(rtable_entry->mask.s_addr));

    /* Truncate that many number of bits, because we don't need them */
    buf = ntohl(rtable_entry->dest.s_addr) >> numBits;

    /* Sub the entire value with the ip address  */
    buf = buf - (ntohl(ip.s_addr) >> numBits);
    
    if(greatest_match == 0)
    {
        greatest_match = rtable_entry;
    }
        else if(buf == 0) 
        {
        greatest_match = rtable_entry;
        }

    rtable_entry = rtable_entry->next;
    }
    return greatest_match;
}

/*--------------------------------------------------------------------- 
 * Method: sr_construct_packet
 * Scope:  Global
 *
 * Create a new packet - ARP REQ (or in future, new ICMP types?)
 *
 * @author : Aditya Kousik
 * @date   : 26-09-2014
 *
 *---------------------------------------------------------------------*/
uint8_t* sr_construct_new_packet(unsigned char mac_vrhost[ETHER_ADDR_LEN],
                 uint32_t sip, uint32_t tip, uint8_t *ip_hdr_dgram, int err_rsp_no)
{
    int byteCount, result, bufSize, size;
    uint8_t bufMAC[ETHER_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t *data = 0, *buf;
    uint16_t *twoByte; 
    struct sr_ethernet_hdr *ethernet_hdr = 0;
    struct sr_arphdr *arp_hdr = 0;
    struct ip *ip_hdr = 0;
    struct icmp *icmp_hdr = 0;
    unsigned char tmp[ETHER_ADDR_LEN] = {0};

    switch(err_rsp_no)
    {
    case ERR_RSP_ARP_REQ_SNET:
                  buf = (uint8_t*)malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr));
                  ethernet_hdr = (struct sr_ethernet_hdr*) buf;
                  arp_hdr = (struct sr_arphdr*) (buf + sizeof(struct sr_ethernet_hdr));
                  arp_hdr->ar_hrd = htons(ARPHDR_ETHER);
                  arp_hdr->ar_pro = htons(ETHERTYPE_IP);
                  arp_hdr->ar_hln = ETHER_ADDR_LEN;
                  arp_hdr->ar_pln = IP_ADDR_LEN;
                  arp_hdr->ar_op  = htons(ARP_REQUEST);
                  memcpy(arp_hdr->ar_sha, mac_vrhost, ETHER_ADDR_LEN);
                  arp_hdr->ar_sip = sip;
                  memcpy(arp_hdr->ar_tha, tmp, ETHER_ADDR_LEN);
                  arp_hdr->ar_tip = tip;
                      /* Payload fixed. Now add Ethernet header fields */
                  memcpy(ethernet_hdr->ether_dhost, bufMAC, ETHER_ADDR_LEN);  
                  byteCount = 0;
                  while(byteCount < ETHER_ADDR_LEN) 
                  {  
                    ethernet_hdr->ether_shost[byteCount] = *(uint8_t*)(&mac_vrhost[byteCount]);
                    byteCount++;
                  }
                  ethernet_hdr->ether_type = htons(ETHERTYPE_ARP);
                  break;
    case ERR_RSP_ICMP_TOUT: case ERR_RSP_ICMP_HU: case ERR_RSP_ICMP_PU:
                  bufSize =  sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) +
                             sizeof(struct icmp) + sizeof(uint32_t) +  sizeof(struct ip) + 
                             8;
                  buf = (uint8_t*)malloc(bufSize);
                  ip_hdr = (struct ip*)(buf + sizeof(struct sr_ethernet_hdr));
                  ip_hdr->ip_hl = sizeof(struct ip) / 4;
                  ip_hdr->ip_v = 4;
                  ip_hdr->ip_tos = 0;
                  ip_hdr->ip_len = htons(bufSize - sizeof(struct sr_ethernet_hdr));
                  ip_hdr->ip_id = htons(0x2607);
                  ip_hdr->ip_off = htons(IP_DF);
                  ip_hdr->ip_ttl = 64;
                  ip_hdr->ip_p = IPPROTO_ICMP; 
                  ip_hdr->ip_src.s_addr = sip;
                  ip_hdr->ip_dst.s_addr = tip; 

                  /* Recompute Checksum */
                  size = ip_hdr->ip_hl * 4; twoByte = (uint16_t*)ip_hdr;
                  result = compute_checksum(twoByte, size, 6);
                  ip_hdr->ip_sum = htons(result);

                  icmp_hdr = (struct icmp*) (buf + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
                  switch(err_rsp_no)
                  {
                      case ERR_RSP_ICMP_TOUT: 
                                            icmp_hdr->type = ICMP_TYPE_TOUT;
                                            icmp_hdr->code = ICMP_CODE_TTLXCD;
                                            break;
                      case ERR_RSP_ICMP_PU:
                                            icmp_hdr->type = ICMP_TYPE_DU;
                                            icmp_hdr->code = ICMP_CODE_DU_PU;
                                            break;
                      case ERR_RSP_ICMP_HU:
                                            icmp_hdr->type = ICMP_TYPE_DU;
                                            icmp_hdr->code = ICMP_CODE_DU_HU;
                                            break;
                  }
                  icmp_hdr->checksum = 0;
                  data = (uint8_t*)(buf + sizeof(struct sr_ethernet_hdr) + 
                                 sizeof(struct ip) + sizeof(struct icmp));
                  for(byteCount = 0; byteCount < IP_ADDR_LEN; byteCount++)
                    data[byteCount] = 0;
                  for(byteCount = 0; byteCount < sizeof(struct ip) + 8; byteCount++)
                    data[byteCount + IP_ADDR_LEN] = ip_hdr_dgram[byteCount];
                  twoByte = (uint16_t*)icmp_hdr;
                  result = compute_checksum(twoByte, bufSize - 
                                            sizeof(struct sr_ethernet_hdr) - sizeof(struct ip), 2);
                  icmp_hdr->checksum = htons(result);               
                  break;
    }

    return buf;
}


/*--------------------------------------------------------------------- 
 * Method: sr_forward_packet
 * Scope:  Global
 *
 * Choose what to do with the packet based on the return value from 
 * sr_handle_ethernet_frame
 *
 * @author : Aditya Kousik
 * @date   : 25-09-2014
 *
 *---------------------------------------------------------------------*/
int sr_forward_packet(struct sr_instance* sr, struct sr_ethernet_hdr *ethernet_hdr, 
           uint8_t* packet, unsigned int len, 
           char* interface, int err_rsp_no)
{

    uint8_t       buf[ETHER_ADDR_LEN], *newPacket = 0, *byte;
    struct    sr_if *if_packet;
    int       byteCount = 0, result = -1, size;
    unsigned char mac_vrhost[ETHER_ADDR_LEN];
    struct sr_rt* rt_entry;    
    uint32_t      ip_vrhost;
    uint16_t      *twoByte;
    struct ip*    ip_hdr;
    struct icmp*  icmp_hdr;
    struct in_addr tmp;
    struct pending_packet_count *cur;
    /* Could still be the old packet */
    newPacket = packet; 

    /* Route only if IP packet */
    if(ntohs(ethernet_hdr->ether_type) == ETHERTYPE_IP)
    {
    ip_hdr = (struct ip*) (packet + sizeof(struct sr_ethernet_hdr));
   
        /* Routing is done here. At the network level */
        rt_entry = sr_rtable_prefix_lookup(sr, ip_hdr->ip_dst); 
    
        /* Set the new interface. This holds for ICMP too */
        interface = rt_entry->interface;
    }
    /* Resolve interfaces - where the packet is going to */    
    if_packet = sr_get_interface(sr, interface);
    memcpy(mac_vrhost, if_packet->addr, ETHER_ADDR_LEN);
    ip_vrhost = if_packet->ip;

    /* Choose what to do with the packet */

    switch(err_rsp_no)
    {
    case ERR_RSP_ARP_REQ_SNET: 
                  pthread_mutex_lock(&queue_mutex);
                  enqueue_packet(sr, newPacket, len, interface, ip_hdr->ip_dst); 
                  pthread_mutex_unlock(&queue_mutex);
                  cur = QUEUE_HEAD;
                  while(cur != NULL && cur->ip != ip_hdr->ip_dst.s_addr)
                    cur = cur->next;
                  if(cur == NULL)
                    cur = increment_wait_counter(ip_hdr->ip_dst, 1);
                  else if(cur->numPacketsSent == 0) 
                  {
                    cur = increment_wait_counter(ip_hdr->ip_dst, 1);
                  }
                  if(cur != NULL)
                  {
                    if(cur->sentARPReq == 0)
                    {
                        cur->sentARPReq = 1;                        
                        THREAD_COUNT++;
                        thread = (pthread_t *)malloc(sizeof(pthread_t));
                        p = (struct thread_counter*)malloc(sizeof(struct thread_counter));
                        p->id = THREAD_COUNT;
                        p->ip = ip_hdr->ip_dst.s_addr;
                        p->thread = thread;
                        memcpy(p->mac_vrhost, mac_vrhost, ETHER_ADDR_LEN);
                        p->ip_vrhost = ip_vrhost;                        
                        pthread_create(&thread[0], NULL, thread_handler, (void *)(p));
                    }
                    else usleep(50000);
                  }  
                  break;
    case ERR_RSP_ARP_REP: 
                  /* The payload already has the ARP reply in it. 
                   * Swap the Source and Destination MAC address in the Ethernet header 
                   * and send it back along the receiving interface.
                   */
 
                  memcpy(buf, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
                  memcpy(ethernet_hdr->ether_shost,ethernet_hdr->ether_dhost, ETHER_ADDR_LEN);
                  memcpy(ethernet_hdr->ether_dhost, buf, ETHER_ADDR_LEN);  

                  result = 0;
                  break;
    case ERR_RSP_IP_FWD: 
                   /* ARP cache hit has occurred. The dhost is already  
                   * and send it along the right interface.
                   */
                  result = 0;
                  break;

    case ERR_RSP_ICMP_ECHO_REP:
                  ip_hdr->ip_ttl = 64; tmp = ip_hdr->ip_src; 
                  ip_hdr->ip_src = ip_hdr->ip_dst; ip_hdr->ip_dst = tmp; 
                  /* Recompute Checksum */
                  byte = (uint8_t*)ip_hdr;
                  size = (*(byte) & 0x0f) << 2; twoByte = (uint16_t*)ip_hdr;
                  result = compute_checksum(twoByte, size, 6);
                  ip_hdr->ip_sum = htons(result);


                  icmp_hdr = (struct icmp*) (packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
                  twoByte = (uint16_t*)icmp_hdr;
                  icmp_hdr->type = ICMP_TYPE_ECHO_REPLY;
                  icmp_hdr->code = ICMP_TYPE_ECHO_REPLY;
                  icmp_hdr->checksum = 0;
                  result = compute_checksum(twoByte, 
                            len - sizeof(struct sr_ethernet_hdr) - sizeof(struct ip), 2);
                  icmp_hdr->checksum = htons(result);

                      rt_entry = sr_rtable_prefix_lookup(sr, ip_hdr->ip_dst); 
                      interface = rt_entry->interface;
                      if_packet = sr_get_interface(sr, interface);
                      memcpy(mac_vrhost, if_packet->addr, ETHER_ADDR_LEN);

                  err_rsp_no = arp_addr_resolv(sr, ethernet_hdr->ether_dhost,
                                               ip_hdr->ip_dst, buf);

                  if(err_rsp_no == ERR_RSP_ARP_REQ_GWAY) 
                  {
                    memcpy(ethernet_hdr->ether_dhost, gway.arp_sha, ETHER_ADDR_LEN);
                    result = 0;
                  }
                                   
                  switch(err_rsp_no)
                  {
                      case ERR_RSP_ARP_REQ_SNET: 
                                      pthread_mutex_lock(&queue_mutex);
                                      enqueue_packet(sr, newPacket, len, interface, ip_hdr->ip_dst); 
                                      pthread_mutex_unlock(&queue_mutex);
                                      arp_packets(ip_hdr, ip_vrhost, mac_vrhost);
                                      break;
                  }                                   
     
                  if(err_rsp_no == ERR_RSP_IP_FWD)
                    result = 0;
                  break;
    case ERR_RSP_ICMP_TOUT: case ERR_RSP_ICMP_PU: case ERR_RSP_ICMP_HU:
                  ip_hdr = (struct ip*) (newPacket + sizeof(struct sr_ethernet_hdr));
                  newPacket = sr_construct_new_packet(mac_vrhost, ip_vrhost,
                                                      ip_hdr->ip_src.s_addr, (uint8_t*)ip_hdr, err_rsp_no);
                  len = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) +
                          sizeof(struct icmp) + sizeof(uint32_t) +  sizeof(struct ip) + 8 * sizeof(uint8_t);
                  ethernet_hdr = (struct sr_ethernet_hdr*) newPacket;
                  ethernet_hdr->ether_type = htons(ETHERTYPE_IP);
                  ip_hdr = (struct ip*)(newPacket + sizeof(struct sr_ethernet_hdr));
                  rt_entry = sr_rtable_prefix_lookup(sr, ip_hdr->ip_dst); 
                  interface = rt_entry->interface;
                  if_packet = sr_get_interface(sr, interface);
                  memcpy(mac_vrhost, if_packet->addr, ETHER_ADDR_LEN);
                  ip_vrhost = if_packet->ip;
                  err_rsp_no = arp_addr_resolv(sr, ethernet_hdr->ether_dhost,ip_hdr->ip_dst,buf);
                  switch(err_rsp_no)
                  {
                      case ERR_RSP_ARP_REQ_SNET: 
                                      arp_packets(ip_hdr, ip_vrhost, mac_vrhost);
                                      break;
                  } 
                  if(err_rsp_no == ERR_RSP_ARP_REQ_GWAY) 
                  {
                    memcpy(ethernet_hdr->ether_dhost, gway.arp_sha, ETHER_ADDR_LEN);
                    result = 0;
                  }
                  if(err_rsp_no == ERR_RSP_IP_FWD)
                    result = 0;
                  break;

    default         : break;
    }

    /* Slapping the MAC address of the host - this is fixed 
     * Do this at the last, because swapping shost and dhost 
     * will overwrite the shost value.
     */
    /* Conversion of unsigned char to uint8_t seems to be er.... "pita"  */

    byteCount = 0;
    while(byteCount < ETHER_ADDR_LEN) 
    {
    ethernet_hdr->ether_shost[byteCount] = *(uint8_t*)(&mac_vrhost[byteCount]);
    byteCount++;
    }

    if(!result)
    {
        //printf("\nRight before send:%s", interface); 
        /* For Debugging. Printing contents of packet just before sending it */
        //sr_print_packet_contents(sr, newPacket, len, interface);
        /*Packet is ready and valid. Send it */
        sr_send_packet(sr, newPacket, len, interface);
    }

    
    return(result);
}

/*--------------------------------------------------------------------- 
 * Method: print_ethernet_address
 * Scope:  Global
 *
 * Print Ethernet address in hexa format 
 *
 * @author : Aditya Kousik
 * @date   : 23-09-2014
 *
 *---------------------------------------------------------------------*/

void print_ethernet_address(uint8_t *ethernet_addr)
{
   int byteCount = 0;
    while(byteCount < ETHER_ADDR_LEN)
    {
    if(byteCount > 0 ) printf(":");
    printf("%x", ethernet_addr[byteCount]);
    byteCount++;
    }   
  
}

/*--------------------------------------------------------------------- 
 * Method: sr_print_packet_contents
 * Scope:  Global
 * 
 * This method printsout the contents of the sr_instance packet
 * received. For debugging.
 *
 * @author : Aditya Kousik
 * @date   : 23-09-2014
 *
 *---------------------------------------------------------------------*/

void sr_print_packet_contents(struct sr_instance* sr,
    uint8_t * packet,
    unsigned int len,
    char* iface)
{
    struct sr_ethernet_hdr *ethernet_hdr  = 0;
    struct sr_arphdr *arp_hdr = 0;
    struct ip *ip_hdr = 0;
    assert(sr);

   
    /*  Begin traversing the packet list */
    ethernet_hdr = (struct sr_ethernet_hdr *)packet;

    printf("\nInterface name : %s" ,iface); 
    printf("\n\n------Ethernet frame begins--------");
    
    printf("\nDestination MAC address : \t");
    print_ethernet_address(ethernet_hdr->ether_dhost);

    printf("\nSource MAC address : \t");
    print_ethernet_address(ethernet_hdr->ether_shost);  
    printf("\nEthernet Type : %x", ntohs(ethernet_hdr->ether_type));  
    printf("\n------------End of Ethernet header--------------\n");

    if(ntohs(ethernet_hdr->ether_type) == ETHERTYPE_ARP)
    {
        arp_hdr = (struct sr_arphdr *)(packet + sizeof(struct sr_ethernet_hdr));
        printf("\n\n------------ARP header--------------");
        printf("\nHw addr format: %x\t Protocol addr format: %x\t ARP opcode: %x\t", 
        ntohs(arp_hdr->ar_hrd), ntohs(arp_hdr->ar_pro), ntohs(arp_hdr->ar_op));
        printf("\nHw addr length: %x\t Protocol addr length: %x\t", 
        arp_hdr->ar_hln, arp_hdr->ar_pln);
    printf("\nSender hardware address: ");
    print_ethernet_address((uint8_t*)&arp_hdr->ar_sha);
    printf("\tSender IP address: %s\t", inet_ntoa(*(struct in_addr*)&arp_hdr->ar_sip));
    printf("\nDestination hardware address: ");
    print_ethernet_address((uint8_t*)&arp_hdr->ar_tha);
    printf("\tDestination IP address: %s\t", inet_ntoa(*(struct in_addr*)&arp_hdr->ar_tip));
    printf("\n---------End of ARP header-----------\n");
    }   
    else if(ntohs(ethernet_hdr->ether_type) == ETHERTYPE_IP)
    {
    ip_hdr = (struct ip*) (packet + sizeof(struct sr_ethernet_hdr));
        printf("\n\n------------IP header--------------");
    printf("\nTime to live : %d \tProtocol type : %x \t Checksum : %x \n", ip_hdr->ip_ttl,
        ip_hdr->ip_p, ip_hdr->ip_sum);
    printf("Sender IP address: %s\t", inet_ntoa(ip_hdr->ip_src));
    printf("Destination IP address: %s\t", inet_ntoa(ip_hdr->ip_dst));
    printf("\n---------End of IP header-----------\n");
    }
}
