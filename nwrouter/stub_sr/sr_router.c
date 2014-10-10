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

/* Local includes  */
#include "sr_arp_cache.h"
#include "sr_err_rsp.h"
#include "sr_fwd_ref.h"
#include "sr_packet_queue.h"
#include "sr_icmp.h"

/* Number of packets_queued */
int PACKETS_QUEUED = 0;

/*Initialise an empty ARP cache */
struct sr_arp_cache *arp_cache_root = NULL; 

/* Initialise empty packet queue  */
struct sr_packet_queue *queue_head = NULL;

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
    struct sr_arp_cache *cur = arp_cache_root;
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
    struct sr_arp_cache *cur, *new;
    
    new = (struct sr_arp_cache*)malloc(sizeof(struct sr_arp_cache));
    new->arp_type = tuple->arp_type; new->arp_sip = tuple->arp_sip;
    memcpy(new->arp_sha, tuple->arp_sha, ETHER_ADDR_LEN);
    new->next = NULL;
    
    if(arp_cache_root == NULL)
    { 
	arp_cache_root = new;
    }
    else
    {		    
    	    cur = arp_cache_root; 
	    while(cur->next != NULL) { cur = cur->next; } 
	    cur->next = new;
    }
        
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

    if(arp_cache_root == NULL) return retval;
    cur = arp_cache_root;

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

    if(arp_cache_root == NULL) retval = -1;
    cur = arp_cache_root;

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
    	printf("\nDefault Gateway hit!");
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
	else return ERR_RSP_ARP_REQ_GWAY;
    }
    else
    {
	return ERR_RSP_ARP_REQ_SNET;
    }
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
			  uint8_t shost[ETHER_ADDR_LEN], 
			  uint16_t type, uint8_t* payload, 
			  struct sr_instance* sr, char* interface) 
{

    /* ARP declarations */
    int 	  merge_flag, ips_are_same;
    struct 	  sr_arphdr *arp_hdr;
    struct 	  sr_arp_cache cur;
    unsigned char buf[ETHER_ADDR_LEN];
    unsigned long err_rsp_no;
    struct sr_rt* routing_entry = 0;

    /* IP declarations */
    uint32_t      ipbuf;
    struct ip     *ip_hdr;
    uint8_t	  *byte;
    uint16_t      *twoByte;
    int       	  byteCount, size, retval;
    struct icmp   *icmp_hdr;    

    /* Interface resolutions */
    struct sr_if *if_packet = 0;
    
    /* VR Host IP address and MAC address */
    struct in_addr ip_vrhost;
    unsigned char mac_vrhost[ETHER_ADDR_LEN];
    

    /* Resolve interfaces - where the packet is coming from */
    if_packet = sr_get_interface(sr, interface);
    
    ip_vrhost.s_addr = if_packet->ip;
    printf("\nvrhost IP address: %s", inet_ntoa(ip_vrhost));
    
    memcpy(mac_vrhost, if_packet->addr, ETHER_ADDR_LEN);
    printf("\nvrhost MAC address: ");
    print_ethernet_address((uint8_t*)mac_vrhost);
  
    err_rsp_no = -1;
    switch(type)
    {
	case ETHERTYPE_ARP: 
			    arp_hdr = (struct sr_arphdr*)payload; 
			    cur.arp_type = arp_hdr->ar_pro; cur.arp_sip = htonl(arp_hdr->ar_sip);
			    memcpy(cur.arp_sha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
			    merge_flag = walk_arp_cache(&cur);
			    printf("\nMerge flag :: %d", merge_flag);


			    //If the target IP is really mine
			    ips_are_same = arp_hdr->ar_tip == *((uint32_t*)&(ip_vrhost));
			    if(ips_are_same)
			    {
				if(merge_flag == 0)
				{
				    add_arp_cache_tuple(&cur);
				    print_arp_cache();
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
				/* Do nothing with the REPLY packet. Drop it  */
				else
				{
				    printf("\nARP REPLY: PRINT ARP CACHE NOW");
				    print_arp_cache();
				    _dump_pending_packets(arp_hdr->ar_sip);
				    err_rsp_no = ERR_RSP_ARP_NIL;
				}
					
			    }
			    break;
	case ETHERTYPE_IP : 
			    ip_hdr = (struct ip*)payload;
			    byte = (uint8_t*)payload;
			    twoByte = (unsigned int*)payload;
			    
			    /* Get IHL from the last four bits of the MSB */
			    size = (*(byte) & 0x0f) << 2;
			    /* Use of byte is over. Let's use it for
			     * receiving the MAC address from the ARP lookup */

			    /* Verify checksum */
			    err_rsp_no = verify_checksum(twoByte, size);
			    if(err_rsp_no) 
			    { err_rsp_no = ERR_RSP_IP_CHKSUM;  break; }

			    /* Check the ARP cache for MAC address */
			    print_arp_cache();
			    retval = sr_lookup_arp_cache(buf, ip_hdr->ip_dst);
			    /* Found the MAC address. Set it to the ethernet 
			     * header dhost */
			    if(!retval)
			    {
				printf("\nARPhit");
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
				 err_rsp_no = arp_miss_resolv(sr, ip_hdr->ip_dst, dhost);
			    }

			    /* Verify TTL validity and decrement only if packet is
			     * not addressed to this machine's IP */
			    retval = is_addressed_to_eth(ip_hdr->ip_dst.s_addr, sr);
			    printf("\nIs addressed to eth: %d", retval);
			    if(retval)
			    {
			        if(ip_hdr->ip_ttl <= 0)
			        { err_rsp_no = ERR_RSP_ICMP_TOUT; break; }
				    else ip_hdr->ip_ttl--;
			    }
			    /* The IP packet is addressed to this router's 
			     * interface. Read what type of IP message it is */
			    else
			    {
				if(ntohs(ip_hdr->ip_p) == IPPROTO_TCP || 
				   ntohs(ip_hdr->ip_p) == IPPROTO_UDP)
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
    uint8_t *payload = 0;    
    uint16_t type;
    int err_rsp_no, result;

    tmp = sr;

    printf("\n*** -> Received packet of length %d \n",len);
 
    // For Debugging. Print contents of packet before processing.
    sr_print_packet_contents(tmp, packet, len, interface);
    
    /*  Begin traversing the packet list */
    ethernet_hdr = (struct sr_ethernet_hdr *) packet;
    payload = (uint8_t *) (packet + sizeof(struct sr_ethernet_hdr));

    //Clear the memory - causing too much segfaults
    type = ethernet_hdr->ether_type;
    type = ntohs(type);
 
    err_rsp_no = sr_handle_ether_frame(ethernet_hdr->ether_dhost, 
				       ethernet_hdr->ether_shost, 
				       type, payload,
   				       sr, interface);
    
    /* Pass on what to do with the packet */
    result = sr_forward_packet(sr, ethernet_hdr, packet, len, interface, err_rsp_no);

}/* end sr_ForwardPacket */

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

struct sr_packet_queue* dequeue_packet()
{
    struct sr_packet_queue *cur = queue_head;
    if(cur == NULL) return cur;
    else 
    {
	queue_head = cur->next;
	cur->next = NULL;
	free(cur);
	return queue_head;
    }
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

void _dump_pending_packets(uint32_t ip)
{
    struct sr_packet_queue *cur = queue_head, *tmp;
    struct sr_ethernet_hdr *ethernet_hdr = 0;
    unsigned char buf[ETHER_ADDR_LEN];
    int retval = 0, byteCount;

    tmp = cur;
    while(cur != NULL)
    {
	if(cur->dst_ip.s_addr == ip)
	{
	    retval = sr_lookup_arp_cache(buf, *(struct in_addr*)&ip);
	    if(!retval)
	    {
		ethernet_hdr = (struct sr_ethernet_hdr*)cur->root;

	    	byteCount = 0;
	    	while(byteCount < ETHER_ADDR_LEN) 
	    	{
		    ethernet_hdr->ether_dhost[byteCount] = (uint8_t)(buf[byteCount]);
		    byteCount++;
	        }
	    	printf("\nInside dump : ");
	    	ethernet_hdr->ether_type = htons(ETHERTYPE_IP);
	    	byteCount = 0;
	    	while(byteCount < cur->len)
   	    	{
		    printf("%x ", *(cur->root + byteCount * sizeof(uint8_t)));
		    byteCount++;
	    	}
	        sr_print_packet_contents(cur->sr, cur->root, cur->len, cur->interface);
	        sr_forward_packet(cur->sr, ethernet_hdr, cur->root, 
				  cur->len, cur->interface, ERR_RSP_IP_FWD); 
		tmp = dequeue_packet();
	    }
	}

	cur = tmp;
    }
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
    int byteCount = 0;
    printf("\nDestination IP");
    while(cur != NULL)
    {
	printf("IP: \n%s ", inet_ntoa(*(struct in_addr*)&cur->dst_ip.s_addr)); 
	while(byteCount < cur->len)
	{
	    byteCount++;
	    printf("\n%x ", *(cur->root + sizeof(uint8_t) * byteCount)); 
	}
	cur = cur->next;
    }
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
    struct sr_packet_queue *cur, *new;
    uint8_t *buf = 0;
    int byteCount;

    new = (struct sr_packet_queue*)malloc(sizeof(struct sr_packet_queue));
    new->sr = sr; new->len = len;
    new->interface = interface; new->dst_ip = ip;
    new->next = NULL; 
    new->root = (uint8_t*)malloc(sizeof(uint8_t) * len);
    buf = new->root;
    printf("\nNew memory location allocated for root : %x", new->root);
    printf("\nContents: ");
    memcpy(new->root, tmp, sizeof(uint8_t) * len);

    while(byteCount < len)
    {
	//*(new->root + byteCount * sizeof(uint8_t)) = *tmp + byteCount * sizeof(uint8_t); 
	printf("%x ", *(buf + byteCount * sizeof(uint8_t)));
	byteCount++;
    }
    if(queue_head == NULL)
    { 
	queue_head = new;
    }
	else
	{
	    cur = queue_head;	    
	    while(cur->next != NULL) { cur = cur->next; } 
	    cur->next = new;
	}
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
				 uint32_t sip, uint32_t tip, int err_rsp_no)
{
    int byteCount;
    uint8_t *buf = 0, bufMAC[ETHER_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    struct sr_ethernet_hdr *ethernet_hdr = 0;
    struct sr_arphdr *arp_hdr = 0;
    struct icmp *icmp_hdr = 0;
    unsigned char tmp[ETHER_ADDR_LEN] = {0};

    buf = (uint8_t*)malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr));
    ethernet_hdr = (struct sr_ethernet_hdr*) buf;
    switch(err_rsp_no)
    {
	case ERR_RSP_ARP_REQ_GWAY: case ERR_RSP_ARP_REQ_SNET:
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
			      break;
    }

    /* Payload fixed. Now add Ethernet header fields */
    memcpy(ethernet_hdr->ether_dhost, bufMAC, ETHER_ADDR_LEN);  
    byteCount = 0;
    while(byteCount < ETHER_ADDR_LEN) 
    {
	ethernet_hdr->ether_shost[byteCount] = *(uint8_t*)(&mac_vrhost[byteCount]);
	byteCount++;
    }
    ethernet_hdr->ether_type = htons(ETHERTYPE_ARP);
  
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

    uint8_t 	  buf[ETHER_ADDR_LEN], *newPacket = 0, *byte;
    struct 	  sr_if *if_packet;
    int 	  byteCount = 0, result = -1, size;
    unsigned char mac_vrhost[ETHER_ADDR_LEN];
    struct sr_rt* rt_entry;    
    uint32_t	  ip_vrhost;
    uint16_t	  *twoByte;
    struct ip*    ip_hdr;
    struct icmp*  icmp_hdr;
    struct in_addr tmp;

    /* Could still be the old packet */
    newPacket = packet; 

    /* Route only if IP packet */
    if(ntohs(ethernet_hdr->ether_type) == ETHERTYPE_IP)
    {
	ip_hdr = (struct ip*) (packet + sizeof(struct sr_ethernet_hdr));
   
        /* Routing is done here. At the network level */
    	rt_entry = sr_rtable_prefix_lookup(sr, ip_hdr->ip_dst); 
    
    	/* Set the new interface. This holds for ICMP too */
    	interface = &(rt_entry->interface);
    }
    /* Resolve interfaces - where the packet is going to */    
    if_packet = sr_get_interface(sr, interface);
    memcpy(mac_vrhost, if_packet->addr, ETHER_ADDR_LEN);
    ip_vrhost = if_packet->ip;

    /* Choose what to do with the packet */

    switch(err_rsp_no)
    {
	case ERR_RSP_ARP_REQ_SNET: 
			      enqueue_packet(sr, newPacket, len, interface, ip_hdr->ip_dst); 
			      newPacket = sr_construct_new_packet(mac_vrhost, ip_vrhost, 
								  ip_hdr->ip_dst.s_addr, ERR_RSP_ARP_REQ_SNET); 
			      /* ARP packet. There's only gonna be eth_hdr and arp_hdr  */
			      len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr);
			      result = 0;
			      break;
	case ERR_RSP_ARP_REQ_GWAY: 
			      enqueue_packet(sr, newPacket, len, interface, rt_entry->gw); 
			      newPacket = sr_construct_new_packet(mac_vrhost, ip_vrhost, 
								  rt_entry->gw.s_addr, ERR_RSP_ARP_REQ_GWAY); 
			      /* ARP packet. There's only gonna be eth_hdr and arp_hdr  */
			      len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr);
			      result = 0;
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
			      printf("Size %d, Checkum %x", size, result);
			      ip_hdr->ip_sum = htons(result);


			      icmp_hdr = (struct icmp*) (packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
			      twoByte = (uint16_t*)icmp_hdr;
			      icmp_hdr->type = ICMP_TYPE_ECHO_REPLY;
			      icmp_hdr->code = ICMP_TYPE_ECHO_REPLY;
			      icmp_hdr->checksum = 0;
			      result = compute_checksum(twoByte, 
					 		len - sizeof(struct sr_ethernet_hdr) - sizeof(struct ip), 2);
			      printf("Size %d, Checkum %x", len - sizeof(struct sr_ethernet_hdr) - sizeof(struct ip), result);
			      icmp_hdr->checksum = htons(result);

    			      rt_entry = sr_rtable_prefix_lookup(sr, ip_hdr->ip_dst); 
    			      interface = &(rt_entry->interface);
    			      if_packet = sr_get_interface(sr, interface);
	    		      memcpy(mac_vrhost, if_packet->addr, ETHER_ADDR_LEN);

			      result = arp_miss_resolv(sr, ip_hdr->ip_dst, ethernet_hdr->ether_dhost);
			      if(result == ERR_RSP_ARP_REQ_GWAY) 
				  sr_forward_packet(sr,ethernet_hdr,newPacket,len,interface,result);
			      else result = 0;			

	default		    : break;
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

    printf("\nRight before send:%d %s", result, interface); 
    /* For Debugging. Printing contents of packet just before sending it */
    sr_print_packet_contents(sr, newPacket, len, interface);

  
    /*Packet is ready and valid. Send it */
    if(!result)
    {
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
