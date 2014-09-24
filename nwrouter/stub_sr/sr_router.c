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
#include <stdint.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
//Added ARP cache include - AK
#include "sr_arp_cache.h"

void sr_print_packet_contents(struct sr_instance*, uint8_t*, unsigned int , char*);
/*Initialise an empty ARP cache */
struct sr_arp_cache *arp_cache_root = 0;


/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 * \TODO Perhaps initialise ARP cache here? 
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr) 
{
    /* REQUIRES */
    assert(sr);

    /* Add initialization code here! */
    /* Set IP of vrhost to be visible globally */
    struct in_addr *ip_vrhost = 0;
    inet_aton("172.29.10.136", ip_vrhost);

  } /* -- sr_init -- */

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

void add_arp_cache_tuple(struct sr_arp_cache tuple)
{
    int fail = 0;
    struct sr_arp_cache *root, *new;
    root = arp_cache_root; 

    while(root = root->next) { } 
    new = (struct sr_arp_cache*) malloc(sizeof(struct sr_arp_cache));
    new->arp_type = tuple.arp_type; new->arp_sip = tuple.arp_sip;
    memcpy((void*)&new->arp_sha, (void*)&tuple.arp_sha, ETHER_ADDR_LEN);
    new->next = NULL; 
    if(root == NULL) root = new;
        else root->next = new;
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

int walk_arp_cache(struct sr_arp_cache tuple)
{
    int fail = 0;
    struct sr_arp_cache *root = arp_cache_root;
    while(root->next)
    {
	if(root->arp_type == tuple.arp_type && root->arp_sip == tuple.arp_sip)
	{
	    /*There is a <proto_type,sender_address> present. 
	     *Let's update its hw_addr */
	    memcpy((void*)&root->arp_sha, (void*)(&tuple.arp_sha),ETHER_ADDR_LEN);
	    return ++fail;
	}
	root = root->next;
    }
    return fail;
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

int sr_handle_ether_frame(uint8_t* dhost, uint8_t* shost, 
	uint16_t type, uint8_t* payload)
{

    int errno = 0, merge_flag;
    struct sr_arphdr *arp_hdr;
    struct sr_arp_cache cur;

    struct ip *ip_hdr;
	
    switch(type)
    {
	case ETHERTYPE_ARP: arp_hdr = (struct sr_arphdr*)payload;
			    cur.arp_type = type; cur.arp_sip = arp_hdr->ar_sip;
			    memcpy((void*)&cur.arp_sha, (void*)&arp_hdr->ar_sha, ETHER_ADDR_LEN);
			    merge_flag = walk_arp_cache(cur);
			    //If the target IP is really mine
			    if(1) 
			    {
				if(merge_flag == 0)
				    add_arp_cache_tuple(cur);
				if(arp_hdr->ar_op == ARP_REQUEST)
				{
				}
					
			    }
			    break;
	case ETHERTYPE_IP : break;
	default : errno = -1; break;
    }

    return(errno);
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
 * Yank the MAC addresses of the destination adn source, and type
 * and pass it along to sr_handle_ether_frame for type
 *
 * \TODO Sender MAC Address is hard-coded for now.
 * Use resolve_ethernet_address for this.
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

    struct sr_instance *tmp;
    struct sr_ethernet_hdr *ethernet_hdr  = 0;
    uint8_t dest_addr[ETHER_ADDR_LEN], src_addr[ETHER_ADDR_LEN], *payload = 0;    
    uint16_t type;

    tmp = sr;

    printf("*** -> Received packet of length %d \n",len);
    // Skip this print call for now. Used only for debugging
    //sr_print_packet_contents(tmp, packet, len, interface);

    /*  Begin traversing the packet list */
    ethernet_hdr = (struct sr_ethernet_hdr *)packet;
    memcpy((void*)&dest_addr, (void*)&ethernet_hdr->ether_dhost, ETHER_ADDR_LEN);
    memcpy((void*)&src_addr, (void*)&ethernet_hdr->ether_shost, ETHER_ADDR_LEN);   
    memcpy((void*)&type, (void*)&ethernet_hdr->ether_type, sizeof(uint16_t));
    type = ntohs(type);
    payload = (uint8_t*)(packet + sizeof(struct sr_ethernet_hdr)); 

    sr_handle_ether_frame(dest_addr, src_addr, type, payload); 

}/* end sr_ForwardPacket */

/*--------------------------------------------------------------------- 
 * Method: resolve_ethernet_address
 * Scope:  Global
 *
 * Run system calls to find out mac address of current router
 * and return the MAC address. 
 *
 * @author : Aditya Kousik
 * @date   : 23-09-2014
 *
 *---------------------------------------------------------------------*/

/* TODO FINISH THIS FUNCTION!! Either use syscalls or resolve into some
 * tangible data structure
 */

void resolve_ethernet_address()
{
    char *fname = "/sys/class/net/eth0/address", *buf;
    FILE *fp;
    uint8_t hw_addr[ETHER_ADDR_LEN];

    fp = fopen(fp, "r");	
    
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

    assert(sr);

    printf("----------Contents of sr_instance---------\n");
    printf("Socket FD: %d\t User name: %s\t Hostname: %s\t Hostfile name : %s\n", sr->sockfd, sr->user, sr->host, sr->auth_key_fn);
    printf("Topology id: %d\t", sr->topo_id);
    printf("Interface: %s\n", iface);
    
    /*  Begin traversing the packet list */
    ethernet_hdr = (struct sr_ethernet_hdr *)packet;
    arp_hdr = (struct sr_arphdr *)(packet + sizeof(struct sr_ethernet_hdr));

    printf("\n\n------Ethernet frame begins--------");
    
    printf("\nDestination MAC address : \t");
    print_ethernet_address(ethernet_hdr->ether_dhost);

    printf("\nSource MAC address : \t");
    print_ethernet_address(ethernet_hdr->ether_shost);	
    printf("\nEthernet Type : %x", ntohs(ethernet_hdr->ether_type));  
    printf("\n------------End of Ethernet header--------------");

    printf("\n\n------------ARP header--------------");
    printf("\nHw addr format: %x\t Protocol addr format: %x\t ARP opcode: %x\t", 
            ntohs(arp_hdr->ar_hrd), ntohs(arp_hdr->ar_pro), ntohs(arp_hdr->ar_op));

    printf("\nSender hardware address: ");
    print_ethernet_address((uint8_t*)&arp_hdr->ar_sha);
    printf("\tSender IP address: %s\t", inet_ntoa(*(struct in_addr*)&arp_hdr->ar_sip));
    printf("\nDestination hardware address: ");
    print_ethernet_address((uint8_t*)&arp_hdr->ar_tha);
    printf("\tDestination IP address: %s\t", inet_ntoa(*(struct in_addr*)&arp_hdr->ar_tip));
    printf("\n---------End of ARP header-----------\n");
 	
    
}
