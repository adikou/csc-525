/*-----------------------------------------------------------------------------
 * file: sr_pwospf.c
 * date: Tue Nov 23 23:24:18 PST 2004
 * Author: Martin Casado
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include "sr_pwospf.h"
#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_err_rsp.h"
#include "sr_if.h" 
#include "sr_rt.h"
#include "pwospf_protocol.h"

/* Custom headers */
#include "sr_fwd_ref.h"
#include "sr_ospf_dstruct.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/time.h>


/* -- Global declarations --- */
pthread_t *hello_thread;
pthread_t *periodic_lsu_thread;
pthread_t *link_upDown_lsu_thread;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;    

#define ALIVE 1
#define DEAD  0

long int rid, aid = 0; 
int *isUp, numInterfaces = 0;

struct sr_ospf_neighbor *neighbors = NULL;
struct timeval tv;
double curTime;
int lsu_seq = 1, vid = 0;

struct graph *subnetGraph = NULL;

/* -- declaration of main thread function for pwospf subsystem --- */
static void* pwospf_run_thread(void* arg);

/*---------------------------------------------------------------------
 * Method: pwospf_lock
 *
 * Lock mutex associated with pwospf_subsys
 *
 *---------------------------------------------------------------------*/

void pwospf_lock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_lock(&subsys->lock) )
    { assert(0); }
} /* -- pwospf_subsys -- */

/*---------------------------------------------------------------------
 * Method: pwospf_unlock
 *
 * Unlock mutex associated with pwospf subsystem
 *
 *---------------------------------------------------------------------*/

void pwospf_unlock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_unlock(&subsys->lock) )
    { assert(0); }
} /* -- pwospf_subsys -- */


/* Graph algorithms */
void swap(int *a, int *b)
{
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

void insert(struct path *S, struct vertexList *u)
{
    struct path* new = (struct path*)malloc(sizeof(struct path));
    memcpy(&new->v, &u->v, sizeof(struct vertex));
    new->next = S;
    S = new;
}

struct vertexList* getVertex(struct graph *G, int id)
{
    struct vertexList *vlWalker = subnetGraph->vList;
    while(vlWalker)
    {
        if(vlWalker->v.id == id)
            return vlWalker;
        vlWalker = vlWalker->next;
    }

    return NULL;   
}

void initSingleSource(struct graph *subnetGraph, struct vertexList *source)
{
    struct vertexList *v;
    v = subnetGraph->vList;
    while(v)
    {
        v->v.d = INF;
        v->v.parent = -1;
        v->v.visited = UNVISITED;
        v = v->next;
    }
    source->v.d = 0;
}

struct vertexList* extract_min(struct vertexList *Q)
{
    int least = INF+1;
    struct vertexList *tmp = NULL;
    while(Q)
    {
        if(Q->v.visited == UNVISITED)
        {
            if(Q->v.d < least)
            {
               least = Q->v.d;
               tmp = Q;
            }
        }
        Q = Q->next;
    }
    return tmp;
}

void relax(struct vertexList*u, struct vertexList *v, int w)
{
    if(v->v.d > u->v.d + w)
    {
        v->v.d = u->v.d + w;
        v->v.parent = u->v.id;
    }
}

void dijkstra(struct graph* G, struct vertexList *s)
{
    struct vertexList *Q, *v, *u;
    initSingleSource(subnetGraph, s);
    struct path *S = NULL;
    struct adjList *e;
    Q = G->vList;
    while(Q != NULL)
    {
        u = extract_min(G->vList);
        if(u)
        {
            u->v.visited = VISITED;
            insert(S, u);
            e = u->v.head;
            while(e)
            {
                v = getVertex(G, e->e.to);
                relax(u, v, e->e.weight);
                e = e->next;
            }
        }
        Q = Q->next;
    }
}

struct graph* initGraph()
{
    struct graph *g = (struct graph*)malloc(sizeof(struct graph));
    g->V= 0;
    g->vList = NULL;

    return g;
}

void printGraph(struct graph *subnetGraph)
{
    struct vertexList *i;
    
    for(i = subnetGraph->vList; i; i = i->next)
    {
        struct adjList *cur = i->v.head;
        printf("\nAdjacency list of vertex %d rid %s ", i->v.id
                    ,inet_ntoa(*(struct in_addr*)&i->v.rid)); 
        printf("snet %s type %d d=%d parent=%d root "
                    ,inet_ntoa(*(struct in_addr*)&i->v.subnet)
                    ,i->v.type
                    ,i->v.d
                    ,i->v.parent);
        while (cur)
        {
            printf("-> %d", cur->e.to); 
            cur = cur->next;
        }
        printf("\n");
    }
}

struct adjList* isEdgePresent(struct graph* subnetGraph, int v, int w)
{
    struct vertexList *cur = subnetGraph->vList;
    struct adjList *edge;

    while(cur)
    {
        edge = cur->v.head;
        while(edge)
        {
            if(edge->e.from == v && edge->e.to == w)
                return edge;
            edge = edge->next;
        }
        cur = cur->next;
    }
    return 0;
}

struct vertexList* getRouterByRid(struct graph *subnetGraph, uint32_t rid)
{
    struct vertexList *vlWalker = subnetGraph->vList;
    while(vlWalker)
    {
        if(vlWalker->v.type == VTYPE_ROUTER && vlWalker->v.rid == rid)
            return vlWalker;
        vlWalker = vlWalker->next;
    }

    return NULL;
}

struct vertexList* getNodeBySubnet(struct graph *subnetGraph, uint32_t subnet, uint32_t rid)
{
    struct vertexList *vlWalker = subnetGraph->vList;
    while(vlWalker)
    {
        if(vlWalker->v.type == VTYPE_SUBNET && vlWalker->v.subnet == subnet 
            && vlWalker->v.rid == rid)
            return vlWalker;
        vlWalker = vlWalker->next;
    }

    return NULL;
}

void addVertex(struct graph *subnetGraph, uint32_t rid, uint32_t subnet, 
               uint32_t nmask, int type)
{
    struct vertexList *vl;
    vl = (struct vertexList*)malloc(sizeof(struct vertexList));
    subnetGraph->V++;
    vl->v.id = vid++;
    vl->v.rid = rid;
    vl->v.subnet = subnet;
    vl->v.nmask = nmask;
    vl->v.latestSeqNum = 0;
    vl->v.type = type;
    vl->v.visited = 0;
    vl->v.head = NULL;
    vl->next = subnetGraph->vList;
    subnetGraph->vList = vl;
}

void addEdge(struct vertexList *v, struct vertexList *w, int weight)
{
    struct adjList *e1 = (struct adjList*)malloc(sizeof(struct adjList));

    e1->e.from = v->v.id; e1->e.to = w->v.id;
    e1->e.weight = weight;

    e1->next = v->v.head;
    v->v.head = e1;
}

void initCurrentRouter(struct graph *subnetGraph)
{
    addVertex(subnetGraph, rid, 0, 0, VTYPE_ROUTER);
}

void addIfaceVertices(struct graph *subnetGraph, struct sr_instance *sr)
{
    struct sr_if *walker = sr->if_list;
    struct vertexList *r = getRouterByRid(subnetGraph, rid);

    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;

    while(walker)
    {
        addVertex(subnetGraph, rid, walker->ip & walker->mask, 
                  walker->mask, VTYPE_SUBNET);
        addEdge(r, subnetGraph->vList, 1);

        dest_addr.s_addr = walker->ip & walker->mask;
        gw_addr.s_addr = 0;
        mask_addr.s_addr = walker->mask;

        sr_add_rt_entry(sr,dest_addr,gw_addr,
                                mask_addr,walker->name);        
        walker = walker->next;
    }
}

/* ********************************** */

long int getProperty(char *propName)
{
    if(strcmp(propName, "rid")== 0)
        return rid;

    return -1;
}

int getNeighbor(uint32_t rid)
{
    int i = 0;
    for(i = 0; i < numInterfaces; ++i)
    {
        if(neighbors[i].rid == rid)
        {
            if(neighbors[i].isAlive == ALIVE)
            {
                return i;
            }
        }
    }
    return 0;
}

uint32_t getNeighborRid(uint32_t subnet)
{
    int i = 0;
    uint32_t tmp;
    for(i = 0; i < numInterfaces; ++i)
    {
        tmp = neighbors[i].ip & neighbors[i].nmask;
        if(tmp == subnet)
        {
            if(neighbors[i].isAlive == ALIVE)
            {
                return neighbors[i].rid;
            }
        }
    }
    return 0;
}

void initNeighbor(int idx)
{
    char iface[10] = "eth", buf[2];
    neighbors[idx].rid = 0;
    neighbors[idx].ip = 0;
    sprintf(buf, "%d", idx);
    strcat(iface, buf);
    neighbors[idx].iface = (char*)malloc(strlen(iface) + 1);
    strcpy(neighbors[idx].iface, iface);
    neighbors[idx].isAlive = ALIVE;
    neighbors[idx].nmask = 0;
    gettimeofday(&tv, NULL);
    curTime = tv.tv_sec;
    neighbors[idx].tstamp = curTime;
}

int getIndex(char *iface)
{
    return iface[3] - (int)'0';
}


void populateRoutingTable(struct graph* G, struct sr_instance *sr)
{
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;

    struct vertexList *walker = G->vList, *u;
    struct sr_rt *cur = sr->routing_table;

    int idx, flag = 10, i;
    while(walker)
    {
        if(walker->v.type == VTYPE_SUBNET)
        {
            u = getVertex(G, walker->v.parent);
            if(u != NULL)
            {
                idx = getNeighbor(u->v.rid);
                dest_addr.s_addr = walker->v.subnet;
                gw_addr.s_addr = neighbors[idx].ip;
                mask_addr.s_addr = walker->v.nmask;

                cur = sr->routing_table;
                while(cur)
                {
                    if(cur->dest.s_addr == walker->v.subnet)
                        flag = 0;
                    cur = cur->next;
                }
                if(flag)
                {
                    sr_add_rt_entry(sr,dest_addr,gw_addr,
                                mask_addr,neighbors[idx].iface);
                   
                }
                else flag  = 10;
            }
        }

        walker = walker->next;
    }

}


int log_hello_pkt(struct sr_instance *sr, uint8_t* packet,
                    int len,
                      char* interface)
{
    uint8_t *payload = (uint8_t*)(packet + sizeof(struct sr_ethernet_hdr));
    uint8_t *newPacket;
    struct sr_if *walker;
    struct ip *ip_hdr = (struct ip*)payload;
    struct ospfv2_hdr *ospf_hdr = (struct ospfv2_hdr*)(payload 
                                  + sizeof(struct ip));
    struct ospfv2_hello_hdr *hello_packet = 
                    (struct ospfv2_hello_hdr*)(payload + sizeof(struct ip)
                                               + sizeof(struct ospfv2_hdr));
    int idx = getIndex(interface);
    int arplen = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr);
    
    unsigned char mac_vrhost[ETHER_ADDR_LEN];

    newPacket = (uint8_t*)malloc(arplen);

    walker = sr_get_interface(sr, interface);
    
    if(hello_packet->nmask != walker->mask)
        return ERR_RSP_OSPF_HEL_NM;
    else if(ntohs(hello_packet->helloint) != OSPF_DEFAULT_HELLOINT)
        return ERR_RSP_OSPF_HEL_HI;

    if(neighbors[idx].rid == 0)
    {
        memcpy(mac_vrhost, walker->addr, ETHER_ADDR_LEN);

        neighbors[idx].rid = ospf_hdr->rid;
        neighbors[idx].ip = ip_hdr->ip_src.s_addr;
        neighbors[idx].nmask = hello_packet->nmask;
        gettimeofday(&tv, NULL);
        curTime = tv.tv_sec;
        neighbors[idx].isAlive = ALIVE;
        neighbors[idx].tstamp = curTime;

        newPacket = sr_construct_new_packet(mac_vrhost, walker->ip, 
                                        neighbors[idx].ip, NULL, 
                                        ERR_RSP_ARP_REQ_SNET); 
        sr_send_packet(sr, newPacket, arplen, walker->name);
    }
    else
    {
        gettimeofday(&tv, NULL);
        curTime = tv.tv_sec;
        neighbors[idx].tstamp = curTime;    
    }

    return 0;

}

int log_lsu_pkt(struct sr_instance *sr, uint8_t* packet,
                int len,
                      char* interface)
{
    int i, byteCount, result;
    uint8_t *payload;
    uint16_t *twoByte;
    long int numAdv;
    struct sr_if *walker;
    payload = (uint8_t*)(packet + sizeof(struct sr_ethernet_hdr));
    struct ospfv2_hdr *ospf_hdr = (struct ospfv2_hdr*)(payload 
                                  + sizeof(struct ip));
    struct ospfv2_lsu_hdr *lsu_hdr;
    struct ospfv2_lsu *lsa, *lsa_pkt;
    struct vertexList *v, *w, *tmp, *s;

    struct sr_ethernet_hdr *ethernet_hdr;
    unsigned char mac_src[ETHER_ADDR_LEN];
    
    lsu_hdr = (struct ospfv2_lsu_hdr*)(payload + sizeof(struct ip)
                                               + sizeof(struct ospfv2_hdr));

    lsa = (struct ospfv2_lsu*)malloc(ntohl(lsu_hdr->num_adv) * sizeof(struct ospfv2_lsu));
    lsa_pkt = (struct ospfv2_lsu*)(payload + sizeof(struct ip)
                                               + sizeof(struct ospfv2_hdr)
                                               + sizeof(struct ospfv2_lsu_hdr));

    numAdv = ntohl(lsu_hdr->num_adv);
    memcpy(lsa, lsa_pkt, numAdv * sizeof(struct ospfv2_lsu));

    if(ospf_hdr->rid == rid)
        return ERR_RSP_OSPF_LSU_DROP;
    else
    {
        tmp = getRouterByRid(subnetGraph, ospf_hdr->rid);
        if(tmp != NULL)
        {
            if(tmp->v.latestSeqNum >= ntohs(lsu_hdr->seq))
                return ERR_RSP_OSPF_LSU_DROP;
            else tmp->v.latestSeqNum = ntohs(lsu_hdr->seq);
        }
    }

    if(getRouterByRid(subnetGraph, ospf_hdr->rid) == NULL)
    {
        addVertex(subnetGraph, ospf_hdr->rid, 0, 0, VTYPE_ROUTER);
        tmp = getRouterByRid(subnetGraph, ospf_hdr->rid);
        tmp->v.latestSeqNum = ntohs(lsu_hdr->seq);
    }
    for(i = 0; i < numAdv; ++i)
    {
        if(getNodeBySubnet(subnetGraph, lsa[i].subnet, ospf_hdr->rid) == NULL)
            addVertex(subnetGraph, ospf_hdr->rid, lsa[i].subnet, 
                      lsa[i].mask, VTYPE_SUBNET);

        v = getRouterByRid(subnetGraph, ospf_hdr->rid);
        w = getNodeBySubnet(subnetGraph, lsa[i].subnet, ospf_hdr->rid);
        
        if(!isEdgePresent(subnetGraph, v->v.id, w->v.id))
            addEdge(v, w, 1);        

        if(lsa[i].rid != 0)
        {
            if(getRouterByRid(subnetGraph, lsa[i].rid) == NULL)
                addVertex(subnetGraph, lsa[i].rid, 0, 0, VTYPE_ROUTER);
        }

        v = getRouterByRid(subnetGraph, ospf_hdr->rid);
        w = getRouterByRid(subnetGraph, lsa[i].rid);

        if(v!= NULL && w!= NULL)   
        {
            if(!isEdgePresent(subnetGraph, v->v.id, w->v.id))
                addEdge(v, w, 1);        
            if(!isEdgePresent(subnetGraph, w->v.id, v->v.id))
                addEdge(w, v, 1);        
        }
        lsu_hdr->ttl--;
        walker = sr->if_list;
        while(walker)
        {
            memcpy(mac_src, walker->addr, ETHER_ADDR_LEN);            
            ethernet_hdr = (struct sr_ethernet_hdr*)packet;
            byteCount = 0;
            while(byteCount < ETHER_ADDR_LEN) 
            {  
                ethernet_hdr->ether_shost[byteCount] = *(uint8_t*)(&mac_src[byteCount]);
                byteCount++;
            }

            twoByte = (uint16_t*)ospf_hdr;
            result = compute_checksum(twoByte, ntohs(ospf_hdr->len), 7);
            ospf_hdr->csum = htons(result);

            if(strcmp(walker->name, interface) != 0)
                sr_send_packet(sr, packet, len, walker->name);
                    
            walker = walker->next;
        }
    }
    s = getRouterByRid(subnetGraph, rid);
    //printGraph(subnetGraph);
    dijkstra(subnetGraph, s);

    /*Let's populate routing table*/
    pwospf_lock(sr->ospf_subsys);
    populateRoutingTable(subnetGraph, sr);
    pwospf_unlock(sr->ospf_subsys);

    /*sr_print_routing_table(sr);
    printf("\n\n\n");*/

    return 0;
}

void sr_handle_pwospf(struct sr_instance *sr, uint8_t* packet,
                      int len,
                      char* interface)
{
    int err_rsp_no;
    uint8_t* payload = (uint8_t*)(packet + sizeof(struct sr_ethernet_hdr));

    struct ospfv2_hdr *ospf_hdr = (struct ospfv2_hdr*)(payload 
                                   + sizeof(struct ip));
    struct ip *ip_hdr = (struct ip*)payload;

    /*Version check*/
    if(ospf_hdr->version != OSPF_V2)
        err_rsp_no = ERR_RSP_OSPF_VER;

    /*Checksum verification*/
    else if(verify_checksum((uint16_t*)ospf_hdr, ntohs(ospf_hdr->len))!= 0)
        err_rsp_no = ERR_RSP_OSPF_CSUM;
    
    /*Area ID validation*/
    else if(ntohl(ospf_hdr->aid) != aid)
        err_rsp_no = ERR_RSP_OSPF_AID;
    
    /*Authentication type match check*/
    else if(ospf_hdr->autype != 0)
        err_rsp_no = ERR_RSP_OSPF_AUTYPE;

    /*IP_Dst must be 0xe0000005*/
    else if(ntohl(ip_hdr->ip_dst.s_addr) != OSPF_AllSPFRouters)
        err_rsp_no = ERR_RSP_OSPF_IP_DST;

    /*PWOSPF Type*/
    else
    {
        if(ospf_hdr->type == OSPF_TYPE_HELLO)
            err_rsp_no = ERR_RSP_OSPF_HELLO;
        else if(ospf_hdr->type == OSPF_TYPE_LSU)
            err_rsp_no = ERR_RSP_OSPF_LSU;
        else err_rsp_no = ERR_RSP_OSPF_TYPE;
    }

    switch(err_rsp_no)
    {
        case ERR_RSP_OSPF_HELLO:
                err_rsp_no = log_hello_pkt(sr, packet, len, interface);
                break;
        case ERR_RSP_OSPF_LSU: 
                err_rsp_no = log_lsu_pkt(sr, packet, len, interface);
                break;
    }
    /*printf("\nOSPF pkt received from %s", interface);
    printf("\nerr_rsp_no = %d", err_rsp_no);*/

}

void* hello_handler(void *arg)
{
    struct sr_instance *sr = (struct sr_instance*)arg;
    struct sr_if *walker = sr->if_list;
    uint8_t* newPacket;
    uint16_t* twoByte;
    uint32_t ip_src;
    unsigned char mac_src[ETHER_ADDR_LEN];
    uint8_t bufMAC[ETHER_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    int len, byteCount, size, result;

    /* Packet headers */
    struct sr_ethernet_hdr *ethernet_hdr;
    struct ip *ip_hdr;
    struct ospfv2_hdr *ospf_hdr;
    struct ospfv2_hello_hdr *hello_packet;

    len = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) +
          sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_hello_hdr);

    while(1)
    {
        pthread_mutex_lock(&mutex);

        walker = sr->if_list;
        while(walker)
        {
            memcpy(mac_src, walker->addr, ETHER_ADDR_LEN);
            ip_src = walker->ip;
            
            newPacket = (uint8_t*)malloc(len);
            ethernet_hdr = (struct sr_ethernet_hdr*)newPacket;
            ethernet_hdr->ether_type = htons(ETHERTYPE_IP);
            memcpy(ethernet_hdr->ether_dhost, bufMAC, ETHER_ADDR_LEN);  
            byteCount = 0;
            while(byteCount < ETHER_ADDR_LEN) 
            {  
                ethernet_hdr->ether_shost[byteCount] = *(uint8_t*)(&mac_src[byteCount]);
                byteCount++;
            }

            ip_hdr = (struct ip*)(newPacket + sizeof(struct sr_ethernet_hdr));
            ip_hdr->ip_hl = sizeof(struct ip) / 4;
            ip_hdr->ip_v = 4;
            ip_hdr->ip_tos = 0;
            ip_hdr->ip_len = htons(len - sizeof(struct sr_ethernet_hdr));
            ip_hdr->ip_id = htons(0x2607);
            ip_hdr->ip_off = htons(IP_DF);
            ip_hdr->ip_ttl = 64;
            ip_hdr->ip_p = IPPROTO_OSPF; 
            ip_hdr->ip_src.s_addr = ip_src;
            ip_hdr->ip_dst.s_addr = htonl(OSPF_AllSPFRouters); 

            /* Recompute Checksum */
            size = ip_hdr->ip_hl * 4; 
            twoByte = (uint16_t*)ip_hdr;
            result = compute_checksum(twoByte, size, 6);
            ip_hdr->ip_sum = htons(result);

            ospf_hdr = (struct ospfv2_hdr*)(newPacket + sizeof(struct sr_ethernet_hdr)
                            + sizeof(struct ip));

            ospf_hdr->version = OSPF_V2;
            ospf_hdr->type = OSPF_TYPE_HELLO;
            ospf_hdr->len = htons(len - sizeof(struct sr_ethernet_hdr) 
                                      - sizeof(struct ip));
            ospf_hdr->rid = rid;
            ospf_hdr->aid = htonl(aid);
            ospf_hdr->autype = 0;
            ospf_hdr->audata = 0;

            hello_packet = (struct ospfv2_hello_hdr*)(newPacket 
                                + sizeof(struct sr_ethernet_hdr)
                                + sizeof(struct ip)
                                + sizeof(struct ospfv2_hdr));

            hello_packet->nmask = walker->mask;  
            hello_packet->helloint = htons(OSPF_DEFAULT_HELLOINT);
            hello_packet->padding = 0;

            twoByte = (uint16_t*)ospf_hdr;
            result = compute_checksum(twoByte, ntohs(ospf_hdr->len), 7);
            ospf_hdr->csum = htons(result);

            //sr_print_packet_contents(sr, newPacket, len, walker->name);
            sr_send_packet(sr, newPacket, len, walker->name);

            walker = walker->next;
        }
        pthread_mutex_unlock(&mutex);
        sleep(OSPF_DEFAULT_HELLOINT);
    }
    return NULL;
}

void* periodic_lsu_handler(void* arg)
{
    struct sr_instance *sr = (struct sr_instance*)arg;
    struct sr_if *walker = sr->if_list, *lsa_walker;
    uint8_t* newPacket;
    uint16_t* twoByte;
    uint32_t ip_src;
    unsigned char mac_src[ETHER_ADDR_LEN];
    uint8_t bufMAC[ETHER_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    int len, byteCount, size, result, numSubnets = 0;
    int i, idx;

    /* Packet headers */
    struct sr_ethernet_hdr *ethernet_hdr;
    struct ip *ip_hdr;
    struct ospfv2_hdr *ospf_hdr;
    struct ospfv2_lsu_hdr *lsu_hdr;
    struct ospfv2_lsu *lsa, *lsa_pkt;

    uint32_t tmp;

    /*Wait for  seconds before next hello packets are received/sent*/
    //sleep(7);

    while(1)
    {
        pthread_mutex_lock(&mutex);
        walker = sr->if_list;
        numSubnets = 0;
        for(i = 0; i < numInterfaces; ++i)
            if(neighbors[i].isAlive == ALIVE)
                numSubnets++;

        len = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) +
              sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr)
              + numSubnets * sizeof(struct ospfv2_lsu);

        while(walker)
        {
            memcpy(mac_src, walker->addr, ETHER_ADDR_LEN);
            ip_src = walker->ip;
            
            newPacket = (uint8_t*)malloc(len);
            ethernet_hdr = (struct sr_ethernet_hdr*)newPacket;
            ethernet_hdr->ether_type = htons(ETHERTYPE_IP);
            memcpy(ethernet_hdr->ether_dhost, bufMAC, ETHER_ADDR_LEN);  
            byteCount = 0;
            while(byteCount < ETHER_ADDR_LEN) 
            {  
                ethernet_hdr->ether_shost[byteCount] = *(uint8_t*)(&mac_src[byteCount]);
                byteCount++;
            }

            ip_hdr = (struct ip*)(newPacket + sizeof(struct sr_ethernet_hdr));
            ip_hdr->ip_hl = sizeof(struct ip) / 4;
            ip_hdr->ip_v = 4;
            ip_hdr->ip_tos = 0;
            ip_hdr->ip_len = htons(len - sizeof(struct sr_ethernet_hdr));
            ip_hdr->ip_id = htons(0x2607);
            ip_hdr->ip_off = htons(IP_DF);
            ip_hdr->ip_ttl = 64;
            ip_hdr->ip_p = IPPROTO_OSPF; 
            ip_hdr->ip_src.s_addr = ip_src;
            ip_hdr->ip_dst.s_addr = htonl(OSPF_AllSPFRouters); 

            /* Recompute Checksum */
            size = ip_hdr->ip_hl * 4; 
            twoByte = (uint16_t*)ip_hdr;
            result = compute_checksum(twoByte, size, 6);
            ip_hdr->ip_sum = htons(result);

            ospf_hdr = (struct ospfv2_hdr*)(newPacket + sizeof(struct sr_ethernet_hdr)
                            + sizeof(struct ip));

            ospf_hdr->version = OSPF_V2;
            ospf_hdr->type = OSPF_TYPE_LSU;
            ospf_hdr->len = htons(len - sizeof(struct sr_ethernet_hdr) 
                                      - sizeof(struct ip));
            ospf_hdr->rid = rid;
            ospf_hdr->aid = htonl(aid);
            ospf_hdr->autype = 0;
            ospf_hdr->audata = 0;

            lsu_hdr = (struct ospfv2_lsu_hdr*)(newPacket + sizeof(struct sr_ethernet_hdr)
                        + sizeof(struct ip) + sizeof(struct ospfv2_hdr));

            lsu_hdr->seq = htons(lsu_seq);
            lsu_hdr->unused = 0;
            lsu_hdr->ttl = 64;
            lsu_hdr->num_adv = htonl(numInterfaces);

            lsa = (struct ospfv2_lsu*)malloc(numSubnets * sizeof(struct ospfv2_lsu));
            lsa_pkt = (struct ospfv2_lsu*) (newPacket + sizeof(struct sr_ethernet_hdr)
                        + sizeof(struct ip) + sizeof(struct ospfv2_hdr)
                        + sizeof(struct ospfv2_lsu_hdr));
            lsa_walker = sr->if_list;
            i = 0;
            while(lsa_walker)
            {
                lsa[i].subnet = lsa_walker->ip & lsa_walker->mask;
                lsa[i].mask = lsa_walker->mask;

                tmp = getNeighborRid(lsa[i].subnet);
                lsa[i].rid = tmp;

                if(tmp == 0)
                {
                    idx = getNeighbor(0);
                    if(getIndex(neighbors[idx].iface) == 0)
                    {
                        lsa[i].subnet = 0;
                        lsa[i].mask = 0;
                    }
                }

                lsa_walker = lsa_walker->next;
                ++i;
            }
            memcpy(lsa_pkt, lsa,
                        numSubnets * sizeof(struct ospfv2_lsu));

            twoByte = (uint16_t*)ospf_hdr;
            result = compute_checksum(twoByte, ntohs(ospf_hdr->len), 7);
            ospf_hdr->csum = htons(result);

            //sr_print_packet_contents(sr, newPacket, len, walker->name);
            sr_send_packet(sr, newPacket, len, walker->name);

            walker = walker->next;
        }
        pthread_mutex_unlock(&mutex);
        sleep(OSPF_DEFAULT_LSUINT);
        lsu_seq++;
    }
    return NULL;
}

void* link_upDown_lsu_handler(void *arg)
{
    return NULL;
}

/*---------------------------------------------------------------------
 * Method: pwospf_init(..)
 *
 * Sets up the internal data structures for the pwospf subsystem
 *
 * You may assume that the interfaces have been created and initialized
 * by this point.
 *---------------------------------------------------------------------*/

int pwospf_init(struct sr_instance* sr)
{
    struct sr_if *walker;
    int i;
    assert(sr);

    walker = sr->if_list;
    while(walker)
    {
        if(numInterfaces == 0)
            rid = walker->ip;
        numInterfaces++;
        walker = walker->next;
    }
    sr->ospf_subsys = (struct pwospf_subsys*)malloc(sizeof(struct
                                                      pwospf_subsys));

    assert(sr->ospf_subsys);
    pthread_mutex_init(&(sr->ospf_subsys->lock), 0);


    /* -- handle subsystem initialization here! -- */
    hello_thread = (pthread_t*)malloc(sizeof(pthread_t));
    periodic_lsu_thread = (pthread_t*)malloc(sizeof(pthread_t));
    link_upDown_lsu_thread = (pthread_t*)malloc(sizeof(pthread_t));

    isUp = (int*)malloc(numInterfaces * sizeof(int));
    neighbors = (struct sr_ospf_neighbor*)malloc(numInterfaces 
                                          * sizeof(struct sr_ospf_neighbor));

    for(i = 0; i < numInterfaces; ++i)
    {
        isUp[i] = ALIVE;
        initNeighbor(i);
    }

    fill_arp_cache(sr);

    subnetGraph = initGraph();
    initCurrentRouter(subnetGraph);
    addIfaceVertices(subnetGraph, sr);

    /* -- start thread subsystem -- */
    if( pthread_create(&sr->ospf_subsys->thread, 0, pwospf_run_thread, sr)) {
        perror("pthread_create");
        assert(0);
    }
    
    if( pthread_create(&hello_thread[0], NULL, hello_handler, sr)) 
    {
        perror("pthread_create");
        assert(0);
    }
    
    if( pthread_create(&periodic_lsu_thread[0], NULL, periodic_lsu_handler, sr))
    {
        perror("pthread_create");
        assert(0);
    }
    
    if( pthread_create(&link_upDown_lsu_thread[0], NULL, link_upDown_lsu_handler, sr))
    {
        perror("pthread_create");
        assert(0);
    }
    return 0; /* success */
} /* -- pwospf_init -- */

/*---------------------------------------------------------------------
 * Method: pwospf_run_thread
 *
 * Main thread of pwospf subsystem.
 *
 *---------------------------------------------------------------------*/

static
void* pwospf_run_thread(void* arg)
{
    struct sr_instance* sr = (struct sr_instance*)arg;
    int i;

    while(1)
    {
        /* -- PWOSPF subsystem functionality should start  here! -- */

        pwospf_lock(sr->ospf_subsys);
        //printf(" pwospf subsystem sleeping \n");
        pthread_mutex_lock(&mutex);
        /*printf("\nNeighbors ");
        printf("\nRID\t\tIP\t\tIface");
                
        for(i = 0; i < numInterfaces; ++i)
        {
            printf("\n%s", inet_ntoa(*(struct in_addr*)&neighbors[i].rid));
            printf("\t%s\t%s", inet_ntoa(*(struct in_addr*)&neighbors[i].ip)
                                , neighbors[i].iface);
        }*/

        pthread_mutex_unlock(&mutex);
        pwospf_unlock(sr->ospf_subsys);
        sleep(2);
        //printf(" pwospf subsystem awake \n");
    };

    return NULL;    
} /* -- run_ospf_thread -- */

