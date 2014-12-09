#ifndef SR_OSPF_DSTRUCT_H
#define SR_OSPF_DSTRUCT_H

#include <math.h>

static const int VTYPE_ROUTER = 0;
static const int VTYPE_SUBNET = 1;

struct sr_ospf_neighbor
{
	uint32_t rid;
	uint32_t ip;
	uint32_t nmask;
	char *iface;
	int isAlive;
	double tstamp;
};

/*Heap data structure for dijkstra*/

struct heap
{
	int *A;
	int heap_size;
	int length;
};

/*Graph  data structures*/

struct edge
{
	int from, to;
	int isAlive;
	int weight;
};

struct adjList
{	
	struct edge e;
	struct adjList *next;
};

struct vertex
{
	uint32_t rid;
	uint32_t id;
	int type;
	uint32_t subnet;
	int d, parent;
	int latestSeqNum;
	struct adjList *head;
};

struct vertexList
{
	struct vertex v;
	struct vertexList *next;
};

struct graph
{
	int V;
	struct vertexList *vList;
};

int parent(int);
int left(int);
int right(int);
void min_heapify(struct heap*, int);
int extrace_min(struct heap*);

struct graph* initGraph();
void addVertex(struct graph *, uint32_t, uint32_t, int);
void addEdge(struct vertexList *, struct vertexList*, int);
void initSingleSource(struct graph *, int);
void relax(struct graph*, struct edge *);
void dijkstra(struct graph*, int);

#endif