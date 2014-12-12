#ifndef SR_OSPF_DSTRUCT_H
#define SR_OSPF_DSTRUCT_H

#include <math.h>

static const int VTYPE_ROUTER = 0;
static const int VTYPE_SUBNET = 1;
static const int INF = 5;
static const int VISITED = 1;
static const int UNVISITED = 0;

struct sr_ospf_neighbor
{
	uint32_t rid;
	uint32_t ip;
	uint32_t nmask;
	char *iface;
	int isAlive;
	double tstamp;
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
	uint32_t nmask;
	int d, parent;
	int visited;
	int latestSeqNum;
	struct adjList *head;
};

struct vertexList
{
	struct vertex v;
	struct vertexList *next;
};

struct path
{
	struct vertex v;
	struct path *next;
};

struct graph
{
	int V;
	struct vertexList *vList;
};

struct graph* initGraph();

void addVertex(struct graph *, uint32_t, uint32_t, uint32_t, int);
void addEdge(struct vertexList *, struct vertexList*, int);
void initSingleSource(struct graph *, struct vertexList*);
void relax(struct vertexList*, struct vertexList*, int);
void dijkstra(struct graph*, struct vertexList*);

#endif