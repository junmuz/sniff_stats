#include "header.h"

// init_pkt_struct	Initialize Packet Structure;
// pflow_id		Previous Flow ID


s32 init_pkt_struct(struct pkt_attr *pkt, s32 pflow_id, struct pkt_attr *pkt_pr)
{
	pkt = malloc(sizeof(struct pkt_attr));
	pkt->flow_id = pflow_id + 1;
	pkt->saddr = 0;
	pkt->daddr = 0;
	pkt->proto = 0;
	pkt->pkt_count = 0;
	memset(pkt->discrim, 0, 249);
	memset(pkt->tti, 0, 5);
	memset(pkt->mac_bytes, 0, 5);
	pkt->pkt_next = NULL;
	return SUCCESS;
}

s32 free_pkt_struct(struct pkt_attr *pkt)
{
}
