#ifndef HEADER

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

typedef	unsigned char	u8;
typedef	unsigned short	u16;
typedef unsigned int 	u32;

//	Add architecture dependence stuff over here for 64 bit data

typedef signed char	s8;
typedef signed short	s16;
typedef signed int	s32;


#define	SUCCESS		1
#define FAIL		-1

struct pkt_attr {
	s32 flow_id;
	u32 saddr;
	u32 daddr;
	u8 proto;
	u16 sport;
	u16 dport;
	u32 pkt_count;
	u32 discrim[249];
	u32 tti[5];
	s32 mac_bytes[5];
	struct pkt_attr *pkt_next;
};

struct flow_param {
	s32 flow_id;
	u32 saddr, daddr;
	u16 sport, dport;
	u8 proto;
	u32 state;
	u8 inspect_complete:1;
	u16 ethpktlen[5];
	u16 ippktlen[5];
	u16 cntpktlen[5];
	struct flow_param *flow_next;
};

void process_packet(u8 *, const struct pcap_pkthdr *, const u8 *);
void process_ip_packet(const u8 *, s32);
void print_ip_packet(const u8 *, s32);
void print_tcp_packet(const u8 *, s32);
void print_udp_packet(const u8 *, s32);
void print_icmp_packet(const u8 *, s32);
void PrintData(const u8 *, s32);

void print_tcp_stats(struct pkt_attr *);

s32 init_pkt_struct(struct pkt_attr *, s32, struct pkt_attr *);
s32 free_pkt_struct(struct pkt_attr *);

struct flow_param * find_flow(u32, u32, u8, u16, u16);
struct pkt_attr * find_pkt_attr(u32, u32, u8, u16, u16);

extern FILE *logfile;

extern struct flow_param *flow_base;
extern struct flow_param *flow_this;

extern struct pkt_attr *pkt_this;
extern struct pkt_attr *pkt_base;
extern struct sockaddr_in source, dest;

extern s32 tcp, udp, icmp, others, igmp, total, i,j;

#define HEADER 	1
#endif


