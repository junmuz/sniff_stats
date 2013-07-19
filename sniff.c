#include "header.h"

s32 tcp = 0, udp = 0, icmp = 0, others = 0, igmp = 0, total = 0, i,j;

void process_packet(u8 *args, const struct pcap_pkthdr *header, const u8 *buffer)
{

	s32 size = header->len;
	//Get the Ethernet Header
	struct ethhdr *eth = (struct ethhdr *) (buffer);
	//Get the IP Header part of this packet
	struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
	//Get the TCP header part of this packet
	struct flow_param *flow_temp;
	struct pkt_attr *pkt_temp;
	
	++total;

	switch(iph->protocol) {
		case 1:		//ICMP protocol
			++icmp;
			#ifdef SNIFF
			print_icmp_packet(buffer, size);
			#endif
			break;

		case 2:		//IGMP protocol
			++igmp;
			break;

		case 6:		//TCP protocol
			++tcp;
		        struct tcphdr *tcph=(struct tcphdr*)(buffer + sizeof(struct iphdr) + sizeof(struct ethhdr));
			flow_temp = find_flow(iph->saddr, iph->daddr, iph->protocol, tcph->source, tcph->dest);	
			if (flow_temp == NULL) {

				flow_this->flow_next = (struct flow_param *) malloc(sizeof(struct flow_param));
				pkt_this->pkt_next = (struct pkt_attr *) malloc(sizeof(struct pkt_attr));
				pkt_this->saddr = flow_this->saddr = iph->saddr;
				pkt_this->daddr = flow_this->daddr = iph->daddr;
				pkt_this->proto = flow_this->proto = iph->protocol;
				pkt_this->sport = flow_this->sport = tcph->source;
				pkt_this->dport = flow_this->dport = tcph->dest;
				flow_this->inspect_complete = 0;

				flow_this->ethpktlen[0] = ntohs(iph->tot_len) + 14;
				flow_this->ippktlen[0] = ntohs(iph->tot_len);

				pkt_this->pkt_count = 1;
				pkt_this->discrim[0] = ntohs(tcph->dest);
				pkt_this->discrim[1] = ntohs(tcph->source);
				pkt_this->discrim[9] = ntohs(iph->tot_len) + 14;
				pkt_this->discrim[14] = ntohs(iph->tot_len) + 14;
                                pkt_this->discrim[30] = 1;
	                        pkt_this->discrim[31] = 0;

                        	pkt_this->discrim[32] = tcph->ack;
                        	pkt_this->discrim[36] = tcph->syn & tcph->ack;
                        	pkt_this->discrim[57] = tcph->psh;
                        	pkt_this->discrim[60] = tcph->syn;
                        	pkt_this->discrim[61] = tcph->fin;
                        	pkt_this->discrim[74] = tcph->urg;


				printf("Source Port     \t\t%d\n", pkt_this->sport);
				printf("Destination Port\t\t%d\n", pkt_this->dport);
				printf("Source IP       \t\t%d\n", pkt_this->saddr);
				printf("Destination IP  \t\t%d\n", pkt_this->daddr);
				printf("Port            \t\t%d\n", pkt_this->proto);
				printf("Count           \t\t%d\n\n", pkt_this->pkt_count);


                                pkt_this = pkt_this->pkt_next;
                                flow_this = flow_this->flow_next;
				pkt_this->pkt_next = NULL;
				flow_this->flow_next = NULL;

			}

			else {
				if(flow_temp->inspect_complete == 0) {
					pkt_temp = find_pkt_attr(iph->saddr, iph->daddr, iph->protocol, tcph->source, tcph->dest);
					if(pkt_temp != NULL) {

                                               	pkt_temp->pkt_count++;
                                               	if((flow_temp->sport == tcph->dest) && (flow_temp->dport == tcph->source)) {
 	                                       		pkt_temp->discrim[31]++;
                                               	}
                                               	else if ((flow_temp->sport == tcph->source) && (flow_temp->dport == tcph->dest)){
       							pkt_temp->discrim[30]++;
                                                }

						switch(pkt_temp->pkt_count) {
							case 2:
								flow_temp->ippktlen[1] = ntohs(iph->tot_len);
								flow_temp->ethpktlen[1] = ntohs(iph->tot_len) + 14;
								break;

							case 3:
								flow_temp->ippktlen[2] = ntohs(iph->tot_len);
								flow_temp->ethpktlen[2] = ntohs(iph->tot_len) + 14;
								break;
							
							case 4:
								flow_temp->ippktlen[3] = ntohs(iph->tot_len);
								flow_temp->ethpktlen[3] = ntohs(iph->tot_len) + 14;
								break;

							case 5:
								flow_temp->ippktlen[4] = ntohs(iph->tot_len);
								flow_temp->ethpktlen[4] = ntohs(iph->tot_len) + 14;
								{
									int i, j;
									for(i = 0; i < 5; i++) {
										for(j = i; j < 5; j++) {
											if(flow_temp->ethpktlen[i] > flow_temp->ethpktlen[j]) {
												int temp; 
												temp = flow_temp->ethpktlen[i];
												flow_temp->ethpktlen[i] = flow_temp->ethpktlen[j];
												flow_temp->ethpktlen[j] = temp;
												temp = flow_temp->ippktlen[i];
												flow_temp->ippktlen[i] = flow_temp->ippktlen[j];
												flow_temp->ippktlen[j] = temp;
											}
										}
									}
								}
								pkt_temp->discrim[9] = flow_temp->ethpktlen[0];
								pkt_temp->discrim[10] = flow_temp->ethpktlen[1];
								pkt_temp->discrim[11] = flow_temp->ethpktlen[2];
								pkt_temp->discrim[13] = flow_temp->ethpktlen[3];
								pkt_temp->discrim[14] = flow_temp->ethpktlen[4];
								pkt_temp->discrim[12] = 0;

                                                                pkt_temp->discrim[16] = flow_temp->ippktlen[0];
                                                                pkt_temp->discrim[17] = flow_temp->ippktlen[1];
                                                                pkt_temp->discrim[18] = flow_temp->ippktlen[2];
                                                                pkt_temp->discrim[20] = flow_temp->ippktlen[3];
                                                                pkt_temp->discrim[21] = flow_temp->ippktlen[4];
                                                                pkt_temp->discrim[19] = 0;


								{
									int i;
									for(i = 0; i < 5; i++) {
										pkt_temp->discrim[12] += flow_temp->ethpktlen[i];
										pkt_temp->discrim[19] += flow_temp->ippktlen[i];
									}
									pkt_temp->discrim[12] = pkt_temp->discrim[12] / 5;
									pkt_temp->discrim[19] = pkt_temp->discrim[19] / 5;
								}
								flow_temp->inspect_complete = 1;
								print_tcp_stats(pkt_temp);

				        fprintf(logfile, "\nTCP Statistics\n");

                               printf("\n\nREPEAT\n");
                                printf("Client Port     \t\t%d\n", pkt_temp->sport);
                                printf("Source Port     \t\t%d\n", pkt_temp->dport);
                                printf("Source IP       \t\t%d\n", pkt_temp->saddr);
                                printf("Destination IP  \t\t%d\n", pkt_temp->daddr);
                                printf("Port            \t\t%d\n", pkt_temp->proto);
                                printf("Count           \t\t%d\n\n", pkt_temp->pkt_count);

								break;


							default:
								break;
						}
					}

				}
			}
	
			#ifdef SNIFF
			print_tcp_packet(buffer, size);
			#endif
			break;

		case 17:	//UDP protocol
			++udp;
			#ifdef SNIFF
			print_udp_packet(buffer, size);
			#endif
			break;
		
		default:
			++others;
			break;
	}

	printf("TCP: %d\tUDP: %d\nICMP: %d\tIGMP: %d\tOthers: %d\tTotal: %d\n", tcp, udp, icmp, igmp, others, total);
}


void print_ethernet_header(const u8 *buffer, s32 Size)
{
	struct ethhdr *eth = (struct ethhdr *) buffer;

	fprintf(logfile, "\nEthernet Header\n");
	fprintf(logfile, "\t|-Destination Address	: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
        fprintf(logfile, "\t|-Source Address      	: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
        fprintf(logfile, "\t|-Protocol            	: %u\n", (unsigned short) eth->h_proto);
}

void print_ip_header(const u8 *buffer, s32 size)
{
	print_ethernet_header(buffer, size);

	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));

	iphdrlen = iph->ihl * 4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	fprintf(logfile, "\nIP Header\n");
	fprintf(logfile, "\t|-IP Version		: %d\n", (u32) iph->version);
	fprintf(logfile, "\t|-IP Header Length		: %d Bytes\n", (u32) iph->ihl * 4);
	fprintf(logfile, "\t|-Type of Service		: %d\n", (u32) iph-> tos);
	fprintf(logfile, "\t|-IP Packet Length		: %d Bytes\n", (u32) ntohs(iph->tot_len));
	fprintf(logfile, "\t|-Identification		: %d\n", (u32) iph->id);
        fprintf(logfile, "\t|-TTL			: %d\n", (u32) iph->ttl);
        fprintf(logfile, "\t|-Protocol		 	: %d\n", (u32) iph->protocol);
        fprintf(logfile, "\t|-Checksum       		: %d\n", (u32) iph->check);
        fprintf(logfile, "\t|-Source IP       		: %d\n", (u32) inet_ntoa(source.sin_addr));
        fprintf(logfile, "\t|-Destination IP       	: %d\n", (u32) inet_ntoa(dest.sin_addr));
	
}

void print_tcp_packet(const u8 * buffer, s32 Size)
{
	unsigned short iphdrlen;
	struct iphdr *iph = (struct iphdr *)( buffer  + sizeof(struct ethhdr) );
	iphdrlen = iph->ihl*4;
	struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
	s32 header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

	fprintf(logfile , "\n\n***********************TCP Packet*************************\n"); 
	print_ip_header(buffer,Size);

    	fprintf(logfile , "\nTCP Header\n");
	fprintf(logfile , "\t|-Client Port      	: %u\n",ntohs(tcph->source));
    	fprintf(logfile , "\t|-Server Port      	: %u\n",ntohs(tcph->dest));
    	fprintf(logfile , "\t|-Sequence Number    	: %u\n",ntohl(tcph->seq));
    	fprintf(logfile , "\t|-Acknowledge Number 	: %u\n",ntohl(tcph->ack_seq));
    	fprintf(logfile , "\t|-Header Length      	: %d Bytes\n" , (u32)tcph->doff*4);
    	fprintf(logfile , "\t|-Urgent Flag          	: %d\n",(u32)tcph->urg);
    	fprintf(logfile , "\t|-Acknowledgement Flag 	: %d\n",(u32)tcph->ack);
    	fprintf(logfile , "\t|-Push Flag            	: %d\n",(u32)tcph->psh);
    	fprintf(logfile , "\t|-Reset Flag           	: %d\n",(u32)tcph->rst);
	fprintf(logfile , "\t|-Synchronise Flag     	: %d\n",(u32)tcph->syn);
    	fprintf(logfile , "\t|-Finish Flag          	: %d\n",(u32)tcph->fin);
    	fprintf(logfile , "\t|-Window         		: %d\n",ntohs(tcph->window));
    	fprintf(logfile , "\t|-Checksum       		: %d\n",ntohs(tcph->check));
    	fprintf(logfile , "\t|-Urgent Pointer 		: %d\n",tcph->urg_ptr);
    	fprintf(logfile , "\n                        DATA Dump                         \n");

    	fprintf(logfile , "IP Header\n");
    	PrintData(buffer,iphdrlen);
   	fprintf(logfile , "TCP Header\n");
   	PrintData(buffer+iphdrlen,tcph->doff*4);
    	fprintf(logfile , "Data Payload\n");   
   	PrintData(buffer + header_size , Size - header_size );
  	fprintf(logfile , "\n###########################################################");
}

 

void print_udp_packet(const u8 *buffer , s32 Size)

{
    	unsigned short iphdrlen;
    	struct iphdr *iph = (struct iphdr *)(buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;
    	struct udphdr *udph = (struct udphdr*)(buffer + iphdrlen  + sizeof(struct ethhdr));
   	s32 header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;

        fprintf(logfile , "\n\n***********************UDP Packet*************************\n");
  	print_ip_header(buffer,Size);          


    	fprintf(logfile , "\nUDP Header\n");
   	fprintf(logfile , "\t|-Source Port      	: %d\n" , ntohs(udph->source));
    	fprintf(logfile , "\t|-Destination Port 	: %d\n" , ntohs(udph->dest));
    	fprintf(logfile , "\t|-UDP Length       	: %d\n" , ntohs(udph->len));
    	fprintf(logfile , "\t|-UDP Checksum     	: %d\n" , ntohs(udph->check));
    
	fprintf(logfile , "\nIP Header\n");
    	PrintData(buffer , iphdrlen);
    	fprintf(logfile , "UDP Header\n");
  	PrintData(buffer+iphdrlen , sizeof udph);
    	fprintf(logfile , "Data Payload\n");   

    //Move the pointer ahead and reduce the size of string

   	PrintData(buffer + header_size , Size - header_size);

     	fprintf(logfile , "\n###########################################################");
}

 

void print_icmp_packet(const u8 * buffer , s32 Size)
{
   	unsigned short iphdrlen;
   	struct iphdr *iph = (struct iphdr *)(buffer  + sizeof(struct ethhdr));
  	iphdrlen = iph->ihl * 4;
   	struct icmphdr *icmph = (struct icmphdr *)(buffer + iphdrlen  + sizeof(struct ethhdr));
   	s32 header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;

     	fprintf(logfile , "\n\n***********************ICMP Packet*************************\n");
   	print_ip_header(buffer , Size);
   	fprintf(logfile , "\n");
   	fprintf(logfile , "ICMP Header\n");
 	fprintf(logfile , "\t|-Type 			: %d",(u32)(icmph->type));
  

    	if((u32)(icmph->type) == 11) {
	        fprintf(logfile , "  (TTL Expired)\n");
    	}

    	else if((u32)(icmph->type) == ICMP_ECHOREPLY) {
	        fprintf(logfile , "  (ICMP Echo Reply)\n");
    	}

     	fprintf(logfile , "\t|-Code 			: %d\n",(u32)(icmph->code));
	fprintf(logfile , "\t|-Checksum 		: %d\n",ntohs(icmph->checksum));

	fprintf(logfile , "\nIP Header\n");

    	PrintData(buffer,iphdrlen);

    	fprintf(logfile , "UDP Header\n");
    	PrintData(buffer + iphdrlen , sizeof icmph);

    	fprintf(logfile , "Data Payload\n");   
  	PrintData(buffer + header_size , (Size - header_size) );

   	fprintf(logfile , "\n###########################################################");
}

void PrintData (const u8 * data , s32 Size)
{
    	s32 i , j;
    	for(i=0 ; i < Size ; i++) {
        	if( i!=0 && i%16==0) {
            		fprintf(logfile , "         ");
            		for(j=i-16 ; j<i ; j++) {
                		if(data[j]>=32 && data[j]<=128)
                    			fprintf(logfile , "%c",(u8)data[j]); //if its a number or alphabet
		             	else fprintf(logfile , "."); //otherwise prs32 a dot
            		}
            	fprintf(logfile , "\n");
        	}
        	if(i%16==0) fprintf(logfile , "   ");
        	fprintf(logfile , " %02X",(u32)data[i]);

	        if( i==Size-1) {
        		for(j=0;j<15-i%16;j++) {
	        		fprintf(logfile , "   "); //extra spaces
	           	}
        	    	fprintf(logfile , "         ");
            		for(j=i-i%16 ; j<=i ; j++) {
                		if(data[j]>=32 && data[j]<=128) {
                  			fprintf(logfile , "%c",(u8)data[j]);
                		}
                		else {
                  			fprintf(logfile , ".");
                		}
            		}
            		fprintf(logfile ,  "\n" );
        	}
    	}
}

void print_tcp_stats(struct pkt_attr * pkt_temp)
{
	FILE *fptr = fopen("tcp.txt", "a");
        fprintf(logfile, "\n\n***********************TCP Packet*************************\n");

        fprintf(fptr, "\nTCP Statistics\n");
        fprintf(fptr, "\t|-Server Port              : %u\n", pkt_temp->discrim[0]);
        fprintf(fptr, "\t|-Client Port              : %u\n", pkt_temp->discrim[1]);
	fprintf(fptr, "\t|-Minimum Ethernet Length  : %u\n", pkt_temp->discrim[9]);
        fprintf(fptr, "\t|-First Quartile Ethernet  : %u\n", pkt_temp->discrim[10]);
        fprintf(fptr, "\t|-Median Ethernet          : %u\n", pkt_temp->discrim[11]);
        fprintf(fptr, "\t|-Mean Ethernet            : %u\n", pkt_temp->discrim[12]);
        fprintf(fptr, "\t|-Third Quartile Ethernet  : %u\n", pkt_temp->discrim[13]);
	fprintf(fptr, "\t|-Maximum Ethernet Length  : %u\n", pkt_temp->discrim[14]);
        fprintf(fptr, "\t|-Minimum IP Length        : %u\n", pkt_temp->discrim[16]);
        fprintf(fptr, "\t|-First Quartile IP        : %u\n", pkt_temp->discrim[17]);
        fprintf(fptr, "\t|-Median IP Length         : %u\n", pkt_temp->discrim[18]);
        fprintf(fptr, "\t|-Mean IP Length           : %u\n", pkt_temp->discrim[19]);
        fprintf(fptr, "\t|-Thist Quartile IP        : %u\n", pkt_temp->discrim[20]);
        fprintf(fptr, "\t|-Maximum IP               : %u\n", pkt_temp->discrim[21]);
	fprintf(fptr, "\t|-Cli-Ser Packets          : %u\n", pkt_temp->discrim[30]);
	fprintf(fptr, "\t|-Ser-Cli Packets          : %u\n", pkt_temp->discrim[31]);
	fprintf(fptr, "\t|-ACK Bit                  : %u\n", pkt_temp->discrim[32]);
	fprintf(fptr, "\t|-SYN ACK Occurence        : %u\n", pkt_temp->discrim[36]);
	fprintf(fptr, "\t|-PUSH Bit                 : %u\n", pkt_temp->discrim[57]);
	fprintf(fptr, "\t|-SYN Bit                  : %u\n", pkt_temp->discrim[60]);
	fprintf(fptr, "\t|-FIN Bit                  : %u\n", pkt_temp->discrim[61]);
	fprintf(fptr, "\t|-URG Bit                  : %u\n", pkt_temp->discrim[74]);
        fprintf(fptr, "\n###########################################################\n");
	fclose(fptr);
}

struct flow_param * find_flow(u32 saddr, u32 daddr, u8 proto, u16 sport, u16 dport)
{

	struct flow_param *flow_temp;
	for(flow_temp = flow_base; flow_temp != NULL; flow_temp = flow_temp->flow_next) {
		if(((flow_temp->saddr == saddr) || (flow_temp->saddr == daddr)) && ((flow_temp->daddr == daddr) || (flow_temp->daddr == saddr)) &&
			(flow_temp->proto == proto) && 
			((flow_temp->sport == sport) || (flow_temp->sport == dport)) &&
			((flow_temp->dport == dport) || (flow_temp->dport == sport))) {
			return flow_temp;
		}
	}

	return NULL;
}

struct pkt_attr * find_pkt_attr(u32 saddr, u32 daddr, u8 proto, u16 sport, u16 dport)
{
	struct pkt_attr *pkt_temp;
	for(pkt_temp = pkt_base; pkt_temp != NULL; pkt_temp = pkt_temp->pkt_next) {
               if(((pkt_temp->saddr == saddr) || (pkt_temp->saddr == daddr)) && ((pkt_temp->daddr == daddr) || (pkt_temp->daddr == saddr)) &&
                        (pkt_temp->proto == proto) &&
                        ((pkt_temp->sport == sport) || (pkt_temp->sport == dport)) &&
                        (pkt_temp->dport == dport) || (pkt_temp->dport == sport)) {

			return pkt_temp;
                }
        }

	return NULL;
}


