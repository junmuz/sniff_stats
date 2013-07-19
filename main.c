
#include "header.h"

struct pkt_attr *pkt_this;
struct pkt_attr *pkt_base;
struct flow_param *flow_base;
struct flow_param *flow_this;
struct sockaddr_in source, dest;

FILE *logfile;

s32 main()
{
	pcap_if_t * alldevsp, *device;
	pcap_t *handle;	
	
	s32 status = FAIL;	

	//Handle of the device that shall be sniffed	

	s8 errbuf[100], *devname, devs[100][100];
	s32 count = 1, n;
	s8 temp[5];

	//First get the list of Available Devices

	printf("Finding available Devices ...\n");
	if(pcap_findalldevs(&alldevsp, errbuf)) {
		printf("Error Finding Device: %s\n", errbuf);
		exit(-1);
	}
	
	printf("Available Devices are :\n");
	for(device = alldevsp; device != NULL; device = device->next) {
		printf("%d. %s - %s\n", count, device->name, device->description);
		if(device->name != NULL) {
			strcpy(devs[count], device->name);
		}
		count++;
	}

	// Ask user which device to sniff


	printf("Enter the number of the device you want to sniff: ");
	gets(temp);
	n = atoi(temp);
	
	devname = devs[n];

	// Open the device for sniffing

	printf("Opening Device %s for sniffing ...\n", devname);
	handle = pcap_open_live(devname, 65536, 1, 0, errbuf);

	if(handle == NULL) {
		fprintf(stderr, "Couldn't open device %s : %s\n", devname, errbuf);
		exit(1);
	}

	printf("Done\n");

	logfile = fopen("log.txt", "w");

	if(logfile == NULL) {
		printf("Unable to create log file\n");
		exit(1);
	}

	// Memory Allocation for Base flow
	flow_base = (struct flow_param *) malloc(sizeof(struct flow_param));
	flow_this = flow_base;
	flow_this->flow_next = NULL;

	pkt_base = (struct pkt_attr *) malloc(sizeof(struct pkt_attr));
	pkt_this = pkt_base;
	pkt_this->pkt_next = NULL;

//	status = init_pkt_struct(pkt, 0, NULL);	
//	if(status < 0) {
//		printf("Unable to initialize structure\n");
//		exit(-1);
//	}

	pcap_loop(handle, -1, process_packet, NULL);
	printf("Failed to stay in loop\n");
	for(pkt_this = pkt_base; pkt_this != NULL; pkt_this = pkt_this->pkt_next) {
		free(pkt_base);
		pkt_base = pkt_this;
	}

        for(flow_this = flow_base; flow_this != NULL; flow_this = flow_this->flow_next) {
                free(flow_base);
                flow_base = flow_this;
        }


	return 0;
	

}
