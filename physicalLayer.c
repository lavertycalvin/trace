#include "physicalLayer.h"
#include "linkLayer.h"


void ethType(uint16_t type){
	char *etherType = NULL;
	if(type == ARP){
		etherType = "ARP";
	}
	else if(type == IPV4){
		etherType = "IP"; 
	}
	else {
		etherType = "Unknown";
	}
	
	printf("%s\n", etherType);//formatting
}

int parseEthernetHeader(const u_char *pkt_data){
	int subStructureReturn = 0;
	struct enet_header *ethHeader = (struct enet_header *)pkt_data;
	printEthernetHeader(ethHeader);
	//now pass on to correct sub-structure	
	if(ethHeader->type == ARP){
		subStructureReturn = parseARPHeader(&pkt_data[sizeof(uint8_t) * 14]);
	}
	else if(ethHeader->type == IPV4){
		subStructureReturn = parseIPHeader(&pkt_data[sizeof(uint8_t) * 14]);
	}
	else {
		fprintf(stderr, "Unable to parse substructure of Ethernet Header... Returning 1\n");
		subStructureReturn = 1;
	}
	return subStructureReturn;
}

void printEthernetHeader(struct enet_header *ethHeader){
	printf("\tEthernet Header\n");
	printf("\t\tDest MAC: "); 
	strMAC(ethHeader->dest);
	printf("\n\t\tSource MAC: "); 
	strMAC(ethHeader->source);
	printf("\n\t\tType: "); 
	ethType(ethHeader->type);
}

