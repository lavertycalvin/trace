#include "physicalLayer.h"

void strMAC(uint8_t *macAddr){
	int i = 0;
	for (i = 0; i < 5; i++){
		printf("%x:", macAddr[i]);
	}
	printf("%x\n", macAddr[i]);

}

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
	struct enet_header *ethHeader = (struct enet_header *)pkt_data;
	printEthernetHeader(ethHeader);
	//now pass on to correct sub-structure	
	return 0;
}

void printEthernetHeader(struct enet_header *ethHeader){
	printf("\tEthernet Header\n");
	printf("\t\tDest MAC: "); 
	strMAC(ethHeader->dest);
	printf("\t\tSource MAC: "); 
	strMAC(ethHeader->source);
	printf("\t\tType: "); 
	ethType(ethHeader->type);
}

