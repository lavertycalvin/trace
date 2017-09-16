/* Program 1     : Packet Parsing
 * Author        : Calvin Laverty
 * Last Modified : 9/14/17
 */

#include <stdint.h>
#include <stdio.h>
#include <pcap.h>
#include "physicalLayer.h"

/* design will be peel off a layer an pass to lower level of packet */
int parsePacket(pcap_t *pcapSaveFile) {
	int eNetHeaderRet = 0;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	int packetsRead = 0;
	
	//loop through until we don't have anymore saved packets
	while (pcap_next_ex(pcapSaveFile, &header, &pkt_data) != -2) {
		packetsRead++;
		fprintf(stderr, "Packets Read: %d\n", packetsRead); 
		//pass to ethernetHeader who will pass on the rest of the work
		eNetHeaderRet = parseEthernetHeader(pcapSaveFile);
		fprintf(stderr, "Ethernet Header Return Value: %d\n", eNetHeaderRet);
	}
	
	return eNetHeaderRet;
}

/* will return null if pcap_open_offlien is null */
pcap_t *openPcapFile(char *fileName) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcapInfo;
	if ((pcapInfo = pcap_open_offline(fileName, errbuf)) == NULL) {
		fprintf(stderr, "Unable to open pcap file %s: %s\n", fileName, errbuf);
	}
	return pcapInfo;
}

int main(int argc, char **args) {
	//take one file as an input
	pcap_t *pcapInfo;
	if (argc != 2) {
		fprintf(stderr, "Illegal Use: Please provide one trace file\n");
		return 1;
	}
		
	//open pcap file
	if ((pcapInfo = openPcapFile(args[1])) == NULL) {
		return 1;
	}

	//parse pcap file
	int parseRet = parsePacket(pcapInfo);
	return parseRet;
}
