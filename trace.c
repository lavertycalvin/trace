/* Program 1     : Packet Parsing
 * Author        : Calvin Laverty
 * Last Modified : 9/14/17
 */

#include <stdint.h>
#include <stdio.h>
#include <pcap.h>
#include "ethernetHeader.h"

/* design will be peel off a layer an pass to lower level of packet */
void parsePacket(pcap_t *pcapInfo) {
	//pass to ethernetHeader who will pass on the rest of the work
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
	parsePacket(pcapInfo);
	return 0;
}
