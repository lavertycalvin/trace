/* allows for trace to parse only the ethernet header 
 * Header Output:
 * 	Dest MAC	: 
 * 	Source MAC	:
 * 	Type		: ARP, IP, Unknown		
 */

#ifndef PHYSICALLAYER
#define PHYSICALLAYER

#include <pcap.h>
#include <stdint.h>

/*14 bytes consumed by the ethernet header*/
struct enet_header {
	uint8_t dest[6];
	uint8_t source[6];
	uint16_t type; /*ARP, IP, Unknown*/
};


int parseEthernetHeader(pcap_t *pcapInfo);
void printEthernetHeader(enet_header *ethHeader);

#endif
