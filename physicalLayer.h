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

#define ARP  0x0608 //little endian?
#define IPV4 0x0008 //little endian?


/*14 bytes consumed by the ethernet header*/
struct enet_header {
	uint8_t dest[6];
	uint8_t source[6];
	uint16_t type; /*ARP, IP, Unknown*/
}__attribute__((packed));


void strMAC(uint8_t *macAddr);
void ethType(uint16_t type);
int parseEthernetHeader(const u_char *pkt_data);
void printEthernetHeader(struct enet_header *ethHeader);

#endif
