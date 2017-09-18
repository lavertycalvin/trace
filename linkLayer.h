/* Interface for structures of:
 * 	ARP
 * 	IP
 * 	(physical layer will handle unknown)
 */

#ifndef LINKLAYER
#define LINKLAYER

#include <stdint.h>
#include <stdio.h>
#include <pcap.h>

#define ARP_REQUEST 	256 //little endian???
#define ARP_REPLY 	512 //little endian???

#define ICMP 		1
#define TCP		6
#define UDP		17

struct arp_header{
	uint16_t hardware_type;
	uint16_t protocol_type;
	uint8_t  hardware_addr_len;
	uint8_t  protocol_addr_len;
	uint16_t opcode; 	//print
	uint8_t  sender_mac[6]; //print
	uint8_t sender_ip[4];     //print
	uint8_t  target_mac[6]; //print
	uint8_t target_ip[4];	//print
}__attribute__((packed));

struct ip_header{
	uint8_t  ip_version; //4 bits are version, next 4 are ihl
	uint8_t tos; //type of service or DSCP
	uint16_t ip_len; //entire packet length including header and data
	uint16_t ip_id; //???
	uint16_t ip_flags_and_offset; //first 3 bits are flags, last are fragment offset
	uint8_t  ip_ttl; //time to live
	uint8_t  ip_protocol; // TCP/UDP/ICMP/Unknown
	uint16_t ip_header_checksum; //error checking
	uint8_t ip_source_addr[4]; //
	uint8_t ip_dest_addr[4];   //
	uint64_t ip_options_1;	 //OPTIONS
	uint64_t ip_options_2;   //MORE OPTION
}__attribute__((packed));

void strMAC(uint8_t *macAddr);
void strIP(uint8_t *ipAddr);
int parseIPHeader(const u_char *pkt_data);
int parseARPHeader(const u_char *pkt_data);
void printIPHeader(struct ip_header *ip);
void printARPHeader(struct arp_header *arp);
#endif
