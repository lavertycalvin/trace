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
#include <netinet/in.h>

#define ARP_REQUEST 	1
#define ARP_REPLY 	2 

#define ICMP 		1
#define TCP		6
#define UDP		17

struct arp_header{
	uint16_t hardware_type;
	uint16_t protocol_type;
	uint8_t  hardware_addr_len;
	uint8_t  protocol_addr_len;
	uint16_t opcode; 		//print
	uint8_t  sender_mac[6]; 	//print
	in_addr_t sender_ip;     	//print
	uint8_t  target_mac[6]; 	//print
	in_addr_t target_ip;		//print
}__attribute__((packed));

struct ip_header{
	uint8_t  ip_version; 		//4 bits are version, next 4 are ihl
	uint8_t tos; 			//type of service or DSCP
	uint16_t ip_len; 		//entire packet length including header and data
	uint16_t ip_id; 		//???
	uint16_t ip_flags_and_offset; 	//first 3 bits are flags, last are fragment offset
	uint8_t  ip_ttl; 		//time to live
	uint8_t  ip_protocol; 		// TCP/UDP/ICMP/Unknown
	uint16_t ip_header_checksum; 	//error checking
	in_addr_t ip_source_addr; 	//
	in_addr_t ip_dest_addr;   	//
	uint64_t ip_options_1;	 	//OPTIONS
	uint64_t ip_options_2;   	//MORE OPTIONS
}__attribute__((packed));

int parseIPHeader(const u_char *pkt_data);
int parseARPHeader(const u_char *pkt_data);
void printIPHeader(struct ip_header *ip);
void printARPHeader(struct arp_header *arp);
#endif
