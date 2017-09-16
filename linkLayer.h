/* Interface for structures of:
 * 	ARP
 * 	IP
 * 	(physical layer will handle unknown)
 */

#ifndef LINKLAYER
#define LINKLAYER

struct arp_header{
	uint16_t hardware_type;
	uint16_t protocol_type;
	uint8_t  hardware_addr_len;
	uint8_t  protocol_addr_len;
	uint16_t opcode; 	//print
	uint8_t  sender_mac[6]; //print
	uint32_t sender_ip;     //print
	uint8_t  target_mac[6]; //print
	uint32_t target_ip;	//print
}__attribute__((packed));

struct ip_header{
	uint32_t ip_version;
	uint32_t ihl; //internet header length (length of IP header)
	//left off here
	//
}__attribute__((packed));


#endif
