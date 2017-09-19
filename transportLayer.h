/* Interface for transport layer for protocols:
 * 	TCP
 * 	UDP
 * 	ICMP
 */

#ifndef TRANSPORTLAYER
#define TRANSPORTLAYER

#include <stdint.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ether.h>

/*tcp defines */
#define FIN_MASK	0x1
#define SYN_MASK 	0x2
#define RST_MASK	0x4

/*icmp defines */
#define ICMP_REQUEST 	0x8 		//stored in type field
#define ICMP_REPLY	0x0 		//stored in type field

#define TCP_PROTO 	0x0
#define UDP_PROTO	0x1

/* Common port defs */
#define FTP		21
#define TELNET		23
#define SMTP		25
#define HTTP		80
#define POP3		110


struct tcp_header{
	uint16_t tcp_source_port;
	uint16_t tcp_dest_port;
	uint32_t tcp_seq_num;
	uint32_t tcp_ack_num;
	uint8_t  tcp_data_offset; 	//0-3 offset, 4-6 reserved, 7 NS flag
	uint8_t  tcp_flags; 		//check header info
	uint16_t tcp_window_size;
	uint16_t tcp_checksum;
	uint16_t tcp_urgent_pointer;
}__attribute__((packed));

struct tcp_psuedo_header{
	uint32_t ip_source_addr;
	uint32_t ip_dest_addr;
	uint8_t  reserved;
	uint8_t  protocol;
	uint16_t tcp_seg_len;
	struct tcp_header *header; 	//also need to tcp data to follow!
}__attribute__((packed));


struct udp_header{
	uint16_t udp_source_port;
	uint16_t udp_dest_port;
	uint16_t udp_len;
	uint16_t udp_checksum;
}__attribute__((packed));

struct icmp_header{
	uint8_t  icmp_type; 		//request, reply, unknown
	uint8_t  icmp_code;
	uint16_t icmp_checksum;
	uint32_t icmp_leftover;
}__attribute__((packed));


void strMAC(uint8_t *macAddr);
void strIP(in_addr_t ipAddr);
int parseTCPHeader(const u_char *pkt_data);
int parseUDPHeader(const u_char *pkt_data);
int parseICMPHeader(const u_char *pkt_data);
void printTCPHeader(struct tcp_header *tcp);
void printUDPHeader(struct udp_header *udp);
void printICMPHeader(struct icmp_header *icmp);

#endif
