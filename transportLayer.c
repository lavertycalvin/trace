#include "transportLayer.h"
#include "checksum.h"
#include "smartalloc.h"


void strIP(in_addr_t ipAddr){
	struct in_addr *address = (struct in_addr *)&ipAddr;
	fprintf(stdout, "%s", inet_ntoa(*address));
}

void strMAC(uint8_t *macAddr){
	const struct ether_addr *address = (struct ether_addr *)macAddr;
	fprintf(stdout, "%s", ether_ntoa(address));
}

void strICMPRequest(uint8_t type){
	char *str_type = NULL;
	if(type == ICMP_REQUEST){
		str_type = "Request";
	}
	else if(type == ICMP_REPLY){
		str_type = "Reply";
	}
	else{
		str_type = "Unknown";
	}
	fprintf(stdout, "%s", str_type);
}

/* str functions for TCP Header */
void strPort(uint16_t port_num, int protocol){
	//name of ports available
	char *str_port = NULL;
	uint16_t host_order_port = ntohs(port_num);
	if(host_order_port == HTTP){
		str_port = "HTTP";	
	}
	else if(host_order_port == TELNET){
		str_port = "TELNET";	
	}
	else if(host_order_port == FTP){
		str_port = "FTP";	
	}
	else if(host_order_port == POP3){
		str_port = "POP3";	
	}
	else if(host_order_port == SMTP){
		str_port = "SMTP";	
	}
	else{
		//fprintf(stderr, "No Designated port!\n");	
	}

	//check to see if str is null
	if(str_port != NULL){
		fprintf(stdout, "%s", str_port);
	}
	else{
		fprintf(stdout, "%u", host_order_port);
	}
}
void strSeqNum(uint32_t num){
	fprintf(stdout, "%u", ntohl(num));
}
void strAckNum(uint32_t num){
	fprintf(stdout, "%u", ntohl(num));
}
void strSYNFlag(uint8_t flags){
	char *str_syn = NULL;
	if(flags & SYN_MASK){
		str_syn = "Yes";
	}
	else{
		str_syn = "No";
	}
	fprintf(stdout, "%s", str_syn); 
}
void strRSTFlag(uint8_t flags){
	char *str_rst = NULL;
	if(flags & RST_MASK){
		str_rst = "Yes";
	}
	else{
		str_rst = "No";
	}
	fprintf(stdout, "%s", str_rst); 
}
void strFINFlag(uint8_t flags){
	char *str_fin = NULL;
	if(flags & FIN_MASK){
		str_fin = "Yes";
	}
	else{
		str_fin = "No";
	}
	fprintf(stdout, "%s", str_fin); 
}
void strWinSize(uint16_t window_size){
	fprintf(stdout, "%u", ntohs(window_size));
}
void strTCPChecksum(struct tcp_header *tcp){
	unsigned short cksum_ret = 0;
 	unsigned short tcp_checksum = ntohs(tcp->tcp_checksum);
	
	/* construct our psuedo header */
	struct tcp_psuedo_header *psuedo_header = malloc(sizeof(struct tcp_psuedo_header));
       	psuedo_header->ip_source_addr = 0;
	psuedo_header->ip_dest_addr = 0;
	psuedo_header->reserved = 0; //8 bits of 0s
	psuedo_header->protocol = 0;
	psuedo_header->tcp_seg_len = 0;
	psuedo_header->header = tcp;	
	//let's do some fancy math to get our psuedo header
	
	
	tcp->tcp_checksum = 0; //set to 0 for check
	//cksum_ret = ntohs(in_cksum((short unsigned int *)---------, ----));
	if(cksum_ret != tcp_checksum){
		fprintf(stdout, "Incorrect (0x%x)", tcp_checksum);
	}
	else{
		fprintf(stdout, "Correct (0x%x)", tcp_checksum);
	}
	free(psuedo_header);
}
/*end str functions for TCP Header */


void printTCPHeader(struct tcp_header *tcp){
	fprintf(stdout, "\n\n\tTCP Header");
	fprintf(stdout, "\n\t\tSource Port:  ");
	strPort(tcp->tcp_source_port, TCP_PROTO);
	fprintf(stdout, "\n\t\tDest Port:  ");
	strPort(tcp->tcp_dest_port, TCP_PROTO);	
	fprintf(stdout, "\n\t\tSequence Number: ");
	strSeqNum(tcp->tcp_seq_num);
	fprintf(stdout, "\n\t\tACK Number: ");
	strAckNum(tcp->tcp_ack_num);
	fprintf(stdout, "\n\t\tSYN Flag: ");
	strSYNFlag(tcp->tcp_flags);
	fprintf(stdout, "\n\t\tRST Flag: ");
	strRSTFlag(tcp->tcp_flags);
	fprintf(stdout, "\n\t\tFIN Flag: ");
	strFINFlag(tcp->tcp_flags);
	fprintf(stdout, "\n\t\tWindow Size: ");
	strWinSize(tcp->tcp_window_size);
	fprintf(stdout, "\n\t\tChecksum: ");
	strTCPChecksum(tcp);
}
void printUDPHeader(struct udp_header *udp){
	fprintf(stdout, "\n\n\tUDP Header");
	fprintf(stdout, "\n\t\tSource Port:  ");
	strPort(udp->udp_source_port, UDP_PROTO);
	fprintf(stdout, "\n\t\tDest Port:  ");
	strPort(udp->udp_dest_port, UDP_PROTO);
}
void printICMPHeader(struct icmp_header *icmp){
	fprintf(stdout, "\n\n\tICMP Header");
	fprintf(stdout, "\n\t\tType: ");
	strICMPRequest(icmp->icmp_type);
}

int parseTCPHeader(const u_char *pkt_data){
	struct tcp_header *tcp = (struct tcp_header *)pkt_data;
	printTCPHeader(tcp);
	return 0;
}

int parseUDPHeader(const u_char *pkt_data){
	struct udp_header *udp = (struct udp_header *)pkt_data;
	printUDPHeader(udp);
	return 0;
}

int parseICMPHeader(const u_char *pkt_data){	
	struct icmp_header *icmp = (struct icmp_header *)pkt_data;
	printICMPHeader(icmp);
	return 0;
}
