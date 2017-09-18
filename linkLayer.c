#include "linkLayer.h"
#include "checksum.h"

void strIP(uint8_t *ipAddr){
	int i = 0;
	for (i = 0; i < 3; i++){
		printf("%d.", ipAddr[i]);
	}
	printf("%d", ipAddr[i]);
}

void strMAC(uint8_t *macAddr){
	int i = 0;
	for (i = 0; i < 5; i++){
		printf("%x:", macAddr[i]);
	}
	printf("%x", macAddr[i]);
}

int parseIPHeader(const u_char *pkt_data){
	struct ip_header *ip = (struct ip_header *)pkt_data;	
	printIPHeader(ip);
	return 0;
}

int parseARPHeader(const u_char *pkt_data){
 	struct arp_header *arp = (struct arp_header *)pkt_data;	
	printARPHeader(arp);
	return 0;
}

void strOpcode(uint16_t opcode){
	if(opcode == ARP_REQUEST){
		fprintf(stdout, "Request");
	}
	else if(opcode == ARP_REPLY){
		fprintf(stdout, "Reply");
	}
	else{
		fprintf(stderr, "ARP Opcode not identified: %d", opcode);
	}
}

void strTOS(uint16_t tos){
	fprintf(stdout, "0x%x", tos);
}
void strTTL(uint8_t ip_ttl){
	fprintf(stdout, "%d", ip_ttl);
}
void strIPProtocol(uint8_t ip_protocol){
 // TCP/UDP/ICMP/Unknown
	char *print_protocol = NULL;
	if(ip_protocol == ICMP){
		print_protocol = "ICMP";
	}
	else if(ip_protocol == UDP){
		print_protocol = "UDP";
	}
	else if(ip_protocol == TCP){
		print_protocol = "TCP";
	}
	else{
		print_protocol = "Unknown";
	}
	fprintf(stdout, "%s", print_protocol);
}
void strChecksum(struct ip_header *ip){
	unsigned short cksum_ret = 0;
	if((cksum_ret = in_cksum((short unsigned int *)&ip->ip_header_checksum, ip->ip_len)) != 0){
		fprintf(stdout, "Incorrect (0x%x)", cksum_ret);
	}
	else{
		fprintf(stdout, "Correct");
	}
	
}

void printIPHeader(struct ip_header *ip){
	fprintf(stdout, "\n\tIP Header");
	fprintf(stdout, "\n\t\tTOS: ");
	strTOS(ip->tos);
	fprintf(stdout, "\n\t\tTTL: ");
	strTTL(ip->ip_ttl);
	fprintf(stdout, "\n\t\tProtocol: ");
	strIPProtocol(ip->ip_protocol);
	fprintf(stdout, "\n\t\tChecksum: ");
	strChecksum(ip);
	fprintf(stdout, "\n\t\tSender IP: ");
	strIP(ip->ip_source_addr);
	fprintf(stdout, "\n\t\tDest IP: ");
	strIP(ip->ip_dest_addr);
}

void printARPHeader(struct arp_header *arp){
	fprintf(stdout, "\n\tARP Header");
	fprintf(stdout, "\n\t\tOpcode: ");
	strOpcode(arp->opcode);
	fprintf(stdout, "\n\t\tSender MAC: ");
	strMAC(arp->sender_mac);
	fprintf(stdout, "\n\t\tSender IP: ");
	strIP(arp->sender_ip);
	fprintf(stdout, "\n\t\tTarget MAC: ");
	strMAC(arp->target_mac);
	fprintf(stdout, "\n\t\tTarget IP: ");
	strIP(arp->target_ip);
	fprintf(stdout, "\n");
}

