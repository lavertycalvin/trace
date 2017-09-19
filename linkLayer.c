#include "linkLayer.h"
#include "transportLayer.h"
#include "checksum.h"


int parseIPHeader(const u_char *pkt_data){
	int ip_ret = 0;
	struct ip_header *ip = (struct ip_header *)pkt_data;	
	unsigned short ihl = (ip->ip_version & 0xf) * sizeof(uint32_t); //take off the upper bits
	printIPHeader(ip);
	//decide on substructure to pass to
	if(ip->ip_protocol == ICMP){
		ip_ret = parseICMPHeader(&pkt_data[ihl]); 	
	}
	else if(ip->ip_protocol == UDP){
		ip_ret = parseUDPHeader(&pkt_data[ihl]);
	}
	else if(ip->ip_protocol == TCP){
		ip_ret = parseTCPHeader(&pkt_data[ihl]);
	}
	else{
		//unknown....
		fprintf(stderr, "Unknown sub-IP Protocol. Returning 1\n");
		ip_ret = 1;
	}
	return ip_ret;
}

int parseARPHeader(const u_char *pkt_data){
 	struct arp_header *arp = (struct arp_header *)pkt_data;	
	printARPHeader(arp);
	return 0;
}

void strOpcode(uint16_t opcode){
	if(ntohs(opcode) == ARP_REQUEST){
		fprintf(stdout, "Request");
	}
	else if(ntohs(opcode) == ARP_REPLY){
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
void strIPChecksum(struct ip_header *ip){
	unsigned short cksum_ret = 0;
	unsigned short ihl = (ip->ip_version & 0xf) * sizeof(uint32_t); //take off the upper bits
 	unsigned short packet_checksum = ntohs(ip->ip_header_checksum);
	ip->ip_header_checksum = 0; //set to 0 for check
	cksum_ret = ntohs(in_cksum((short unsigned int *)&ip->ip_version, ihl));

	if(cksum_ret != packet_checksum){
		fprintf(stdout, "Incorrect (0x%x)", packet_checksum);
	}
	else{
		fprintf(stdout, "Correct (0x%x)", packet_checksum);
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
	strIPChecksum(ip);
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
}

