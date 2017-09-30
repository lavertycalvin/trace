/* Program 1     : Packet Parsing
 * Author        : Calvin Laverty
 * Last Modified : 9/29/17
 */

#include "trace.h"
#include "smartalloc.h"
#include "checksum.h"

/* transport layer */

void strIP(in_addr_t ipAddr){
	struct in_addr *address = (struct in_addr *)&ipAddr;
	fprintf(stdout, "%s", inet_ntoa(*address));
}

void strMAC(uint8_t *macAddr){
	const struct ether_addr *address = (struct ether_addr *)macAddr;
	fprintf(stdout, "%s", ether_ntoa(address));
}

void strICMPType(uint8_t type){
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
		fprintf(stderr, "No Designated port, printing out port number!\n");	
	}

	//check to see if port was recognized
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

void strTCPChecksum(struct tcp_combo *tcp){
	unsigned short cksum_ret = 0;
 	unsigned short cksum_header = ntohs(tcp->header.tcp_checksum);
	fprintf(stderr, "\nPSUEDO HEADER CONTENTS:\n");

	int tcp_offset = ((tcp->header.tcp_data_offset) >> 4) * sizeof(uint32_t); //mask off other bits
      	fprintf(stderr, "\tTCP HEADER LEN\t: %u\n", tcp_offset);
	
	//subtract tcp_offset from TCP_seg_len
	tcp->pseudo_header.tcp_seg_len = htons(ntohs(tcp->pseudo_header.tcp_seg_len) - tcp_offset);
      	fprintf(stderr, "\tTCP SEG LEN\t: %u\n", ntohs(tcp->pseudo_header.tcp_seg_len));

	fprintf(stderr, "\tCHECKSUM COMP LEN: %lu\n", ntohs(tcp->pseudo_header.tcp_seg_len) + sizeof(tcp->pseudo_header) + tcp_offset);	
	tcp->header.tcp_checksum = 0; //set to 0 for check
	cksum_ret = ntohs(in_cksum((short unsigned int *)&tcp->pseudo_header, ntohs(tcp->pseudo_header.tcp_seg_len) + sizeof(tcp->pseudo_header) + tcp_offset));
	
	if(cksum_ret != cksum_header){
		fprintf(stdout, "Incorrect (0x%x)", cksum_header);
	}
	else{
		fprintf(stdout, "Correct (0x%x)", cksum_header);
	}
}
/*end str functions for TCP Header */

void printTCPHeader(struct tcp_combo *tcp){
	fprintf(stdout, "\n\n\tTCP Header");
	fprintf(stdout, "\n\t\tSource Port:  ");
	strPort(tcp->header.tcp_source_port, TCP_PROTO);
	fprintf(stdout, "\n\t\tDest Port:  ");
	strPort(tcp->header.tcp_dest_port, TCP_PROTO);	
	fprintf(stdout, "\n\t\tSequence Number: ");
	strSeqNum(tcp->header.tcp_seq_num);
	fprintf(stdout, "\n\t\tACK Number: ");
	strAckNum(tcp->header.tcp_ack_num);
	fprintf(stdout, "\n\t\tSYN Flag: ");
	strSYNFlag(tcp->header.tcp_flags);
	fprintf(stdout, "\n\t\tRST Flag: ");
	strRSTFlag(tcp->header.tcp_flags);
	fprintf(stdout, "\n\t\tFIN Flag: ");
	strFINFlag(tcp->header.tcp_flags);
	fprintf(stdout, "\n\t\tWindow Size: ");
	strWinSize(tcp->header.tcp_window_size);
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
	strICMPType(icmp->icmp_type);
}

int parseTCPHeader(struct tcp_combo *combo){
	printTCPHeader(combo);
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

/* end transport layer */
/* link layer */

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
      		//create tcp_pseudo header to pass info
      		struct tcp_combo *combo = malloc(sizeof(struct tcp_combo) + ntohs(ip->ip_len) - ihl);
		
		//set up pseudo tcp header
		combo->pseudo_header.ip_source_addr = ip->ip_source_addr;
      		combo->pseudo_header.ip_dest_addr = ip->ip_dest_addr;
      		combo->pseudo_header.reserved = 0;
      		combo->pseudo_header.protocol = ip->ip_protocol;
      		combo->pseudo_header.tcp_seg_len = htons(ntohs(ip->ip_len) - ihl); //still need to delete length of TCP Header after setup
		
		//set up tcp header
		memcpy(&combo->header, &pkt_data[ihl], sizeof(combo->header) + ntohs(ip->ip_len) - ihl); 
		
		ip_ret = parseTCPHeader(combo);
		free(combo);
	}
	else{
		//unknown type
		fprintf(stderr, "Unknown sub-IP Protocol. Returning 0 still\n");
		ip_ret = 0;
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
 	// Types accepted: TCP/UDP/ICMP/Unknown
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


/* end link layer */
/* physical layer */
void ethType(uint16_t type){
	char *etherType = NULL;
	if(ntohs(type) == ARP){
		etherType = "ARP";
	}
	else if(ntohs(type) == IPV4){
		etherType = "IP"; 
	}
	else {
		etherType = "Unknown";
	}
	
	printf("%s\n", etherType);//formatting
}

int parseEthernetHeader(const u_char *pkt_data){
	int subHeaderReturn = 0;
	struct enet_header *ethHeader = (struct enet_header *)pkt_data;
	printEthernetHeader(ethHeader);
	//now pass on to correct sub-structure	
	if(ntohs(ethHeader->type) == ARP){
		subHeaderReturn = parseARPHeader(&pkt_data[sizeof(struct enet_header)]);
	}
	else if(ntohs(ethHeader->type) == IPV4){
		subHeaderReturn = parseIPHeader(&pkt_data[sizeof(struct enet_header)]);
	}
	else {
		fprintf(stderr, "Unable to parse substructure of Ethernet Header... Returning 1\n");
		subHeaderReturn = 1;
	}
	return subHeaderReturn;
}

void printEthernetHeader(struct enet_header *ethHeader){
	printf("\tEthernet Header\n");
	printf("\t\tDest MAC: "); 
	strMAC(ethHeader->dest);
	printf("\n\t\tSource MAC: "); 
	strMAC(ethHeader->source);
	printf("\n\t\tType: "); 
	ethType(ethHeader->type);
}
/* end physical layer */

/* design: peel off a layer an pass to next level of packet */
int parsePacket(pcap_t *pcapSaveFile) {
	int eNetHeaderRet = 0;
	struct pcap_pkthdr *header = NULL;
	const u_char *pkt_data = NULL;
	int packetsRead = 0;
	
	//loop through until we don't have anymore saved packets
	while (pcap_next_ex(pcapSaveFile, &header, &pkt_data) != -2) {
		packetsRead++;
		fprintf(stdout, "\nPacket number: %d  ", packetsRead); 
		fprintf(stdout, "Packet Len: %d\n\n", header->len);
		//pass to ethernetHeader
		eNetHeaderRet = parseEthernetHeader(pkt_data);
		fprintf(stderr, "Ethernet Header Return Value: %d\n", eNetHeaderRet);
		fprintf(stdout, "\n"); //formatting
	}	
	return eNetHeaderRet;
}

/* will return null if pcap_open_offline is null */
pcap_t *openPcapFile(char *fileName) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcapInfo;
	if ((pcapInfo = pcap_open_offline(fileName, errbuf)) == NULL) {
		fprintf(stderr, "Unable to open pcap file! Error: %s\n", errbuf);
	}
	return pcapInfo;
}

int main(int argc, char **args) {
	//only take one pcap file as an input
	int parseRet = 0;
	pcap_t *pcapInfo;
	if (argc != 2) {
		fprintf(stderr, "Illegal Use: Please provide a single pcap file\n");
		parseRet = 1;
	}
		
	//open pcap file
	else if ((pcapInfo = openPcapFile(args[1])) == NULL) {
		parseRet = 1;
	}
	else{
		//parse pcap file if open is successful
		parseRet = parsePacket(pcapInfo);
	}
	exit(parseRet);
}
