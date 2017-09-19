/* Program 1     : Packet Parsing
 * Author        : Calvin Laverty
 * Last Modified : 9/19/17
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

int parseTCPHeader(const u_char *pkt_data, struct tcp_psuedo_header psuedo){
   //also pass the psuedo-header to calc checksum
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
      //create tcp_psuedo header to pass info
      struct tcp_psuedo_header *psuedo_header = malloc(sizeof(struct tcp_psuedo_header));
		//now initialize with ip info
      psuedo_header->tcp;
      psuedo_header;
      ip_ret = parseTCPHeader(&pkt_data[ihl], psuedo_header);
	}
	else{
		//unknown....
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
	int subStructureReturn = 0;
	struct enet_header *ethHeader = (struct enet_header *)pkt_data;
	printEthernetHeader(ethHeader);
	//now pass on to correct sub-structure	
	if(ntohs(ethHeader->type) == ARP){
		subStructureReturn = parseARPHeader(&pkt_data[sizeof(uint8_t) * 14]);
	}
	else if(ntohs(ethHeader->type) == IPV4){
		subStructureReturn = parseIPHeader(&pkt_data[sizeof(uint8_t) * 14]);
	}
	else {
		fprintf(stderr, "Unable to parse substructure of Ethernet Header... Returning 1\n");
		subStructureReturn = 1;
	}
	return subStructureReturn;
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

/* design will be peel off a layer an pass to lower level of packet */
int parsePacket(pcap_t *pcapSaveFile) {
	int eNetHeaderRet = 0;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	int packetsRead = 0;
	
	//loop through until we don't have anymore saved packets
	while (pcap_next_ex(pcapSaveFile, &header, &pkt_data) != -2) {
		packetsRead++;
		fprintf(stdout, "\nPacket number: %d  ", packetsRead); 
		fprintf(stdout, "Packet Len: %d\n\n", header->len);
		//pass to ethernetHeader who will pass on the rest of the work
		eNetHeaderRet = parseEthernetHeader(pkt_data);
		//fprintf(stderr, "Ethernet Header Return Value: %d\n", eNetHeaderRet);
		fprintf(stdout, "\n"); //formatting
	}
	
	return eNetHeaderRet;
}

/* will return null if pcap_open_offlien is null */
pcap_t *openPcapFile(char *fileName) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcapInfo;
	if ((pcapInfo = pcap_open_offline(fileName, errbuf)) == NULL) {
		fprintf(stderr, "Unable to open pcap file %s: %s\n", fileName, errbuf);
	}
	return pcapInfo;
}

int main(int argc, char **args) {
	//take one file as an input
	pcap_t *pcapInfo;
	if (argc != 2) {
		fprintf(stderr, "Illegal Use: Please provide one trace file\n");
		return 1;
	}
		
	//open pcap file
	if ((pcapInfo = openPcapFile(args[1])) == NULL) {
		return 1;
	}

	//parse pcap file
	int parseRet = parsePacket(pcapInfo);
	return parseRet;
}
