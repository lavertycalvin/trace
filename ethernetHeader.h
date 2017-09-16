/* allows for trace to parse only the ethernet header 
 * Header Output:
 * 	Dest MAC	: 
 * 	Source MAC	:
 * 	Type		: ARP, IP, Unknown		
 */


/*14 bytes consumed by the ethernet header*/
struct enet_header {
	char dest[6];
	char source[6];
	char type[2];
};

