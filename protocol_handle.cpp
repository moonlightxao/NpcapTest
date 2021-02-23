#include "protocol_handle.h"

void protocol_handle::mac_packet_handler(u_char *arg,const struct pcap_pkthdr *pkt_header, const u_char *pkt_content){
	mac_header *mac_hdr;
	u_short upper_type;
	u_char *mac_addr;

	mac_hdr = (mac_header*)pkt_content;
	upper_type = ntohs(mac_hdr->type);

	printf("==============Ethernet protocol==============\n");
	mac_addr = mac_hdr->dest_addr;

	printf("Destination: %02x:%02x:%02x:%02x:%02x:%02x\n",
		*mac_addr,
		*(mac_addr + 1),
		*(mac_addr + 2),
		*(mac_addr + 3),
		*(mac_addr + 4),
		*(mac_addr + 5)
	);

	mac_addr = mac_hdr->src_addr;
	printf("Source: %02x:%02x:%02x:%02x:%02x:%02x\n",
		*mac_addr,
		*(mac_addr + 1),
		*(mac_addr + 2),
		*(mac_addr + 3),
		*(mac_addr + 4),
		*(mac_addr + 5)
	);

	switch (upper_type)
	{
	case 0x0800:
		printf("Type: %s\n", "IP");
		break;
	case 0x0806:
		printf("Type: %s\n", "ARP");
		break;
	case 0x8035:
		printf("Type: %s\n", "RARP");
		break;
	default:
		printf("unkown protocol!\n");
	}

	//处理不同的上层协议
	switch (upper_type)
	{
	case 0x0800:
		ipv4_packet_handler(arg, pkt_header, pkt_content);
		break;
	case 0x0806:
		arp_packet_handler(arg, pkt_header, pkt_content);
		break;
	default:
		printf("unkown protocol!\n");
	}
}

void protocol_handle::ipv4_packet_handler(u_char * arg, const pcap_pkthdr * pkt_header, const u_char * pkt_content)
{
	ip_header *ip_hdr;
	sockaddr_in source, dest;
	ip_hdr = (ip_header*)(pkt_content + 14);
	u_char hlen = (ip_hdr->ver_hlen & 0x0f) << 2;
	u_short rev = ntohs(ip_hdr->flag_offset);
	char sourceIP[MAX_ADDR_LENGTH], destIP[MAX_ADDR_LENGTH];

	source.sin_addr.s_addr = ip_hdr->saddr;
	dest.sin_addr.s_addr = ip_hdr->daddr;

	strncpy_s(sourceIP, inet_ntop(AF_INET, &source.sin_addr, sourceIP, MAX_ADDR_LENGTH), MAX_ADDR_LENGTH);
	strncpy_s(destIP, inet_ntop(AF_INET, &dest.sin_addr, destIP, MAX_ADDR_LENGTH), MAX_ADDR_LENGTH);

	printf("==============IP protocol==============\n");
	printf("ip version: %d\n", ip_hdr->ver_hlen >> 4);
	printf("Header Length: %d\n", hlen);
	printf("Total Length: %d\n", ntohs(ip_hdr->tlen));
	printf("Identification: %d\n", ntohs(ip_hdr->identity));
	printf("Flags: %d\n", rev >> 13);
	printf("Reserved bit: %d\n", (rev & 0x8000) >> 15);
	printf("Don't fragment: %d\n", (rev & 0x4000) >> 14);
	printf("More fragment: %d\n", (rev & 0x2000) >> 13);
	printf("Time to live: %d\n", ip_hdr->ttl);
	printf("Protocol: ");
	switch (ip_hdr->protocol)
	{
	case 1:
		printf("%s \n", "ICMP");
		break;
	case 6:
		printf("%s \n", "TCP");
		break;
	case 17:
		printf("%s \n", "UDP");
		break;
	default:
		printf("%s \n", "unkown protocol");
	}
	printf("Header Checksum: 0x%.4x\n", ntohs(ip_hdr->checksum));
	printf("Source: %s\n", sourceIP);
	printf("Destination: %s\n", destIP);

	printf("========================================\n");
	
	switch (ip_hdr->protocol)
	{
	case 6:
		tcp_packet_handler(arg, pkt_header, (pkt_content + 14) + hlen);
		break;
	default:
		printf("unkown protocol\n");
	}

}
 
void protocol_handle::arp_packet_handler(u_char * arg, const pcap_pkthdr * pkt_header, const u_char * pkt_content)
{
	arp_header *arp_hdr;
	u_char *mac_addr;
	arp_hdr = (arp_header*)(pkt_content + 14);


	printf("==============ARP protocol==============\n");
	switch (ntohs(arp_hdr->hdw_type))
	{
	case ARP_HARDWARE:
		printf("Hardware type: %s\n", "Ethernet");
		break;
	default:
		printf("Hardware type: %s\n", "Unkown");
	}

	switch (ntohs(arp_hdr->protocol))
	{
	case EPT_IP:
		printf("Protocol type: %s\n", "IPv4");
		break;
	default:
		printf("Protocol type: %s\n", "Unkown");
	}

	printf("Hardware size: %d\n", arp_hdr->hdw_len);
	printf("Protocol size: %d\n", arp_hdr->protocol_len);

	switch (ntohs(arp_hdr->op_num))
	{
	case 1:
		printf("Opcode: %s\n", "request");
		break;
	case 2:
		printf("Opcode: %s\n", "response");
		break;
	}

	mac_addr = arp_hdr->smac_addr;
	printf("Sender MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
		*mac_addr,
		*(mac_addr + 1),
		*(mac_addr + 2),
		*(mac_addr + 3),
		*(mac_addr + 4),
		*(mac_addr + 5)
	);

	printf("Sender IP address: %d.%d.%d.%d\n",
		arp_hdr->saddr[0],
		arp_hdr->saddr[1],
		arp_hdr->saddr[2],
		arp_hdr->saddr[3]
	);

	mac_addr = arp_hdr->dmac_addr;
	printf("Target MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
		*mac_addr,
		*(mac_addr + 1),
		*(mac_addr + 2),
		*(mac_addr + 3),
		*(mac_addr + 4),
		*(mac_addr + 5)
	);

	printf("Target IP address: %d.%d.%d.%0d\n",
		arp_hdr->daddr[0],
		arp_hdr->daddr[1],
		arp_hdr->daddr[2],
		arp_hdr->daddr[3]
		);
	
}

void protocol_handle::tcp_packet_handler(u_char * arg, const pcap_pkthdr * pkt_header, const u_char * pkt_content)
{
	tcp_header *tcp_hdr;
	tcp_hdr = (tcp_header*)pkt_content;
	u_short rev = ntohs(tcp_hdr->hdr_size_and_detail);
	printf("==============TCP protocol==============\n");
	printf("Source Port: %d\n", ntohs(tcp_hdr->sport));
	printf("Destination Port: %d\n", ntohs(tcp_hdr->dport));
	printf("Sequence number (raw): %d\n", ntohl(tcp_hdr->seq));
	printf("Acknowledgment number (raw): %d\n", ntohl(tcp_hdr->ack_seq));
	printf("Header length: %d\n", (rev >> 12) << 2);
	printf("Congestion Window Reduced (CWR): %s\n",(rev & 0x0080) ? "Set":"Not Set");
	printf("ECN-Echo: %s\n", (rev & 0x0040) ? "Set" : "Not Set");
	printf("Urgent: %s\n", (rev & 0x0020) ? "Set":"Not Set");
	printf("Acknowledgment: %s\n", (rev & 0x0010) ? "Set":"Not Set");
	printf("Push: %s\n", (rev & 0x0008) ? "Set":"Not Set");
	printf("Reset: %s\n", (rev & 0x0004) ? "Set":"Not Set");
	printf("Syn: %s\n", (rev & 0x0002) ? "Set":"Not Set");
	printf("Fin: %s\n", (rev & 0x0001) ? "Set":"Not Set");
	printf("Window Size: %d\n", ntohs(tcp_hdr->window_size));
	printf("TCP Checksum: %d\n", ntohs(tcp_hdr->checksum));
	printf("Urgent Pointer: %d\n", ntohs(tcp_hdr->pEmer));
	printf("========================================\n");
}
