#pragma once
#pragma comment(lib,"ws2_32.lib")
#include <pcap.h>
#include <iostream>
#include <stdio.h>
#include <time.h>

#define MAX_ADDR_LENGTH 16  
#define EPT_IP 0x0800
#define EPT_ARP 0x0806
#define EPT_RARP 0x8035
#define ARP_HARDWARE 0x0001
#define ARP_REQUEST 0x0001
#define ARP_REPLY 0x0002


/*
  ��ʾMACͷ����Ϣ
  dest_addr: 6�ֽڵ�Ŀ��MAC��ַ
  src_addr: 6�ֽڵ�ԴMAC��ַ
  type: ��ʾ�ϲ�Э������,0x0800��ʾ�ϲ���IPЭ��,0x0806��ʾ�ϲ���ARPЭ��
*/
typedef struct ether_header
{
	u_char dest_addr[6];
	u_char src_addr[6];
	u_short type;
}mac_header;


/*
  ��ʾipv4���ݵ�ͷ����Ϣ
  ver_len: ǰ4λ��ʾipЭ��İ汾�ţ���4λ��ʾ�ײ�����
  tos: ��������
  tlen: ���ݱ��ܳ���
  identity: ip���ݱ�Ψһ��ʶ
  flag_offset: ǰ3λ�Ǳ�־λ����13λ��ʾƫ����
  ttl: ��������
  protocol: �ϲ�Э������
  checksum: У���
  saddr: Դip��ַ
  daddr: Ŀ��ip��ַ
*/
typedef struct ip_header
{
	u_char ver_hlen;
	u_char tos;
	u_short tlen;
	u_short identity;
	u_short flag_offset;
	u_char ttl;
	u_char protocol;
	u_short checksum;
	u_int saddr;
	u_int daddr;
}ip_header;

/*
  ��ʾARP���ݵ�ͷ����Ϣ
  hdw_type: Ӳ������
  protocol: �ϲ�Э������
  hdw_len: Ӳ������
  protocol_len: Э�鳤��
  op_num: ������
  smac_addr: ԴӲ����ַ
  saddr: Դ�߼���ַ
  dmac_addr: Ŀ��Ӳ����ַ
  daddr: Ŀ���߼���ַ
*/

typedef struct arp_header
{
	u_short hdw_type;
	u_short protocol;
	u_char hdw_len;
	u_char protocol_len;
	u_short op_num;
	u_char smac_addr[6];
	u_char saddr[4];
	u_char dmac_addr[6];
	u_char daddr[4];
}arp_header;


typedef struct tcp_header
{
	u_short sport;
	u_short dport;
	u_int seq;
	u_int ack_seq;
	u_short hdr_size_and_detail;
	u_short window_size;
	u_short checksum;
	u_short pEmer;

}tcp_header;

class protocol_handle
{
public:
	void mac_packet_handler(u_char *arg, const struct pcap_pkthdr *pkt_header, const u_char *pkt_content);

	void ipv4_packet_handler(u_char *arg, const struct pcap_pkthdr *pkt_header, const u_char *pkt_content);

	void arp_packet_handler(u_char *arg, const struct pcap_pkthdr * pkt_header, const u_char *pkt_content);

	void tcp_packet_handler(u_char *arg, const struct pcap_pkthdr *pkt_header, const u_char *pkt_content);
};

