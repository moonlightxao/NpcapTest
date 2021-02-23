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
  表示MAC头部信息
  dest_addr: 6字节的目的MAC地址
  src_addr: 6字节的源MAC地址
  type: 表示上层协议类型,0x0800表示上层是IP协议,0x0806表示上层是ARP协议
*/
typedef struct ether_header
{
	u_char dest_addr[6];
	u_char src_addr[6];
	u_short type;
}mac_header;


/*
  表示ipv4数据的头部信息
  ver_len: 前4位表示ip协议的版本号，后4位表示首部长度
  tos: 服务类型
  tlen: 数据报总长度
  identity: ip数据报唯一标识
  flag_offset: 前3位是标志位，后13位表示偏移量
  ttl: 生存周期
  protocol: 上层协议类型
  checksum: 校验和
  saddr: 源ip地址
  daddr: 目的ip地址
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
  表示ARP数据的头部信息
  hdw_type: 硬件类型
  protocol: 上层协议类型
  hdw_len: 硬件长度
  protocol_len: 协议长度
  op_num: 操作码
  smac_addr: 源硬件地址
  saddr: 源逻辑地址
  dmac_addr: 目标硬件地址
  daddr: 目标逻辑地址
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

