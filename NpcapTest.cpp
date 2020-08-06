
#include <iostream>
#include <stdio.h>
#include <pcap.h>
#include <time.h>
#define LINE_MAX 16

typedef struct ether_header
{
	u_char dest_addr[6];
	u_char src_addr[6];
	u_char type[2];
}mac_header;

int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	pcap_pkthdr *header;
	pcap_t *fp;
	const u_char *pkt_data;
	int i = 0;
	int inum;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,NULL,&alldevs,errbuf) == -1) {
		printf("查找所有适配器失败！！\n");
		return -1;
	}

	for (d = alldevs; d != NULL; d = d->next) {
		printf("%d . %s",++i,d->name);
		if (d->description != NULL) {
			printf(" (%s)\n",d->description);
		}
		else {
			printf("该设备没有可用描述\n");
		}
	}

	if (i == 0) {
		printf("\n 未找到可用的适配器！\n");
		return -1;
	}

	printf("请输入想要打开的适配器序号：");
	scanf_s("%d",&inum);

	if (inum<1 || inum>i) {
		printf("输入错误！！");
		return -1;
	}

	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);


	if ((fp = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL) {
		printf("打开选中的适配器错误！！");
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\n正在监听 %s ...\n",d->description);
	int type = pcap_datalink(fp);
	const char *adapterName = pcap_datalink_val_to_name(type);
	printf("该适配器类型:(%s)\n",adapterName);
	if (pcap_set_rfmon(fp, 1) == 0) {
		printf("适配器开启monitor模式成功！！\n");
	}
	printf("适配器开启monitor模式失败！\n");
	int res;
	int cnt = 0;
	while (cnt < 20) {
		res = pcap_next_ex(fp, &header, &pkt_data);
		if (res == 0) {
			printf("捕获数据包超时\n");
			continue;
		}
		mac_header *mh;
		int length = sizeof(mac_header);
		printf("捕获的第%d个数据包(包大小 = %d,捕获大小 = %d)\n",++cnt,header->len,header->caplen);
		for (int k = 1; k < (header->caplen+1); k++) {
			printf("%.2x ",pkt_data[k-1]);
			if ((k% LINE_MAX) == 0) {
				printf("\n");
			}
		}

		//直接用强制类型转换得到以太网帧头
		mh = (mac_header *)pkt_data;
		//开始解析以太网帧（瞎写试试）
		u_char * mac_string;
		printf("\nMAC帧源地址：\n");
		mac_string = mh->src_addr;
		for (int i = 0; i < 6; i++) {
			printf("%.2x ",mac_string[i]);
		}
		printf("\n");
		mac_string = mh->dest_addr;
		printf("MAC帧目的地址：\n");
		for (int i = 0; i < 6; i++) {
			printf("%.2x ", mac_string[i]);
		}
		printf("\n");


		printf("\n\n");
	}
	if (res == -1) {
		printf("捕获数据包出错！！\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	pcap_freealldevs(alldevs);
	return 0;
}
