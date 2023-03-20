// #include "stdafx.h"
#define HAVE_REMOTE
#include<stdio.h>  // stdio需要引用在pcap之前，因为pcap中对sprintf系列函数进行了define
#include "pcap.h"
#include<winsock2.h>
#include<string.h>

#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"packet.lib")
#pragma comment(lib,"ws2_32.lib")
// mingw的lib目录下没有ws2_32.lib文件，gcc 在window下链接 libws2_32.a 文件 方法是加上-lws2_32
 
void ethernet_protocol_packet_callback(u_char *argument,const struct pcap_pkthdr* packet_header,const u_char* packet_content);
void ip_protool_packet_callback(u_char *argument,const struct pcap_pkthdr* packet_header,const u_char* packet_content);
void tcp_protool_packet_callback(u_char *argument,const struct pcap_pkthdr* packet_header,const u_char* packet_content);
void udp_protool_packet_callback(u_char *argument,const struct pcap_pkthdr* packet_header,const u_char* packet_content);
 
// ip地址流量计
struct flowmeter
{
	char ip_address[66];
    int number;  //该ip地址发出或收到的数据包的数量
}counters[30]; //最多记录30个ip地址对应的流量
int count_tail = 0; //记录当前已填充的ip对应的数组下标

//以太网协议头
struct ether_header
{
	u_int8_t ether_dhost[6]; //目的Mac地址
	u_int8_t ether_shost[6]; //源Mac地址
	u_int16_t ether_type;    //协议类型
};
 
//IPv4协议头
struct ip_header
{
#if defined(WORDS_BIENDIAN)
	u_int8_t    ip_version:4,ip_header_length:4;
#else
	u_int8_t    ip_header_length:4,ip_version:4;
#endif
	u_int8_t    ip_tos; // 区分服务，4位
	u_int16_t   ip_length; //整个IP数据包的字节长度，16位，包括协议头部和数据
	u_int16_t   ip_id; // 标识，16位
	u_int16_t   ip_off; // 偏移量，8位
	u_int8_t    ip_ttl; // 生存时间TTL，8位
	u_int8_t    ip_protocol; // 协议，8位，如17代表UDP，6代表TCP
	u_int16_t   ip_checksum; // 首尾校验和，16位，确保IP协议头的完整性
	// in_addr定义在inaddr.h中
	struct in_addr ip_souce_address; //源地址，32位
	struct in_addr ip_destination_address; // 目的地址，32位
};

//UDP协议头
struct udphdr
{
	u_int16_t source_port; // 源地址端口
	u_int16_t dest_port;    // 目的地址端口
	u_int16_t len;     // UDP长度
	u_int16_t check;   // UDP校验和
}; 
 
//TCP协议头
#define __LITTLE_ENDIAN_BITFIELD
struct tcphdr 
{
	u_int16_t   source_port;         // 源地址端口
	u_int16_t   dest_port;           // 目的地址端口
	u_int32_t   seq;            // 序列号
	u_int32_t   ack_seq;        // 确认序列号
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u_int16_t res1:4,   // 保留
	doff:4,				// 偏移
	fin:1,              // 关闭连接标志
	syn:1,              // 请求连接标志
	rst:1,              // 重置连接标志
	psh:1,              // 接收方尽快将数据放到应用层标志
	ack:1,              // 确认序号标志
	urg:1,              // 紧急指针标志
	ece:1,              // 拥塞标志位
	cwr:1;              // 拥塞标志位
#elif defined(__BIG_ENDIAN_BITFIELD)
	u_int16_t doff:4,   /*偏移*/
	res1:4,             /*保留*/
	cwr:1,              /*拥塞标志位*/
	ece:1,              /*拥塞标志位*/
	urg:1,              /*紧急指针标志*/
	ack:1,              /*确认序号标志*/
	psh:1,              /*接收方尽快将数据放到应用层标志*/
	rst:1,              /*重置连接标志*/
	syn:1,              /*请求连接标志*/
	fin:1;              /*关闭连接标志*/
#else
	u_int16_t	flag;
#endif 
	u_int16_t   window;         /*滑动窗口大小*/
	u_int16_t   check;          /*校验和*/
	u_int16_t   urg_ptr;        /*紧急字段指针*/
};

//以太网协议分析
void ethernet_protocol_packet_callback(u_char *argument,const struct pcap_pkthdr* packet_header,const u_char* packet_content)
{
	u_short ethernet_type;
	struct ether_header *ethernet_protocol;
	u_char *mac_string;
	static int packet_number = 1; //全局变量，各数据包共享

	//转换时间戳易于识别
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;
	local_tv_sec = packet_header->ts.tv_sec;
	// localtime函数，将local_tv_sec分解成tm结构
	ltime = localtime(&local_tv_sec);
	// strftime函数，格式化结构ltime表示的时间，并将结果存在timestr中
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
	
	printf("----------------------------------------------\n");
	printf("捕获第%d个网络数据包\n",packet_number);
	printf("捕获时间：%s\n", timestr);
	
	printf("数据包长度:%d\n",packet_header->len);

	printf("---------以太网协议---------\n");
	ethernet_protocol=(struct ether_header*)packet_content;//获得数据包内容
	ethernet_type=ntohs(ethernet_protocol->ether_type);//获得以太网类型
	printf("以太网类型:%04x\n",ethernet_type);
	switch (ethernet_type)
	{
	case 0x0800: printf("网络层协议是IPv4协议\n");break;
	case 0x0806: printf("网络层协议是ARP协议\n");break;
	case 0x8035: printf("网络层协议是RARP协议\n");break;
	case 0x814C: printf("网络层协议是简单网络管理协议SNMP\n");break;
	case 0x8137: printf("网络层协议是因特网包交换（IPX：Internet Packet Exchange）\n");break;
	case 0x86DD: printf("网络层协议是IPv6协议\n");break;
	case 0x880B: printf("网络层协议是点对点协议（PPP：Point-to-Point Protocol）\n");break;
	default:break;
	}
    
	// 显示MAC帧的源地址，目的地址
	mac_string=ethernet_protocol->ether_shost;
	printf("MAC帧源地址:%02x:%02x:%02x:%02x:%02x:%02x\n",*mac_string,*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));
	mac_string=ethernet_protocol->ether_dhost;
	printf("MAC帧目的地址:%02x:%02x:%02x:%02x:%02x:%02x\n",*mac_string,*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));
	
	if(ethernet_type==0x0800)//继续分析IP协议
	{
		// 第3个参数表示
		ip_protool_packet_callback (argument,packet_header,packet_content+sizeof(ether_header));
	}
	printf("----------------------------------------------\n");
	packet_number++;
}
 
//IP协议分析
void ip_protool_packet_callback(u_char *argument,const struct pcap_pkthdr* packet_header,const u_char* packet_content)
{
	struct ip_header *ip_protocol;
	u_int header_length=0;
	u_int offset;
	u_char tos;
	u_int16_t checksum;
 
    // 将ip_header结构体的指针ip_ptotocol指向对应内容
	ip_protocol = (struct ip_header *)packet_content;
	checksum =ntohs(ip_protocol->ip_checksum);
	tos = ip_protocol->ip_tos;
	offset = ntohs(ip_protocol->ip_off);
	printf("---------IP协议---------\n");
	printf("版本号:%d\n", ip_protocol->ip_version);
	printf("首部长度:%d\n",header_length);
	printf("服务质量:%d\n",tos);
	printf("总长度:%d\n",ntohs(ip_protocol->ip_length));
	printf("标识:%d\n",ntohs(ip_protocol->ip_id));
	printf("偏移:%d\n",(offset & 0x1fff) * 8);
	printf("生存时间:%d\n",ip_protocol->ip_ttl);
	printf("协议类型:%d\n",ip_protocol->ip_protocol); // 17代表UDP，6代表TCP
 
    // 维护流量计数组，及其尾部标识
	char aaa[8] = {'1', '1', '1', '1', '1', '1', '1', '1'};
	memcpy(counters[0].ip_address, aaa, strlen(aaa));

	int len1 = strlen(inet_ntoa(ip_protocol->ip_souce_address));
    int len2 = strlen(inet_ntoa(ip_protocol->ip_destination_address));
	
	// 扫描现有flowmeter，查看ip是否已经被登记
	int equal11 = 0;
	int equal12 = 0;
	int pos1 = 0;
	int pos2 = 0;
	// 判断源地址、目的地址是否被登记
    for (int i = 0; i <= count_tail; i++) {
		int ok1 = 1;
	    for (int j = 0; j < len1; j++) {
		    if(counters[i].ip_address[j] != inet_ntoa(ip_protocol->ip_souce_address)[j]) {
		     	ok1 = 0;
			    break;
		    }
	    }
		int ok2 = 1;
	    for (int j = 0; j < len2; j++) {
		    if(counters[i].ip_address[j] != inet_ntoa(ip_protocol->ip_destination_address)[j]) {
		     	ok2 = 0;
			    break;
		    }
	    }
		// 如果被登记，则用pos1记录源地址对应的下标，用pos2记录目的地址对应的下标
		if (ok1) {
			equal11 =1;
			pos1 = i;
		}
		if(ok2) {
			equal12 = 1;
			pos2 = i;
		}
	}
    
	// 维护已经记录的ip的信息
	if(equal11) counters[pos1].number++;
	if(equal12) counters[pos2].number++;
	if (equal11 == 1 && equal12 == 1) {
	}
	else{ // 登记没有记录的1或2个ip信息
		if(!equal11) {	//如果源ip没有登记	
		    count_tail++;
			memcpy(counters[count_tail].ip_address, inet_ntoa(ip_protocol->ip_souce_address), len1 * 8);
			counters[count_tail].number = 1;
		}
		if(!equal12) {  //如果目的ip没有登记
		    count_tail++;
			memcpy(counters[count_tail].ip_address, inet_ntoa(ip_protocol->ip_destination_address), len2 * 8);
			counters[count_tail].number = 1;
		}
	}
    
    // for (int i = 0; i <= count_tail; i++) {
	// 	printf("%s\n", counters[i].ip_address);
	// 	printf("%d\n", counters[i].number);
	// }

	printf("检验和:%d\n",checksum);
	printf("源IP地址:%s\n", inet_ntoa(ip_protocol->ip_souce_address));
	int snum = 0;
	for (int i = 0; i <= count_tail; i++) {
		if (strcmp(counters[i].ip_address, inet_ntoa(ip_protocol->ip_souce_address)) == 0) {
            snum = counters[i].number;
		}
	}
	printf("当前已捕获以该IP地址为源地址的数据包数量：%d\n", snum);
	printf("目的地址:%s\n", inet_ntoa(ip_protocol->ip_destination_address));
	int dnum = 0;
	for (int i = 0; i <= count_tail; i++) {
		if (strcmp(counters[i].ip_address, inet_ntoa(ip_protocol->ip_destination_address)) == 0) {
            dnum = counters[i].number;
		}
	}
	printf("当前已捕获以该IP地址为目的地址的数据包数量：%d\n", dnum);
 
    // 继续分析TCP、UDP协议
	switch (ip_protocol->ip_protocol)
	{
	case 1: printf("传输层协议是ICMP协议\n");break;
	case 2: printf("传输层协议是IGMP协议\n");break;
	case 6: 
		{
			//printf("上层协议是TCP协议\n");
			tcp_protool_packet_callback (argument,packet_header,packet_content+sizeof(ip_header));
		}
		break;
 
	case 17: 
		{
			//printf("上层协议是UDP协议\n");
			udp_protool_packet_callback (argument,packet_header,packet_content+sizeof(ip_header));
		}
		break;
	default:break;
	}
	
}
 
//TCP协议分析
void tcp_protool_packet_callback(u_char *argument,const struct pcap_pkthdr* packet_header,const u_char* packet_content)
{
	struct tcphdr *tcp_protocol;
	u_int header_length=0;
	u_int offset;
	u_char tos;
	u_int16_t checksum;
 
	tcp_protocol = (struct tcphdr *) packet_content;
	checksum =ntohs(tcp_protocol->check);
 
	printf("---------TCP协议---------\n");
	printf("源端口:%d\n", ntohs(tcp_protocol->source_port));
	printf("目的端口:%d\n",ntohs(tcp_protocol->dest_port));
	printf("SEQ:%d\n",ntohl(tcp_protocol->seq)); //sequence,序号
	printf("ACK SEQ:%d\n",ntohl(tcp_protocol->ack_seq)); // 确认序号
	printf("check:%d\n",checksum);
 
	/// 如果源端口或目的端口为80，则是http协议
	if(ntohs(tcp_protocol->source_port)==80 || ntohs(tcp_protocol->dest_port)==80)
	{
		//http协议，属于应用层
		printf("http data:\n%s\n",packet_content+sizeof(tcphdr));
	}
 
}
 
//UDP协议分析
void udp_protool_packet_callback(u_char *argument,const struct pcap_pkthdr* packet_header,const u_char* packet_content)
{
	struct udphdr *udp_protocol;
	u_int header_length=0;
	u_int16_t checksum;
 
	udp_protocol = (struct udphdr *) packet_content;
	checksum =ntohs(udp_protocol->check);
 
	u_int16_t source_port; /*源地址端口*/
	u_int16_t dest_port;    /*目的地址端口*/
	u_int16_t len;     /*UDP长度*/
	u_int16_t check;   /*UDP校验和*/
 
	printf("---------UDP协议---------\n");
	printf("源端口:%d\n", udp_protocol->source_port);
	printf("目的端口:%d\n",udp_protocol->dest_port);
	printf("len:%d\n",udp_protocol->len);
	printf("check:%d\n",checksum);
 
}
 
int main()
{	
	printf( "Let's begin now!\n" );
	
	// freopen("readchoice.txt", "r", stdin);
	// freopen("showdevice.txt", "w", stdout);

	//pcap_t* pcap_handle; //winpcap句柄
	char error_content[PCAP_ERRBUF_SIZE]; //存储错误信息
	bpf_u_int32 net_mask=0; //掩码地址
	bpf_u_int32 net_ip=0;  //网络地址
	char *net_interface;  //网络接口

	struct bpf_program bpf_filter;  //BPF过滤规则
	char bpf_filter_string[]="ip"; //过滤规则字符串，只分析IPv4的数据包
 
	pcap_if_t * allAdapters;//适配器列表
	pcap_if_t * adapter;
	pcap_t           * adapterHandle;//适配器句柄
 
	char errorBuffer[ PCAP_ERRBUF_SIZE ];//错误信息缓冲区
	if( pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &allAdapters, errorBuffer)== -1 )
	{	//检索机器连接的所有网络适配器
		fprintf( stderr, "Error in pcap_findalldevs_ex function: %s\n", errorBuffer );
		return -1;
	}
	if( allAdapters == NULL )
	{	//不存在任何适配器
		printf( "\nNo adapters found! Make sure WinPcap is installed.\n" );
		return 0;
	}
	int crtAdapter = 0;
	for( adapter = allAdapters; adapter != NULL; adapter = adapter->next)
	{	//遍历输入适配器信息(名称和描述信息)
		printf( "\n%d.%s ", ++crtAdapter, adapter->name ); 
		printf( "-- %s\n", adapter->description );
	}
	printf( "\n" );
	//选择要捕获数据包的适配器
	int adapterNumber;
	printf( "Enter the adapter number between 1 and %d:", crtAdapter );

	// fclose(stdout);
    // freopen("askchoice.txt", "w", stdout);
	
	scanf( "%d", &adapterNumber );
	if( adapterNumber < 1 || adapterNumber > crtAdapter )
	{
		printf( "\nAdapter number out of range.\n" );
		// 释放适配器列表
		pcap_freealldevs( allAdapters );
		return -1;
	}
	adapter = allAdapters;
	// 指针跳到指定的适配器
	for( crtAdapter = 0; crtAdapter < adapterNumber - 1; crtAdapter++ )
		adapter = adapter->next;
	
	// fclose(stdout);
    // freopen("result.txt", "w", stdout);
	
	// 打开指定适配器
	adapterHandle = pcap_open( adapter->name, // name of the adapter
		65536,         // portion of the packet to capture
		// 65536 guarantees that the whole 
		// packet will be captured
		PCAP_OPENFLAG_PROMISCUOUS, // promiscuous mode
		1000,             // read timeout - 1 millisecond
		NULL,          // authentication on the remote machine
		errorBuffer    // error buffer
		);
	if( adapterHandle == NULL )
	{//指定适配器打开失败
		fprintf( stderr, "\nUnable to open the adapter\n", adapter->name );
		// 释放适配器列表
		pcap_freealldevs( allAdapters );
		return -1;
	}
 
	char errbuf[2048];
	pcap_createsrcstr(NULL, 0, NULL, "80", NULL, errbuf);
 
	printf( "\nCapture session started on  adapter %s\n", adapter->name );
	pcap_freealldevs( allAdapters );//释放适配器列表
 
	pcap_compile(adapterHandle,&bpf_filter,bpf_filter_string,0,net_ip); //编译过滤规则
	pcap_setfilter(adapterHandle,&bpf_filter);//设置过滤规则“ip”

	// pcap_datalink(adapterHandle)返回链路层的类型，如DLT_IEEE802表示IEEE802.5令牌环网
	if (pcap_datalink(adapterHandle)!=DLT_EN10MB) //DLT_EN10MB表示以太网
		return 0;

	// 捕获指定适配器上的10个数据包，并调用以太网协议分析函数
	pcap_loop(adapterHandle,10,ethernet_protocol_packet_callback,NULL); //捕获10个数据包进行分析
 
    // 抓包完成后，关闭该适配器的句柄
	pcap_close(adapterHandle);
	return 0;
}