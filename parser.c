#include "readPcap.h"
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#define STRSIZE 1024

//char* myIP = "192.168.1.172";
#define max_ipAddrNum 50
char IPs[max_ipAddrNum][16];
int ipAddrNum = 0;

int web_port_num_flow = 0;//80,8080,3128,443端口的流个数
int web_port_num_pkt = 0;//80,8080,3128,443端口的包个数
int tcp_num = 0;
int udp_num = 0;
typedef struct FLOW_t{
	char srcIP[16];
	char dstIP[16];
	int srcPORT;
	int dstPORT;
	int protocol;
	double pktNUM;//包总数
	double nega_pktNUM;//入包个数
	double posi_pktNUM;//出包个数
	double nega_BYTES;//入字节量
	double posi_BYTES;//出字节量
	double max_pktSIZE;//最大数据包
	double sum_pktSIZE;//总字节数
	double first_timestamp;//流的第一个包到达时间
	double last_timestamp;//流的最后一个包到达时间
	double this_timestamp;
	double pre_timestamp;
	double max_interval;//最大包间隔

}FLOW_t;
#define max_flowNum 1000/*------------------------注意：当前只允许最多1000个流------------------------------------*/
FLOW_t* FLOWs[max_flowNum];
int flowNum = 0;

char* pcapFile = "./Test/test.pcap";//测试文件路径

int main(int argc, char* argv[]){
	if(argc != 2){
		printf("\nUsage:./pcapToFlow.o ipAddr\n");
		return -1;
	}
	char* myIP = argv[argc-1];
	//各种初始化
	int i=0;
	for(i=0; i<max_flowNum; i++){
		FLOWs[i] = (FLOW_t *)malloc(sizeof(FLOW_t));
	}

	struct pcap_file_header* file_header;
	struct pcap_pkthdr* pkt_header;
	IPHeader_t* ip_header;
	TCPHeader_t* tcp_header;
	UDPHeader_t* udp_header;
	file_header = (struct pcap_file_header*)malloc(sizeof(struct pcap_file_header));
	pkt_header = (struct pcap_pkthdr*)malloc(sizeof(struct pcap_pkthdr));
	ip_header = (IPHeader_t *)malloc(sizeof(IPHeader_t));
	tcp_header = (TCPHeader_t *)malloc(sizeof(TCPHeader_t));
	udp_header = (UDPHeader_t *)malloc(sizeof(UDPHeader_t));

	//open pcap file
	FILE* fp;
	while(1){
		fp = fopen(pcapFile, "rb");
		if(fp == NULL){
			printf("Error: can not open pcap file or the file does not exist.\n");
			sleep(3);
		}
		else break;
	}

	int pkt_num =0;
	int pkt_offset = 24;
	
	while(fseek(fp, pkt_offset, SEEK_SET) == 0){	
		pkt_num++;
		if(fread(pkt_header, 16, 1, fp)!=1){
			printf("\nread end of pcap file\n");
			break;
		}
	//	printf("\n%d %d %d %d\n", pkt_header->ts.tv_sec,pkt_header->ts.tv_usec,pkt_header->caplen,pkt_header->len);
		//break;
		pkt_offset += 16 + pkt_header->caplen;//next packet
		fseek(fp, 14, SEEK_CUR);//move on 14 bytes from SEEK_CUR

		//IP analysis
		if(fread(ip_header, sizeof(IPHeader_t), 1, fp)!=1){
			printf("%d: can not read ip_header\n", pkt_num);
			break;
		}
		int ip_len, ip_proto;
		char src_ip[STRSIZE];
		char dst_ip[STRSIZE];
		inet_ntop(AF_INET, (void*)&(ip_header->SrcIP), src_ip, 16);
		inet_ntop(AF_INET, (void*)&(ip_header->DstIP), dst_ip, 16);
		ip_proto = ip_header->Protocol;
		ip_len = ip_header->TotalLen;

	//	printf("\n%ld  %ld  ", pkt_header->ts.tv_sec, pkt_header->ts.tv_usec);
	//	printf("%ld  ", pkt_header->len);
	//	printf("%s  %s  ", src_ip, dst_ip);


		int src_port, dst_port, tcp_flags;
		if(ip_proto == 0x06 || ip_proto == 0x11){
			if(ip_proto == 0x06){//TCP analysis
				tcp_num++;
				if(fread(tcp_header, sizeof(TCPHeader_t), 1, fp)!=1){
					printf("%d: Can not read tcp_header\n", pkt_num);
					break;
				}
				src_port = ntohs(tcp_header->SrcPort);
				dst_port = ntohs(tcp_header->DstPort);
				tcp_flags = tcp_header->Flags;
	//			printf("TCP  ");
	//			printf("%d  %d\n", src_port, dst_port);
			}
			if(ip_proto == 0x11){//UDP analysis
				udp_num++;
				if(fread(udp_header, sizeof(UDPHeader_t), 1, fp)!=1){
					printf("%d: Can not read udp_header\n", pkt_num);
					break;
				}
				src_port = ntohs(udp_header->SrcPort);
				dst_port = ntohs(udp_header->DstPort);
	//			printf("UDP  ");
	//			printf("%d  %d\n", src_port, dst_port);
			} 
		}
		else    continue;

		//统计web_port_num_pkt
		if(src_port==80 || dst_port==80 || src_port==8080 || dst_port==8080 || src_port==3128 || dst_port==3128 || src_port==443 || dst_port==443)
			web_port_num_pkt++;


		if(strcmp(myIP, src_ip)==0 || strcmp(myIP, dst_ip)==0){
//			printf("\n%d", flowNum);
			if(flowNum <= max_flowNum){
				int i;
				int flag = 0;//该packet不在FLOWs数组中
				for(i=0; i<flowNum; i++){
					if((strcmp(FLOWs[i]->srcIP, src_ip)==0 && strcmp(FLOWs[i]->dstIP, dst_ip)==0 && FLOWs[i]->srcPORT==src_port && FLOWs[i]->dstPORT==dst_port && FLOWs[i]->protocol==ip_proto) || (strcmp(FLOWs[i]->srcIP, dst_ip)==0 && strcmp(FLOWs[i]->dstIP, src_ip)==0 && FLOWs[i]->srcPORT==dst_port && FLOWs[i]->dstPORT==src_port && FLOWs[i]->protocol==ip_proto)){
						FLOWs[i]->pktNUM++;
						flag = 1;
						if(strcmp(myIP, src_ip)==0){	
							FLOWs[i]->posi_pktNUM++;
							FLOWs[i]->posi_BYTES += pkt_header->len;
						}
						else if(strcmp(myIP, dst_ip)==0){
							FLOWs[i]->nega_pktNUM++;
							FLOWs[i]->nega_BYTES += pkt_header->len;
						}
						if(FLOWs[i]->max_pktSIZE < pkt_header->len)	FLOWs[i]->max_pktSIZE = pkt_header->len;
						FLOWs[i]->sum_pktSIZE += pkt_header->len;
						FLOWs[i]->last_timestamp = (pkt_header->ts.tv_sec * 1.0e+9 + pkt_header->ts.tv_usec*1000)/1.0e+9;
						FLOWs[i]->pre_timestamp = FLOWs[i]->this_timestamp;
						FLOWs[i]->this_timestamp = (pkt_header->ts.tv_sec * 1.0e+9 + pkt_header->ts.tv_usec*1000)/1.0e+9;
						if(FLOWs[i]->max_interval < FLOWs[i]->this_timestamp-FLOWs[i]->pre_timestamp)	FLOWs[i]->max_interval = FLOWs[i]->this_timestamp-FLOWs[i]->pre_timestamp;
						break;
					}
					else continue;
				}
				if(flag == 0){
					strncpy(FLOWs[flowNum]->srcIP, src_ip, 16);
					strncpy(FLOWs[flowNum]->dstIP, dst_ip, 16);
					FLOWs[flowNum]->srcPORT = src_port;
					FLOWs[flowNum]->dstPORT = dst_port;
					FLOWs[flowNum]->protocol = ip_proto;
					FLOWs[flowNum]->pktNUM = 1;
					if(strcmp(myIP, src_ip)==0){
						FLOWs[flowNum]->posi_pktNUM = 1;
						FLOWs[flowNum]->posi_BYTES = pkt_header->len;
					}
					else if(strcmp(myIP, dst_ip)==0){
						FLOWs[flowNum]->nega_pktNUM = 1;
						FLOWs[flowNum]->nega_BYTES = pkt_header->len;
					}
					FLOWs[flowNum]->max_pktSIZE = pkt_header->len;
					FLOWs[flowNum]->sum_pktSIZE = pkt_header->len;
					FLOWs[flowNum]->first_timestamp = (pkt_header->ts.tv_sec * 1.0e+9 + pkt_header->ts.tv_usec*1000)/1.0e+9;
					FLOWs[flowNum]->this_timestamp = FLOWs[flowNum]->first_timestamp;
					FLOWs[flowNum]->pre_timestamp = FLOWs[flowNum]->this_timestamp;
					FLOWs[flowNum]->max_interval = 0;
//					printf("\n%s  %s  %d  %d  %d\n", FLOWs[flowNum]->srcIP, FLOWs[flowNum]->dstIP, FLOWs[flowNum]->srcPORT, FLOWs[flowNum]->dstPORT, FLOWs[flowNum]->protocol);
					flowNum++;
				}
			
			}
		}
		else	continue;
/*
		if(strcmp(myIP, src_ip)==0 || strcmp(myIP, dst_ip)==0){
			if(ipAddrNum <= max_ipAddrNum){
				int i;
				if(strcmp(myIP, src_ip)==0){
					int flag = 0;//dst_ip不在IPs数组中
					for(i=0; i<ipAddrNum; i++){
						if(strcmp(IPs[i], dst_ip)==0){	
							flag = 1;
							break;
						}
						else	continue;
					}
					if(flag == 0){
						strncpy(IPs[ipAddrNum], dst_ip, 16);
						ipAddrNum++;
					}
				}
				if(strcmp(myIP, dst_ip)==0){
					int flag = 0;//src_ip不在IPs数组中
					for(i=0; i<ipAddrNum; i++){
						if(strcmp(IPs[i], src_ip)==0){
							flag = 1;
							break;
						}
						else	continue;
					}
					if(flag == 0){
						strncpy(IPs[ipAddrNum], src_ip, 16);
						ipAddrNum++;
					}
				}		
			}
		}
		else	continue;
*/
/*
		int src_port, dst_port, tcp_flags;
		if(ip_proto == 0x06 || ip_proto == 0x11){
			if(ip_proto == 0x06){//TCP analysis
				if(fread(tcp_header, sizeof(TCPHeader_t), 1, fp)!=1){
			    	printf("%d: Can not read tcp_header\n", pkt_num);
					break;
				}
				src_port = ntohs(tcp_header->SrcPort);
				dst_port = ntohs(tcp_header->DstPort);
				tcp_flags = tcp_header->Flags;
				printf("TCP  ");
				printf("%d  %d\n", src_port, dst_port);

			}
			if(ip_proto == 0x11){//UDP analysis
				if(fread(udp_header, sizeof(UDPHeader_t), 1, fp)!=1){
					printf("%d: Can not read udp_header\n", pkt_num);
					break;
				}
				src_port = ntohs(udp_header->SrcPort);
				dst_port = ntohs(udp_header->DstPort);
				printf("UDP  ");
				printf("%d  %d\n", src_port, dst_port);
			}

		}
		else	continue;
*/
	}

/*
	for(i=0; i<flowNum; i++){
		printf("\n%s  %s  %d  %d  %lf  %lf  %lf  %lf  %lf  %lf  %lf  %lf  %lf  %lf  %lf\n", FLOWs[i]->srcIP, FLOWs[i]->dstIP, FLOWs[i]->srcPORT, FLOWs[i]->dstPORT, (FLOWs[i]->last_timestamp-FLOWs[i]->first_timestamp), FLOWs[i]->pktNUM, FLOWs[i]->nega_pktNUM, FLOWs[i]->posi_pktNUM, FLOWs[i]->nega_BYTES, FLOWs[i]->posi_BYTES, FLOWs[i]->max_pktSIZE, FLOWs[i]->sum_pktSIZE/FLOWs[i]->pktNUM, FLOWs[i]->max_interval, (FLOWs[i]->last_timestamp-FLOWs[i]->first_timestamp)/FLOWs[i]->pktNUM, FLOWs[i]->nega_BYTES/FLOWs[i]->posi_BYTES);
	}
	printf("%d\n", flowNum);
*/
/*
	for(i=0; i<flowNum; i++){
		printf("\n%lf %lf %lf %lf %lf %lf %lf %lf %lf %lf %lf %lf\n", FLOWs[i]->pktNUM, FLOWs[i]->nega_pktNUM, FLOWs[i]->posi_pktNUM, FLOWs[i]->nega_BYTES, FLOWs[i]->posi_BYTES, FLOWs[i]->max_pktSIZE, FLOWs[i]->sum_pktSIZE, FLOWs[i]->first_timestamp, FLOWs[i]->last_timestamp, FLOWs[i]->this_timestamp, FLOWs[i]->pre_timestamp, FLOWs[i]->max_interval);
	}
*/
	
/*----------------------------------------------------------------------------------------------------------------------------------*/
/*-----------------------------------------------  PCA analysis 的准备部分  -------------------------------------------------------------*/
	int p,q;
	int exact_flowNum = 0;//过滤掉pktNUM过小的流，所剩流条数
	for(p=0; p<flowNum; p++){
		if(FLOWs[p]->pktNUM>=3 && FLOWs[p]->posi_pktNUM!=0 && FLOWs[p]->posi_BYTES!=0 && FLOWs[p]->nega_pktNUM!=0 && FLOWs[p]->nega_BYTES!=0)	{
			exact_flowNum++;
			if(FLOWs[p]->srcPORT==80 || FLOWs[p]->dstPORT==80 || FLOWs[p]->srcPORT==8080 || FLOWs[p]->dstPORT==8080 || FLOWs[p]->srcPORT==3128 || FLOWs[p]->dstPORT==3128 || FLOWs[p]->srcPORT==443 || FLOWs[p]->dstPORT==443)	web_port_num_flow++;
		}
	}
//	printf("\n%d  %d\n", web_port_num_flow, exact_flowNum);	
//	printf("\n%d  %d\n", web_port_num_pkt, pkt_num-1);
/*-------------------------通过端口号判断是否为web应用---------------------------*/

	if((double)web_port_num_flow/exact_flowNum>0.8 && (double)web_port_num_pkt/(pkt_num-1)>0.8){//web应用
//		printf("\nWEB\n");
//		return 0;
	}
	else{//非web应用
//		printf("\nNOT WEB\n");
	}

//	printf("\n%d %d\n", web_port_num_flow, exact_flowNum);
//printf("\n%d\n", exact_flowNum);
//printf("\n%d\n", flowNum);

/*-------------------------通过统计特征判断非web应用-----------------------------*/	

	double M[exact_flowNum][11];//M[i][0]-M[i][10]为流i+1的11个属性
	int isTCP[exact_flowNum];//1:tcp; 0:udp
	int n=0;
	for(p=0; p<flowNum; p++){
		//printf("\n%d\n", p);
		if(FLOWs[p]->pktNUM>=3 && FLOWs[p]->posi_pktNUM!=0 && FLOWs[p]->posi_BYTES!=0 && FLOWs[p]->nega_pktNUM!=0 && FLOWs[p]->nega_BYTES!=0){
			if(FLOWs[p]->protocol==0x06){
				isTCP[n]=1;
			}
			if(FLOWs[p]->protocol==0x11){
				isTCP[n]=0;
			}

			if(FLOWs[p]->last_timestamp-FLOWs[p]->first_timestamp > 10)	M[n][0] = 10;
			else	M[n][0] = FLOWs[p]->last_timestamp-FLOWs[p]->first_timestamp;
			M[n][1] = FLOWs[p]->pktNUM;
			M[n][2] = FLOWs[p]->nega_pktNUM;
			M[n][3] = FLOWs[p]->posi_pktNUM;
			M[n][4] = FLOWs[p]->nega_BYTES;
			M[n][5] = FLOWs[p]->posi_BYTES;
			M[n][6] = FLOWs[p]->max_pktSIZE;
			M[n][7] = FLOWs[p]->sum_pktSIZE/FLOWs[p]->pktNUM;
			M[n][8] = FLOWs[p]->max_interval;
			M[n][9] = (FLOWs[p]->last_timestamp-FLOWs[p]->first_timestamp)/FLOWs[p]->pktNUM;
			M[n][10] = FLOWs[p]->nega_BYTES/FLOWs[p]->posi_BYTES;
			n++;
		}
	}
/*
	for(p=0; p<exact_flowNum; p++){
		for(q=0; q<11; q++){
			printf("%lf ", M[p][q]);
		}
		printf("\n");
	}
*/
//	printf("\n-----------------------------------------------------------------------------\n");

/*
	for(p=0; p<exact_flowNum; p++){
		printf("%d ", isTCP[p]);
	}
*/

//	printf("\n%d %d", tcp_num, udp_num);


	FILE* ut = fopen("./Test/test.txt", "w");
	for(p=0; p<exact_flowNum; p++){
		for(q=0; q<11; q++){
			fprintf(ut, "%lf ", M[p][q]);
		}
	//	fprintf(ut, "3 ");
		fprintf(ut, "\n");
	}

/*
//注释开始
	double Mt[11][exact_flowNum];//转置矩阵Mt,Mt[i]即为属性i+1
	for(p=0; p<exact_flowNum; p++){
		for(q=0; q<11; q++){
			Mt[q][p] = M[p][q];
		}
	}

	double u[11];//u[i]为属性i+1的均值
	for(p=0; p<11; p++){
		double sum = 0;
		for(q=0; q<exact_flowNum; q++){
			sum = sum+Mt[p][q];
		}
		u[p] = sum/exact_flowNum;
	//  printf("%lf ", u[p]);
	}

	double e2[11];//e2[i]为属性i+1的方差
	for(p=0; p<11; p++){
		double sum2 = 0;
		for(q=0; q<exact_flowNum; q++){
			sum2 = sum2 + (Mt[p][q]-u[p])*(Mt[p][q]-u[p]);
		}
		e2[p] = sum2/exact_flowNum;
    	printf("%lf ", e2[p]);
	}
	
	 //标准化
	 for(p=0; p<11; p++){
	 	for(q=0; q<exact_flowNum; q++){
			Mt[p][q] = Mt[p][q] - u[p];
	 	}
	 }

	 //更新原矩阵M
	 for(p=0; p<11; p++){
	 	for(q=0; q<exact_flowNum; q++){
	 		M[q][p] = Mt[p][q];
	 	}
	 }
	
	 //将标准化后的矩阵M写入文件M_stan.txt
	 FILE* M_s = fopen("./M_stan.txt", "w");
	for(p=0; p<exact_flowNum; p++){
		for(q=0; q<11; q++){
			fprintf(M_s, "%lf ", M[p][q]);
		}
		fprintf(M_s, "\n");
	}


	//求M的协方差矩阵
	double M_cov[11][11];
	for(p=0; p<11; p++){
		for(q=0; q<11; q++){
			double sum = 0;
			int t;
			for(t=0; t<exact_flowNum; t++){
				sum += Mt[p][t] * Mt[q][t];
			}
			M_cov[p][q] = sum/(exact_flowNum-1);
		}
	}

	//将M的协方差矩阵写入文件
	FILE* M_c = fopen("./M_cov.txt", "w");
	for(p=0; p<11; p++){
		for(q=0; q<11; q++){
			fprintf(M_c, "%lf ", M_cov[p][q]);
		}
		fprintf(M_c, "\n");
	}
*/
//注释结束

	/*
	for(p=0; p<11; p++){
		for(q=0; q<11; q++){
			printf("%lf  ", M_cov[p][q]);
		}
		printf("\n");
	}
	*/














	return 0;
}
