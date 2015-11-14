#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

#define FlowNum 543//规则集合中流的条数
#define AttrNum 11
#define ClassNum 3//1:p2p; 2:video; 3:game; web类通过端口判断 
#define max_testFlowNum 1000//待归类流的条数不能超过1000
int C[FlowNum];//C[i]为第i+1条flow的类
double PC[ClassNum];//PC[i]为类i+1的频率

double C1 = 0;
double C2 = 0;
double C3 = 0;

int main(){
	/*-----------------读取rules.txt--------------------*/
	char tar[2000];
	double M[FlowNum][AttrNum+1];
	char *ch;
	FILE* fp = fopen("./Rules/rules.txt", "r");
	int i=0;
	while(fgets(tar, 2000, fp)!=NULL){
		int j=0;
		ch = strtok(tar, " ");
		while(ch!=NULL){
			if(strcmp(ch, "\n")!=0){
				M[i][j] = atof(ch);
//				printf("%lf ", M[i][j]);
				j++;
			}
			ch = strtok(NULL, " ");
		}
		i++;
//		printf("\n");
	}
	fclose(fp);

	double u[AttrNum];
	int p,q;
	for(p=0; p<11; p++){
		double s = 0;
		for(q=0; q<FlowNum; q++){
			s += M[q][p];
		}
		u[p] = s/FlowNum;
//		printf("\n%lf \n", u[p]);
	}
	/*------------计算PC[i]--------------*/
	for(p=0; p<FlowNum; p++){
		C[p] = M[p][AttrNum];
	}
	for(p=0; p<ClassNum; p++){
		PC[p] = 0;
	}
	for(p=0; p<ClassNum; p++){
		for(q=0; q<FlowNum; q++){
			if(C[q] == p+1)	PC[p]++;
		}
	}
	for(p=0; p<ClassNum; p++){
		PC[p] = PC[p]/FlowNum;
	}
//	printf("\n%lf %lf %lf\n", PC[0], PC[1], PC[2]);


	/*-----------------读取test_new.txt---------------*/
	double this_flow[max_testFlowNum][AttrNum];//待归类flow
	char tar1[2000];
	char* ch1;
	FILE* fp1 = fopen("./Test/test.txt", "r");
	int test_flow_num = 0;
	while(fgets(tar1, 2000, fp1)!=NULL){
		int j=0;
		ch1 = strtok(tar1, " ");
		while(ch1!=NULL){
			if(strcmp(ch1, "\n")!=0){
				this_flow[test_flow_num][j] = atof(ch1);
//				printf("%lf ", this_flow[test_flow_num][j]);
				j++;
			}
			ch1 = strtok(NULL, " ");
		}
		test_flow_num++;
//		printf("\n");
	}
	fclose(fp1);


	double this_flow_PC[ClassNum];//this_flow_PC[i]为待归类flow属于类i+1的概率

	/*---------Bayes Classification-------------*/
	int test_flow_counter = 0;
	printf("test flow number\tclass\n");
	while(test_flow_counter<test_flow_num){
		printf("test flow %d:\t", test_flow_counter+1);
		int t = 0;
		while(t<ClassNum){
			int count_attr1 = 0;
			int count_attr2 = 0;
			int count_attr3 = 0;
			int count_attr4 = 0;
			int count_attr5 = 0;
			int count_attr6 = 0;
			int count_attr7 = 0;
			int count_attr8 = 0;
			int count_attr9 = 0;
			int count_attr10 = 0;
			int count_attr11 = 0;
			for(p=0; p<FlowNum; p++){
				if(M[p][AttrNum] == t+1){
					if(abs(this_flow[test_flow_counter][0]-M[p][0]) < u[0]/10){//匹配规则
						count_attr1++;
					}
					if(abs(this_flow[test_flow_counter][1]-M[p][1]) < u[1]/10){//匹配规则
						count_attr2++;
					}
					if(abs(this_flow[test_flow_counter][2]-M[p][2]) < u[2]/10)	count_attr3++;
					if(abs(this_flow[test_flow_counter][3]-M[p][3]) < u[3]/10)  count_attr4++;
					if(abs(this_flow[test_flow_counter][4]-M[p][4]) < u[4]/10)  count_attr5++;
					if(abs(this_flow[test_flow_counter][5]-M[p][5]) < u[5]/10)  count_attr6++;
					if(abs(this_flow[test_flow_counter][6]-M[p][6]) < u[6]/10)  count_attr7++;
					if(abs(this_flow[test_flow_counter][7]-M[p][7]) < u[7]/10)  count_attr8++;
					if(abs(this_flow[test_flow_counter][8]-M[p][8]) < u[8]/10)  count_attr9++;
					if(abs(this_flow[test_flow_counter][9]-M[p][9]) < u[9]/10)  count_attr10++;
					if(abs(this_flow[test_flow_counter][10]-M[p][10]) < u[10]/10)  count_attr11++;
				}
			}
			if(count_attr1 == 0)	count_attr1 = 1;
			if(count_attr2 == 0)    count_attr2 = 1;
			if(count_attr3 == 0)    count_attr3 = 1;
			if(count_attr4 == 0)    count_attr4 = 1;
			if(count_attr5 == 0)    count_attr5 = 1;
			if(count_attr6 == 0)    count_attr6 = 1;
			if(count_attr7 == 0)    count_attr7 = 1;
			if(count_attr8 == 0)    count_attr8 = 1;
			if(count_attr9 == 0)    count_attr9 = 1;
			if(count_attr10 == 0)    count_attr10 = 1;
			if(count_attr11 == 0)    count_attr11 = 1;
			this_flow_PC[t] = PC[t] * ((double)count_attr1/(PC[t]*FlowNum)) * ((double)count_attr2/(PC[t]*FlowNum)) * ((double)count_attr3/(PC[t]*FlowNum)) * ((double)count_attr4/(PC[t]*FlowNum)) * ((double)count_attr5/(PC[t]*FlowNum)) * ((double)count_attr6/(PC[t]*FlowNum)) * ((double)count_attr7/(PC[t]*FlowNum)) * ((double)count_attr8/(PC[t]*FlowNum)) * ((double)count_attr9/(PC[t]*FlowNum)) * ((double)count_attr10/(PC[t]*FlowNum)) * ((double)count_attr11/(PC[t]*FlowNum));

//			printf("%d, %d\n", count_attr1, count_attr2);
//			printf("%lf\n", this_flow_PC[t]);
			t++;

		}
		int max_index = 0;
		for(p=1; p<ClassNum; p++){
			if(this_flow_PC[max_index]<this_flow_PC[p])
				max_index = p;
			}
		printf("%d\n", max_index+1);
		if(max_index == 0)	C1++;
		if(max_index == 1)	C2++;
		if(max_index == 2)	C3++;
		
		test_flow_counter++;
	}

	printf("\n--------------------统计---------------------\n");
	printf("P2P        Video       Game\n");
	printf("%lf  %lf  %lf\n", C1, C2, C3);
	printf("%lf  %lf  %lf\n", C1/test_flow_num, C2/test_flow_num, C3/test_flow_num);







	return 0;
}
