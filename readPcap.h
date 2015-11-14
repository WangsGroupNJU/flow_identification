/*readPcap.h*/
/*format of pcap file*/

typedef int bpf_int32;
typedef unsigned int bpf_u_int32;
typedef unsigned short u_short;
typedef unsigned int u_int32;
typedef unsigned short u_int16;
typedef unsigned char u_int8;

//pcap file header structure
struct pcap_file_header{
	bpf_u_int32 magic;
	u_short version_major;
	u_short version_minor;
	bpf_int32 thiszone;
	bpf_u_int32 sigfigs;
	bpf_u_int32 snaplen;/*max length saved portion of each pkt*/
	bpf_u_int32 linktype;/*data link type*/
};

//timestamp structure
struct time_val{
	int tv_sec;
	int tv_usec;
};

//pcap header structure
struct pcap_pkthdr{
	struct time_val ts;
	bpf_u_int32 caplen;/*length of portion present*/
	bpf_u_int32 len;/*length of this packet(off wire)*/
};

//Ethernet Frame Header
typedef struct FramHeader_t{
	u_int8 DstMAC[6];
	u_int8 SrcMAC[6];
	u_short FrameType;
}FramHeader_t;

//IP Header
typedef struct IPHeader_t{
	u_int8 Ver_HLen;
	u_int8 TOS;
	u_int16 TotalLen;
	u_int16 ID;
	u_int16 Flag_Segment;
	u_int8 TTL;
	u_int8 Protocol;
	u_int16 Checksum;
	u_int32 SrcIP;
	u_int32 DstIP;
}IPHeader_t;

//TCP Header
typedef struct TCPHeader_t{
	u_int16 SrcPort;
	u_int16 DstPort;
	u_int32 SeqNo;
	u_int32 AckNo;
	u_int8 HeaderLen;
	u_int8 Flags;
	u_int16 Window;
	u_int16 Checksum;
	u_int16 UrgentPointer;
}TCPHeader_t;

//UDP Header
typedef struct UDPHeader_t{
	u_int16 SrcPort;
	u_int16 DstPort;
	u_int16 HeaderLen;
	u_int16 Checksum;
}UDPHeader_t;










