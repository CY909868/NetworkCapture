#pragma  once 

//define some protocal
#define IP 0x0800
#define ARP 0x0806
#define RARP 0x8035

/*define some ip type*/
#define ICMP 1
#define TCP 6
#define UDP 17

/*gotten packet*/
typedef struct packet
{
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
}packet;

/* 4 bytes IP address */ 
typedef struct ip_address 
{ 
	u_char byte1; 
	u_char byte2; 
	u_char byte3; 
	u_char byte4; 
}ip_address; 

/*ethernet header*/
typedef struct ethernet_header
{
	u_char dstmac[6]; //目标mac地址
	u_char srcmac[6]; //源mac地址
	u_short eth_type; //以太网类型
}ethernet_header;

/* IPv4 header */ 
typedef struct ip_header 
{
	u_char ihl:4; /* Internet header length (4 bits)*/ 
	u_char ver:4;/*Version (4 bits)*/
	u_char tos; /* Type of service */ 
	u_short tlen; /* Total length */ 
	u_short identification; /* Identification */  
	u_short fo:13; /* Fragment offset (13 bits)*/ 
	u_short flags:3;/*Flags (3 bits) */
	u_char ttl; /* Time to live */ 
	u_char proto; /* Protocol */ 
	u_short crc; /* Header checksum */ 
	ip_address saddr;/* Source address */ 
	ip_address daddr;/* Destination address */ 
	//u_int op_pad; /* Option + Padding */ 
}ip_header;
struct ip_T_header  //小端模式__LITTLE_ENDIAN  
{   
	unsigned   char     ihl:4;              //ip   header   length      
	unsigned   char     version:4;          //version     
	u_char              tos;                //type   of   service     
	u_short             tot_len;            //total   length     
	u_short             id;                 //identification     
	u_short             frag_off;           //fragment   offset     
	u_char              ttl;                //time   to   live     
	u_char              protocol;           //protocol   type     
	u_short             check;              //check   sum     
	u_int               saddr;              //source   address     
	u_int               daddr;              //destination   address     
};  
struct IpHead
{
	unsigned char  ucVersionAndHeadLength;        // Version (4 bits) + Internet header length (4 bits)
	unsigned char  ucTos;            // Type of service 
	unsigned short usTotalLength;           // Total length 
	unsigned short usIdentification; // Identification
	unsigned short usFlagsAndFragmentOffset;       // Flags (3 bits) + Fragment offset (13 bits)
	unsigned char  ucTtl;            // Time to live
	unsigned char  ucProtocol;          // Protocol
	unsigned short usCrc;            // Header checksum
	unsigned long  dwSourceAddr;      // Source address
	unsigned long  dwDestAddr;      // Destination address
};

/* UDP header */ 
typedef struct udp_header 
{ 
	u_short sport; /* Source port */ 
	u_short dport; /* Destination port */ 
	u_short len; /* Datagram length */ 
	u_short crc; /* Checksum */ 
}udp_header; 

typedef struct tcp_header  //20 bytes : default
{
	u_short sport;      //Source port
	u_short dport;      //Destination port
	u_long seqno;       //Sequence no
	u_long ackno;       //Ack no
	u_char reserved_1:4; //保留6位中的4位首部长度
	u_char offset:4;     //tcp头部长度
	u_char flag:6;       //6位标志
	u_char reserved_2:2; //保留6位中的2位
	//FIN - 0x01
	//SYN - 0x02
	//RST - 0x04 
	//PUSH- 0x08
	//ACK- 0x10
	//URG- 0x20
	//ACE- 0x40
	//CWR- 0x80

	u_short win;
	u_short checksum;
	u_short uptr;
}tcp_header;

struct IpPacket
{
	ethernet_header theEthHead;
	IpHead theIpHead;
};

//ICMP Header
typedef struct icmp_header
{
	u_char type;	  //type
	u_char code;      //code
	u_short chk_sum;  //checksum 16bit
	u_short id; 
	u_short seq; 
	u_long timestamp; 
}icmp_header;
