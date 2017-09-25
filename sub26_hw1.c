/****************************************************************************************
*                                                                                       *
*   Subject : Subject 26                                                                *
*   Prof : gilgil                                                                       *
*   Student Name : Lim Kyung Dai                                                        * 
*   Student ID : 2015410209                                                             *
*                                                                                       *
*   - HW1 : pcap_programming                                                            *
*   - conference                                                                        *
*   https://www.joinc.co.kr/w/Site/Network_Programing/AdvancedComm/pcap_intro#AEN106    *
*   http://www.tcpdump.org/pcap.html                                                    *
*                                                                                       *
****************************************************************************************/

//gilgil_example

#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}


int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }
//----------------------------------------------------------------------------------//

  /* Ethernet header */
  struct sniff_ethernet {
        
  #define ETHER_ADDR_LEN 6
        u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
        u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
        u_short ether_type; /* IP? ARP? RARP? etc */
        };

  int i;
  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
//----------------------------------------------------------------------------------//

  /* IP header */
  struct sniff_ip {
    u_char ip_vhl;    /* version << 4 | header length >> 2 */
    u_char ip_tos;    /* type of service */
    u_short ip_len;   /* total length */
    u_short ip_id;    /* identification */
    u_short ip_off;   /* fragment offset field */
  #define IP_RF 0x8000    /* reserved fragment flag */
  #define IP_DF 0x4000    /* dont fragment flag */
  #define IP_MF 0x2000    /* more fragments flag */
  #define IP_OFFMASK 0x1fff /* mask for fragmenting bits */
    u_char ip_ttl;    /* time to live */
    u_char ip_p;    /* protocol */
    u_short ip_sum;   /* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
  };
  #define IP_HL(ip)   (((ip)->ip_vhl) & 0x0f)
  #define IP_V(ip)    (((ip)->ip_vhl) >> 4)
//----------------------------------------------------------------------------------//

  /* TCP header */
  typedef u_int tcp_seq;

  struct sniff_tcp {
    u_short th_sport; /* source port */
    u_short th_dport; /* destination port */
    tcp_seq th_seq;   /* sequence number */
    tcp_seq th_ack;   /* acknowledgement number */
    u_char th_offx2;  /* data offset, rsvd */
  #define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
  #define TH_FIN 0x01
  #define TH_SYN 0x02
  #define TH_RST 0x04
  #define TH_PUSH 0x08
  #define TH_ACK 0x10
  #define TH_URG 0x20
  #define TH_ECE 0x40
  #define TH_CWR 0x80
  #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;   /* window */
    u_short th_sum;   /* checksum */
    u_short th_urp;   /* urgent pointer */
};
//----------------------------------------------------------------------------------//

  struct pcap_pkthdr* header;  //gilgil's example
  const u_char* packet;        //gilgil's example
  struct sniff_ethernet* eth;
  struct sniff_ip* ip;
  struct sniff_tcp* tcp;
  u_int size_ip; 
  u_int size_tcp;
  u_char* payload;
  #define SIZE_ETHERNET 14
//----------------------------------------------------------------------------------//  
  
  while (1) {
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    /*
     -1 if an error occurred 
     -2 if EOF was reached reading from an offline capture
    */
    eth = (struct sniff_ethernet*)packet;
    printf("Start!\n");
    printf("*************************************************************************\n");
   // printf("%u bytes captured\n", header->caplen);
    printf("Packet Size : %d\n",header->len);
    //printf("Ether Type : %p\n", ntohs(eth->ether_type));
    printf("[*] Ethernet Header's Src / Dest Mac\n");
    printf("Src Mac : ");
        for(i=0;i<6;i++)
        {
                printf("%02x",eth->ether_shost[i]);
                if(i != 5) printf(":");
        }
        printf("\n");
    printf("Dest Mac : ");
    for(i=0;i<6;i++)
    {
            printf("%02x",eth->ether_dhost[i]);
            if(i!=5) printf(":");
    }
    printf("\n\n");
    if(eth->ether_type == 8) //Iam IPv4
  {
      ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
      printf("[+] IP Header's Src / Dest Mac\n");
      printf("Src Ip : %s\n",inet_ntoa(ip->ip_src));
      printf("Dest Ip : %s\n",inet_ntoa(ip->ip_dst));
      printf("\n");
      size_ip = IP_HL(ip)*4;
      if(ip->ip_p == 6) //Iam TCP
      {  
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4;
        printf("[-] TCP Header's Src / Dest Port\n");
        printf("Src Port : %d\n",ntohs(tcp->th_sport));
        printf("Dest Port : %d\n",ntohs(tcp->th_dport));
        printf("\n");
        if(ip->ip_len > (size_ip + size_tcp)) //ip_len : ip datagram's size
        { 
           // printf("test! size_ip : %d\n",size_ip);
           // printf("test! size_tcp : %d\n",size_tcp);
           payload = (u_char*)(packet + SIZE_ETHERNET + size_ip + size_tcp);
           printf("[#] Payload's hexa decimal Value : ");
            for(i=0;i<15;i++)
            {
              printf("\\x%02x",payload[i]);
            }
            printf("\n\n");
        }
      }
    }
    printf("*************************************************************************\n");
    printf("Finish!\n\n");
  }

  pcap_close(handle);
  return 0;
}
