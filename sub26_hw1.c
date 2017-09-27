/****************************************************************************************
*                                                                                       *
*   Subject : Subject 26                                                                *
*   Prof : gilgil                                                                       *
*   Student Name : Lim Kyung Dai                                                        * 
*   Student ID : 2015410209                                                             *
*                                                                                       *
*   - HW1 : pcap_programming                                                            *
*   - reference                                                                         *
*   https://www.joinc.co.kr/w/Site/Network_Programing/AdvancedComm/pcap_intro#AEN106    *
*   http://www.tcpdump.org/pcap.html                                                    *
*                                                                                       *
****************************************************************************************/

//gilgil_example

#include <stdio.h>
#include "my_pcap.h"

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}


int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  int i;
  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
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
    printf("Packet Size : %d\n",header->caplen);
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
      size_ip = IP_HL(ip)*4; //ip header size (maximum : 60byte)
      if(ip->ip_p == 6) //Iam TCP
      {  
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4; //tcp header size (maximum : 60byte)
        printf("[-] TCP Header's Src / Dest Port\n");
        printf("Src Port : %d\n",ntohs(tcp->th_sport));
        printf("Dest Port : %d\n",ntohs(tcp->th_dport));
        printf("\n");
        if(ip->ip_len > (size_ip + size_tcp)) //ip_len : ip datagram's size
        { 
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
