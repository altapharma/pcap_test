#include <stdio.h>
#include <arpa/inet.h>
#include <stdint.h>

uint16_t reverse16(uint16_t packet)
{
	uint16_t low = packet & 0x00ff;
	uint16_t high = packet & 0xff00;
//	printf("low : %x\n",low);
//	printf("high : %x\n",high);
	low = low << 8;
	high = high >> 8;
//	printf("low : %x\n",low);
//      printf("high : %x\n",high);
	return low | high;
}

uint32_t reverse32(uint32_t packet)
{
	uint32_t byte1 = packet & 0xff000000;
	uint32_t byte2 = packet & 0x00ff0000;
	uint32_t byte3 = packet & 0x0000ff00;
	uint32_t byte4 = packet & 0x000000ff;
	byte1 = byte1 >> 24;
	byte2 = byte2 >> 8;
	byte3 = byte3 << 8;
	byte4 = byte4 << 24;
	return byte1 | byte2 | byte3 | byte4;
}

int main()
{
	{
		uint8_t buf[]={0x12,0x34};
		uint16_t* origin = (uint16_t*)buf;
		uint16_t type = *origin;
		printf("\n--16bit change example--\n");
		printf("origin number is 0x%x\n",type);
		printf("reverse number is 0x%x\n",reverse16(type));
		printf("ntohs origin is 0x%x\n",ntohs(type));
		printf("htons origin is 0x%x\n",htons(type));
	}
		
	{
		uint8_t buf2[]={0x12,0x34,0x56,0x78};
		uint32_t* origin2 = (uint32_t*)buf2;
		uint32_t type2 = *origin2;
		printf("\n--32bit change examle--\n");
		printf("origin number is 0x%x\n",type2);
		printf("reverse number is 0x%x\n",reverse32(type2));
		printf("ntohs origin is 0x%x\n",ntohl(type2));
		printf("htons origin is 0x%x\n",htonl(type2));
		return 0;
	}
}
