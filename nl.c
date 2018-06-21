#include <pcap.h>
#include <stdlib.h>
#include <string.h>

#define MAXBYTES2CAP 2048

void processPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, u_char *packet)
{
	int i=0, *counter=(int*)arg;

	printf("Packet Count:%d\n",++(*counter));
	printf("Received Packet Size: %d\n",pkthdr->len);

	printf("Palyload:\n");

	for (i=0; i<pkthdr->len; i++)
	{
		if (isprint(packet[i]))
		{
			printf("%c ",packet[i]);	
		}
		else
		{
			printf(". ");	
		}

		if (( i%16==0 && i!=0) || i==pkthdr->len-1)
		{
			printf("\n");	
		}
	}
	return ;
}

int main()
{
	int i=0, count=0;
	pcap_t *desc = NULL;
	char errbuf[PCAP_ERRBUF_SIZE], *device = NULL;
	memset(errbuf, 0, PCAP_ERRBUF_SIZE);

	device = pcap_lookupdev(errbuf);

	printf("Opening device %s\n",device);
	desc = pcap_open_live(device, MAXBYTES2CAP, 0, 512, errbuf);

	pcap_loop(desc, -1, (pcap_handler)&processPacket, (u_char*)&count);
	return 0;
}
