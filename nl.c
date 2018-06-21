#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>

#define MAXBYTES2CAP 2048

void processPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, u_char *packet)
{
	int i=0, *counter=(int*)arg;
	
	struct ip *iphdr = NULL;
	struct tcphdr  *tcphdr = NULL;

	printf("Packet Count:%d\n",++(*counter));
	printf("Received Packet Size: %d\n",pkthdr->len);


	iphdr   = (struct ip *)(packet + 14);


	tcphdr  = (struct tcphdr *)(packet + 14  + (iphdr->ip_hl<<2));
	fprintf(stdout, "AcSeq[%u] Flags[%x] Seq[%u] SP[%u] DP[%u] \n",ntohl(tcphdr->th_ack),tcphdr->th_flags,ntohl(tcphdr->th_seq),ntohs(tcphdr->th_sport),ntohs(tcphdr->th_dport));
	fprintf(stdout, "DST IP:%s\n",inet_ntoa(iphdr->ip_dst));
	fprintf(stdout, "SRC IP:%s\n",inet_ntoa(iphdr->ip_src));
	return ;
}

int main()
{
	int i=0, count=0;
	pcap_t *handle = NULL;
	struct bpf_program fp;
	char errbuf[PCAP_ERRBUF_SIZE], *device = NULL;
	char filter_exp[] = "tcp[tcpflags]&tcp-syn!=0";
	bpf_u_int32 mask;
	bpf_u_int32 net;

	memset(errbuf, 0, PCAP_ERRBUF_SIZE);

	device = pcap_lookupdev(errbuf);
	if (device == NULL){
		fprintf(stderr, "Cant't find lookup dev:%s\n",errbuf);	
		return 2;
	}
	fprintf(stdout,"Opening device %s\n",device);

	if (pcap_lookupnet(device, &net, &mask, errbuf) == -1)
	{
		fprintf(stderr, "Cant get netmask for device %s:%s\n",device,errbuf);
		return 2;
	}
	fprintf(stdout,"ip:%x mast:%x\n",net,mask);

	handle = pcap_open_live(device, MAXBYTES2CAP, 0, 512, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s:%s\n",device,errbuf);	
		return 2;
	}

	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
	{
		fprintf(stderr, "Couldn't parse filter %s:%s\n",filter_exp, pcap_geterr(handle));
		return 2;
	}

	if (pcap_setfilter(handle, &fp) == -1)
	{
		fprintf(stderr, "Couldnt install filter %s:%s\n",filter_exp,pcap_geterr(handle));	
		return 2;
	}

	pcap_loop(handle, -1, (pcap_handler)&processPacket, (u_char*)&count);
	return 0;
}
