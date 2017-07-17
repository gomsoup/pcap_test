#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pcap.h>

#include <errno.h>

#include <sys/time.h>
#include <sys/socket.h>

#include <net/ethernet.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include <arpa/inet.h>

#define PROMISCUOUS 1
#define NONPRIMISCUOUS 0

using namespace std;


struct ip *iph; // ip header structure
struct tcphdr *tcph; //tcp header structure

class pcapClass{
public:
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[100] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;

	void defineTheDevice(){
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL){
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			exit(2);
	
		}
	}
	void propertiesForDevice(){
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
			exit(2);
		}
	}

	void openSessionPromiscuous(){
		handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
		if(handle == NULL){
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			exit(2);
		}
	}

	void filterApplyAndCompile(){
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1){
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
			exit(2);
		}
	}

	void pcapPrintNet(){
		char *netp;
		struct in_addr addr;

		addr.s_addr = net;
		netp = inet_ntoa(addr);

		cout << "NET : " << netp << endl;
	}
	
	void pcapPrintMask(){
		char *maskp;
		struct in_addr addr;

		addr.s_addr = mask;
		maskp = inet_ntoa(addr);

		cout << "MASK : " << maskp << endl;
	}

	void pcapGetPacket(){
		packet = pcap_next(handle, &header);
		cout << "Jacked a packet with legnth of [" << header.len << "]" << endl;
	}
	
	pcapClass(){
		defineTheDevice();
		propertiesForDevice();
		openSessionPromiscuous();
		filterApplyAndCompile();
	}
	~pcapClass(){
		pcap_close(handle);
	}
};


int main(){
	pcapClass p;

	p.pcapGetPacket();
	p.pcapPrintNet();
	p.pcapPrintMask();
	return 0;
}
