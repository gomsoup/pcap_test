#include <iostream>
#include <string>

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

	void pcapGetEtherSpec();
	void pcapGetIPSpec();
	void pcapGetTCPSpec();


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


class etherClass: public pcapClass{
public:
	struct ether_header *ep;
	unsigned short ether_type;
	
	etherClass(){
		ep = (struct ether_header *) packet;
		packet += sizeof(struct ether_header);
		ether_type = ntohs(ep->ether_type);
	}


};


class ipClass: public etherClass{
public:
	bool is_ip;

	int ip_v;
	int ip_hl;
	int ip_id;
	int ip_ttl;
	char *ip_src;
	char *ip_dst;
	
	struct ip *iph;

	ipClass(){
		if (ether_type == ETHERTYPE_IP){
			is_ip = true;
			iph = (struct ip*)packet;

			ip_v = iph->ip_v;
			ip_hl = iph->ip_hl;
			ip_id = ntohs(iph->ip_id);
			ip_ttl = iph->ip_ttl;
			ip_src = inet_ntoa(iph->ip_src);
			ip_dst = inet_ntoa(iph->ip_dst);
		}
		else{
			is_ip = false;
			cout << "This is not IP Packet" << endl;
		}
	}
	
	void printIPSpec(){
		cout << "IP Packet" << endl;
		cout << "Version     : " << ip_v << endl;
		cout << "Header Len  : " << ip_hl << endl;
		cout << "ID          : " << ip_id << endl;
		cout << "TTL         : " << ip_ttl << endl;
		cout << "Src Address : " << ip_src << endl;
		cout << "Dst Address : " << ip_dst << endl;
	}
};

class tcpClass: public ipClass{
public:
	struct tcphdr *tcph;
	int tcp_src;
	int tcp_dst;
	bool is_tcp;

	tcpClass(){
		if (iph->ip_p == IPPROTO_TCP){
			is_tcp = true;
			tcph = (struct tcphdr *)(packet + ip_hl * 4);
			tcp_src = ntohs(tcph->source);
			tcp_dst = ntohs(tcph->dest);
		}
		else {
			is_tcp = false;
			cout << "This is not TCP Packet" << endl;
		}
	}
	
	void printTCPSpec(){
		cout << "Src Port    : " << tcp_src << endl;
		cout << "Dst Port    : " << tcp_dst << endl;
	}
};


void pcapClass::pcapGetEtherSpec(){
	etherClass eth;
}

void pcapClass::pcapGetIPSpec(){
	ipClass ip;
	
	if(ip.is_ip) ip.printIPSpec();
}
void pcapClass::pcapGetTCPSpec(){
	tcpClass tcp;

	if(tcp.is_tcp) tcp.printTCPSpec();
}


int main(){
	pcapClass p;
	
	while(1){
		p.pcapGetPacket();
		p.pcapPrintNet();
		p.pcapPrintMask();
		p.pcapGetEtherSpec();
		p.pcapGetIPSpec();
		p.pcapGetTCPSpec();
	}	
	return 0;
}
