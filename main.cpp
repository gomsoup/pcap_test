#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>

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

	void pcapGetPacket(){
		packet = pcap_next(handle, &header);
		printf("Jacked a packet with legth of [%d]\n", header.len);
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
	return 0;
}
