all: pcap_test

pcap_test: pcap_test.cpp
	g++ -o pcap_test pcap_test.cpp -lpcap
