all:
	g++ -o send-arp send-arp-main.cpp arphdr.cpp ethhdr.cpp ip.cpp mac.cpp get_mac_ip.cpp -lpcap

clean:
	rm send-arp
