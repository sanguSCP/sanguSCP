#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>


void usage() {
    // arvc가 2가 아닐 경우 실행
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

#pragma pack(push, 1)
typedef struct {
    uint8_t Destination[6]; //des mac
    uint8_t Source[6];    // src mac
    uint16_t Type;

}NETWORK_ETHERNET_HEADER;


typedef struct {
    uint8_t Version : 4;
    uint8_t Header_Length : 4;
    uint8_t Type_Of_Service;
    uint16_t Total_Packet_Length;
    uint16_t Identifier;
    uint8_t Flags : 3;
    uint32_t Fragment_Offset : 13;
    uint8_t Time_to_Live;
    uint8_t Protocol_Id;
    uint16_t Header_Checksum;
    uint8_t Source_IP_Address[4];
    uint8_t Destination_IP_Address[4];
}NETWORK_IP_HEADER;

typedef struct{
    uint16_t Source_Port;
    uint16_t Destination_Port;
}NETWORK_TCP_PROTOCOL;
#pragma pack(pop)

bool parse(Param* param, int argc, char* argv[]) {
    // ./pcap-test로 실행할 경우 argc는 1개 ./pcap-test enp0s3와 같이 는추가 인자를 주면 1씩 더해짐
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    // ./pcap-test enp0s3로 실행하면 argv[0]에는 실행경로가 argv[1]에는 enp0s3 같은 추가 인자를 저장
    return true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        // !가 있으므로 argc가 2가 아니면 return -1로 종료하고 argc가 2면 if문이 실행 안됨
        return -1;
    // argc,argv를 통한 인자 값 개수 채크
    char errbuf[PCAP_ERRBUF_SIZE];
    // libpcap 루틴이 실패할 경우 오류 메세지를 담기 위한 버퍼 PCAP_ERRBUF_SIZE는 256으로 추정
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    // 네트워크 인터페이스 이름, 캡쳐할 패킷의 최대 길이, promiscuous mode 사용여부,
    // 캡쳐 시간 제한 , 오류 메시지 저장 버퍼
    // pcap은 함수가 실패할 경우 NULL포인터가 반환됨

    if (pcap == NULL) {
        // pcap 함수가 실패 했을 경우 오류 메시지 출력 후 종료(enp0s3이 아닌 다른 것을 입력하면 출력 됨)
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }
    // pcap 핸들 열기

    while (true) {
        struct pcap_pkthdr* header;
        // 패킷 캡쳐 시에 각 패킷의 헤더 정보를 저장하는 구조체
        // ts : 패킷의 타임스탬프, caplen : 캡쳐된 패킷의 길이, len : 실제 패킷의 길)
        const u_char* packet;
        // u_char : unsigned 8bit
        int res = pcap_next_ex(pcap, &header, &packet);
        // pcap_open_live 또는 pcap_open_offline등을 통해 열린 네트워크 인터페이스 또는 파일
        // 패킷 헤더 정보를 저장할 포인터의 포인터
        // 캡쳐된 패킷 데이터를 저장할 포인터의 포인터 (여기에 있을 듯)
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        NETWORK_ETHERNET_HEADER *Ethernet = (NETWORK_ETHERNET_HEADER*)packet;
        NETWORK_IP_HEADER *IP = (NETWORK_IP_HEADER*)(packet + sizeof(NETWORK_ETHERNET_HEADER));
        NETWORK_TCP_PROTOCOL *TCP = (NETWORK_TCP_PROTOCOL*)(packet + sizeof(NETWORK_ETHERNET_HEADER)+ sizeof(NETWORK_IP_HEADER));
        const u_char *payload = (NETWORK_TCP_PROTOCOL*)(packet + sizeof(NETWORK_ETHERNET_HEADER)+ sizeof(NETWORK_IP_HEADER)) + 20;
        if (htons(Ethernet->Type) != 0x0800 || IP->Protocol_Id != 0x06)
            continue;
        printf("Dst Mac    : ");
        for (int i = 0; i < 6; i++)
        {
            if (i != 5)
                printf("%02X:",Ethernet->Destination[i]);
            else
                printf("%02X\n",Ethernet->Destination[i]);

        }
        printf("Src Mac    : ");
        for (int i = 0; i < 6; i++)
        {
            if (i != 5)
                printf("%02X:",Ethernet->Source[i]);
            else
                printf("%02X\n",Ethernet->Source[i]);

        }



        printf("Src IP     : ");
        for (int i = 0; i < 4; i++)
        {
            if (i != 3)
                printf("%u.",IP->Source_IP_Address[i]);
            else
                printf("%u\n",IP->Source_IP_Address[i]);

        }
        printf("Dst IP     : ");
        for (int i = 0; i < 4; i++)
        {
            if (i != 3)
                printf("%u.",IP->Destination_IP_Address[i]);
            else
                printf("%u\n",IP->Destination_IP_Address[i]);

        }

        printf("Src Port   : %u\n",TCP->Source_Port);
        printf("Dst Port   : %u\n",TCP->Destination_Port);
        printf("total Byte : %u\n",IP->Total_Packet_Length);
        printf("Payload    : ");
        for (int i = 0; i < 16; i++) {
            printf("%02X ", payload[i]);
        }
        printf("\n");


        printf("\n");
    }
    pcap_close(pcap);
    //패킷 캡쳐 후 pcap_header 구조체로 패킷의 길이를 출력
}
