#include <pcap.h>
#include <stdbool.h>
#include <iostream>
#include <unistd.h>
#include <cstring>
#include <vector>
#include <thread>

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
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void init(char arr[]) 
{
    // 모니터 모드로 변경

    char command[100];
    sprintf(command, "sudo ifconfig %s down", arr);
    system(command);
    sprintf(command, "sudo iwconfig %s mode monitor", arr);
    system(command);
    sprintf(command, "sudo ifconfig %s up", arr);
    system(command);
    std::cout << "랜카드를 모니터 모드로 변경했습니다." << std::endl;
}

void change_channl(char arr[])
{

    // 채널 1~13까지 계속 바꿈
    char command[100];
    int channel = 1;

    while (1)
    {
        channel++;
        if (channel >= 14)
            channel = 1;
        sprintf(command, "iwconfig %s ch %d", arr, channel);
        system(command);
        sleep(3);
    }

}

int isHidden(const u_char*& packet, int Header_length, int len)
{
    // Hidden ssid인지 판별
    int cnt = 0;
    for (int i = 0; i < len; i++)
    {
        if (packet[Header_length + 38 + i] == '\x00')
            cnt++;
    }

    if (cnt == len)
        return 1;
    else
        return 0;
}

class RadioTap {

private:
    uint8_t Header_revision;
    uint8_t Header_pad;
    uint16_t Header_length;
    int jump;
    uint32_t Present_flags;
    int8_t Antenna_signal;
    uint8_t type;

    uint8_t Destination_address[6];
    uint8_t Source_address[6];
    uint8_t bss_id[6];
    uint16_t Capabilities_Information;
    uint8_t ssid_length;
    char* ssid;
    uint8_t channel;

    std::string enc;

    int beacons;
    int data;

public:
    RadioTap(const u_char*& packet)
    {
        Header_revision = packet[0];
        Header_pad = packet[1];
        Header_length = packet[2];
        jump = 0;

        // signal의 offset을 구하기 위한 코드
        Present_flags = (packet[4] + (packet[5] << 8) + (packet[6] << 16) + (packet[7] << 24));
        if ((Present_flags & 0x1) == 0b1)
            jump += 8;
        if (((Present_flags >> 1) & 0b1) == 0x1)
            jump += 1;
        if (((Present_flags >> 2) & 0b1) == 0x1)
            jump += 1;
        if (((Present_flags >> 3) & 0b1) == 0x1)
            jump += 4;
        int a = 4;

        while (((Present_flags >> 31) & 0b1) == 0x1)
        {
            Present_flags = (packet[4 + a] + (packet[5 + a] << 8) + (packet[6 + a] << 16) + (packet[7 + a] << 24));
            jump += 4;

        }
        jump += 4;
        Antenna_signal = packet[4 + jump];


        type = packet[Header_length];

        for (int i = 0; i < 6; i++) // 목적지 mac 파싱
        {
            Destination_address[i] = packet[Header_length + 4 + i];
        }
        for (int i = 0; i < 6; i++) // 출발지 mac 파싱
        {
            Source_address[i] = packet[Header_length + 10 + i];
        }
        for (int i = 0; i < 6; i++) // bssid 파싱
        {
            bss_id[i] = packet[Header_length + 16 + i];
        }

        Capabilities_Information = (packet[Header_length + 35] << 0x8) + packet[Header_length + 34];

        // ssid의 길이 파싱
        ssid_length = packet[Header_length + 37];

        // ssid의 tag number은 0임
        if (ssid_length == 0 && (packet[Header_length + 36] == 0))
        {
            // wild card인 경우
            ssid = new char[10];
            ssid[0] = 'w';
            ssid[1] = 'i';
            ssid[2] = 'l';
            ssid[3] = 'd';
            ssid[4] = ' ';
            ssid[5] = 'c';
            ssid[6] = 'a';
            ssid[7] = 'r';
            ssid[8] = 'd';
            ssid[9] = '\0';

        }
        else if (isHidden(packet, Header_length, ssid_length) && (packet[Header_length + 36] == 0))
        {
            // hidden ssid인 경우

            char cmd[100];
            sprintf(cmd, "<length: %d>", ssid_length);
            ssid = new char[strlen(cmd) + 1];
            strcpy(ssid, cmd);

        }
        else if (packet[Header_length + 36] == 0)
        {
            // ssid 파싱
            ssid = new char[ssid_length + 1];
            for (int i = 0; i < ssid_length; i++)
                ssid[i] = packet[Header_length + 38 + i];
            ssid[ssid_length] = 0;
        }
        else
        {
            // tag number 중에 0인게 없는 경우
            ssid = new char[2];
            ssid[0] = 0;
        }



        int find = 0;
        a = 0;
        // channel의 tag number은 3임
        while (find < 4)
        {

            if (packet[Header_length + 36 + a] == 0x3)
            {

                channel = packet[Header_length + 36 + a + 2];
                break;
            }
            else
            {
                a += 1;
                a += packet[Header_length + 36 + a];
                a += 1;
                find++;

            }
        }

        find = 0;
        a = 0;
        // 보안 규격 파싱
        if (((Capabilities_Information >> 4) & 0x1) == 0x0)
        {
            enc = "WEP";
        }
        else
        {
            while (find < 49)
            {

                if (packet[Header_length + 36 + a] == 0x30)
                {

                    enc = "WPA2";
                    find = 1;
                    break;
                }
                else
                {
                    a += 1;
                    a += packet[Header_length + 36 + a];
                    a += 1;
                    find++;

                }
            }
            if (find != 1)
                enc = "WPA";

        }

        beacons = 1;
        data = 0;


    }


    void print()
    {

        // 파싱 내용 출력
        printf("%02x:%02x:%02x:%02x:%02x:%02x\t", bss_id[0], bss_id[1], bss_id[2], bss_id[3], bss_id[4], bss_id[5]);
        printf("%d\t", beacons);
        printf("%d\t", Antenna_signal);
        printf("%d\t", data);
        printf("%d\t", channel);
        std::cout << enc << '\t';
        std::cout << ssid << '\t';
        printf("\n");



    }
    int is_beacon_data()
    {
        // 비콘과 데이터인지 확인
        if (((((type >> 4) & 0b1111) == 0x8) && ((type & 0b1111) == 0x0)) || (((type >> 2) & 0b11) == 0b10))
        {
            return 1;

        }
        return 0;
    }

    int same(const u_char*& packet)
    {
        RadioTap radio{ packet };


        if ((radio.bss_id[0] == this->bss_id[0]) && (radio.bss_id[1] == this->bss_id[1]) && (radio.bss_id[2] == this->bss_id[2]) && (radio.bss_id[3] == this->bss_id[3]) && (radio.bss_id[4] == this->bss_id[4]) && (radio.bss_id[5] == this->bss_id[5]))
        {
            // mac주소가 같은지 확인

            // 비콘인지 확인
            if (((type >> 4) & 0b1111) == 0x8)
            {
                this->beacons++;
                Antenna_signal = packet[4 + jump];
                int find = 0;
                int a = 0;

                ssid_length = packet[Header_length + 37];
                if (ssid_length == 0 && (packet[Header_length + 36] == 0))
                {
                    ssid = new char[10];
                    ssid[0] = 'w'; 
                    ssid[1] = 'i';
                    ssid[2] = 'l';
                    ssid[3] = 'd';
                    ssid[4] = ' ';
                    ssid[5] = 'c';
                    ssid[6] = 'a';
                    ssid[7] = 'r';
                    ssid[8] = 'd';
                    ssid[9] = '\0';

                }
                else if (isHidden(packet, Header_length, ssid_length) && (packet[Header_length + 36] == 0))
                {

                    char cmd[100];
                    sprintf(cmd, "<length: %d>", ssid_length);
                    ssid = new char[strlen(cmd) + 1];
                    strcpy(ssid, cmd);

                }
                else if (packet[Header_length + 36] == 0)
                {
                    ssid = new char[ssid_length + 1];
                    for (int i = 0; i < ssid_length; i++)
                        ssid[i] = packet[Header_length + 38 + i];
                    ssid[ssid_length] = 0;
                }
                channel = 0;
                while (find < 4)
                {

                    if (packet[Header_length + 36 + a] == 0x3) // channel의 tag number은 3임
                    {

                        channel = packet[Header_length + 36 + a + 2];
                        break;
                    }
                    else
                    {
                        a += 1;
                        a += packet[Header_length + 36 + a];
                        a += 1;
                        find++;

                    }
                }
                return 1;
            }
            else if ((((radio.type >> 2) & 0b11) == 0b10)) // 데이터 패킷인지 확인
            {
                this->data++;
                return 1;
            }


        }


        return 0;
    }



};



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

    std::vector<RadioTap> v;
    std::thread t1(&change_channl, argv[1]);
    int cnt = 1;
    int find = 0;
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        RadioTap radio{ packet };

        if (!radio.is_beacon_data())
            continue;
        //radio.print_len();

        for (auto iter = v.begin(); iter != v.end(); iter++)
        {
            if ((iter->same(packet)) == 1) // 동일한 패킷이 벡터에 있는지 확인
            {
                find = 1;
                break;
            }
            else
            {
                find = 0;
            }
        }

        if (!find) // 동일 패킷인 벡터에 없으면 추가
            v.push_back(radio);

        cnt = 1;

        printf("Number\tBSSID\t\t\tBeacons\tPWR\t#Data\tCH\tENC\tESSID\n\n");
        for (auto& i : v)
        {
            printf("%d\t", cnt);
            cnt++;
            i.print();
        }
        printf("\n\n\n");



        sleep(1);

    }
    t1.join();
    pcap_close(pcap);
}
