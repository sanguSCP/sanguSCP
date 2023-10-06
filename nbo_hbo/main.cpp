#include <stdio.h>
#include <stdint.h>

int main(int argc, char* argv[])
{
    FILE* fp1 = fopen(argv[1], "rb");
    uint32_t data = 0;
    uint64_t data1 = 0;
    uint8_t l = 0;
    fread(&data, sizeof(uint32_t), 1, fp1);
    printf("%x\n", data);
    for (int i = 0; i < 4; i++)
    {
        // 32 비트를 8비트 형으로 받으면 뒤 쪽부터 8bit까지만 저장되는 것을 이용 
        l = data;
        data1 += l;
        if (i != 3) // 마지막에 한 번 더 밀려 처음 값이 사라지는 것을 막기 위해서 사용
            data1 = data1 << 8; // l 즉, data의 뒤쪽 8bit를 쉬프트로 욺겨서 다음 8bit를 입력 받을 수 있도록 하기 위해 사용
        data = data >> 8;   // 8bit를 
        printf("%x\n", data1);
    }
    FILE* fp2 = fopen(argv[2], "wb");
    fwrite(&data1, sizeof(uint32_t), 1,fp2);
    printf("%x\n", data1);


    return 0;
}
