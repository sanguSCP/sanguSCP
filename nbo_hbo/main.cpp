#include <stdio.h>
#include <stdint.h>

int main(int argc, char *argv[])
{
    FILE *fp1 = fopen(argv[1],"rb");
    uint32_t data = 0;
    uint32_t data1 = 0;
    uint8_t l = 0;
    fread(&data,sizeof(uint32_t),1,fp1);
    printf("file1 : %x\n",data);
    for (int i = 0; i < 4; i++)
    {
        l = data;
        data1 += l;
        if (i != 3)
            data1 = data1 << 8;
        data = data >> 8;

    }
    FILE *fp2 = fopen(argv[2],"wb");
    fwrite(&data1,sizeof(uint32_t),1,fp2);
    printf("file2 : %x\n",data1);

    fclose(fp1);
    fclose(fp2);

    return 0;
}
