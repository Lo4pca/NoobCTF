# Two cups of tea

chatgpt 5加了自动思考功能后感觉比上一代聪明很多啊

（以下均指ida pro里的反编译结果）

题目加密输入使用的函数是`sub_1400015E0`。还有一个类似于tea加密的`sub_140001070`，但我直到做完这题也没发现它是干啥的

把`sub_1400015E0`的内容复制下来，改一点变量类型（比如`__int64`改成`int64_t`）就能直接运行了。但调试发现加密结果与程序不符。并不是因为反编译代码的逻辑出了差错（不过一堆混在一起的位运算就算错了我也找不到），而是因为ida声明的变量类型错了。比如这段：
```c
int v14;
v14 = *(_DWORD *)(a3 + 4LL * (((unsigned int)(v4 - 1640531527) >> 2) & 3));
```
a3，v4都是无符号类型，但v14却不是。把代码内所有误判类型的变量改掉就能得到正确的加密函数了

但是吧，这乱七八糟的代码人工逆也要费一番功夫。chatgpt上！

在其第一次尝试失败后，chatgpt第二次自动思考了2m9s得到了正确脚本。整理后的逻辑更清晰了
```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define DELTA 0x9E3779B9u
static inline uint32_t bswap32(uint32_t x) {
    return ((x & 0xFF000000) >> 24) |
           ((x & 0x00FF0000) >> 8 ) |
           ((x & 0x0000FF00) << 8 ) |
           ((x & 0x000000FF) << 24);
}

static inline uint32_t MIX(uint32_t left, uint32_t right, uint32_t sum, uint32_t k)
{
    // (((16*left) ^ (right >> 3)) + ((left >> 5) ^ (4*right))) ^ (((sum ^ right) + (k ^ left)))
    uint32_t a = ((uint32_t)16 * left) ^ (right >> 3);
    uint32_t b = (left >> 5) ^ ((uint32_t)4 * right);
    uint32_t c = (sum ^ right) + (k ^ left);
    return (a + b) ^ c;
}

void tea_encrypt(uint32_t *data, uint32_t *key)
{
    uint32_t block0 = data[0];
    uint32_t block1 = data[1];
    uint32_t block2 = data[2];
    uint32_t block3 = data[3];
    uint32_t block4 = data[4];
    uint32_t block5 = data[5];
    uint32_t block6 = data[6];
    uint32_t block7 = data[7];
    uint32_t block8 = data[8];
    uint32_t block9 = data[9];

    uint32_t sum = 0;
    const int rounds = 11;

    for (int r = 0; r < rounds; ++r) {
        uint32_t temp_sum = sum + DELTA;
        uint32_t idx = (temp_sum >> 2) & 3u;
        uint32_t k0 = key[idx];
        uint32_t k1 = key[idx ^ 1u];
        uint32_t k2 = key[idx ^ 2u];
        uint32_t k3 = key[idx ^ 3u];

        uint32_t temp_block0 = block0 + MIX(block9, block1, temp_sum, k0);
        block1 += MIX(temp_block0, block2, temp_sum, k1);
        block2 += MIX(block1, block3, temp_sum, k2);
        block3 += MIX(block2, block4, temp_sum, k3);
        block4 += MIX(block3, block5, temp_sum, k0);
        block5 += MIX(block4, block6, temp_sum, k1);
        block6 += MIX(block5, block7, temp_sum, k2);
        block7 += MIX(block6, block8, temp_sum, k3);
        block8 += MIX(block7, block9, temp_sum, k0);
        block9 += MIX(block8, temp_block0, temp_sum, k1);

        sum = temp_sum;
        block0 = temp_block0;
    }

    data[0] = block0; data[1] = block1; data[2] = block2; data[3] = block3; data[4] = block4;
    data[5] = block5; data[6] = block6; data[7] = block7; data[8] = block8; data[9] = block9;
}

void tea_decrypt(uint32_t *data, uint32_t *key)
{
    uint32_t block0 = data[0];
    uint32_t block1 = data[1];
    uint32_t block2 = data[2];
    uint32_t block3 = data[3];
    uint32_t block4 = data[4];
    uint32_t block5 = data[5];
    uint32_t block6 = data[6];
    uint32_t block7 = data[7];
    uint32_t block8 = data[8];
    uint32_t block9 = data[9];

    const int rounds = 11;
    uint32_t sum = DELTA * (uint32_t)rounds;

    for (int r = 0; r < rounds; ++r) {
        uint32_t idx = (sum >> 2) & 3u;
        uint32_t k0 = key[idx];
        uint32_t k1 = key[idx ^ 1u];
        uint32_t k2 = key[idx ^ 2u];
        uint32_t k3 = key[idx ^ 3u];

        uint32_t temp_block0 = block0;

        block9 -= MIX(block8, temp_block0, sum, k1);
        block8 -= MIX(block7, block9, sum, k0);
        block7 -= MIX(block6, block8, sum, k3);
        block6 -= MIX(block5, block7, sum, k2);
        block5 -= MIX(block4, block6, sum, k1);
        block4 -= MIX(block3, block5, sum, k0);
        block3 -= MIX(block2, block4, sum, k3);
        block2 -= MIX(block1, block3, sum, k2);
        block1 -= MIX(temp_block0, block2, sum, k1);
        block0 = temp_block0 - MIX(block9, block1, sum, k0);

        sum -= DELTA;
    }

    data[0] = block0; data[1] = block1; data[2] = block2; data[3] = block3; data[4] = block4;
    data[5] = block5; data[6] = block6; data[7] = block7; data[8] = block8; data[9] = block9;
}

int main(void)
{
    //直接从调试器的hex dump里复制的，需要转端序
    uint32_t data[10]={0x344C625D,0xADFE2986,0x9B37119D,0x1132D5FC,0xCE630F46,0x686E81C5,0xAD0053FE,0xEE15000A,0xBBDB0698,0x48264AEF};
    for(int i=0;i<10;i++){
        data[i]=bswap32(data[i]);
    }
    uint32_t key[4] = { 0x63656f6d, 0x21216674, 0x12345678, 0x9abcdef0 };
    tea_decrypt(data,key);
    char flag[41];
    memcpy(flag, data, 40);
    flag[40] = '\0';
    printf("%s\n", flag);
    return 0;
}
```