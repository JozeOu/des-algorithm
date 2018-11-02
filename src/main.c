#include <stdio.h>
#include "des.h"

int main() {
	char plainStr[9];
	char keyStr[9];
	char resultStr[9];

	// 输入明文和密钥
	printf("请输入明文和密钥（格式均为8个字符组成的字符串）\n");
	printf("明文：");
	scanf("%s", plainStr);
	printf("密钥：");
	scanf("%s", keyStr);

	bool plain[64];
	bool cipher[64];
	bool result[64];
	
	// 将明文和密钥转换为位数组
	BytesToBits(plainStr, plain);
	BytesToBits(keyStr, key);
	
	// 生成16个48位的子密钥
	GenerateSubKeys();
	
	// DES加密
	encrypt(plain, cipher);
	printf("你的明文已被加密\n");

	printf("请输入密钥来进行解密：");
	scanf("%s", keyStr);
	BytesToBits(keyStr, key);
	GenerateSubKeys();

	// DES解密
	decrypt(cipher, result);

	// 将解密结果转换char数组
	BitsToBytes(result, resultStr);

	printf("解密得到的明文为：%s\n", resultStr);
	printf("如果你输入了正确的密钥，则该结果与原明文一样；否则，该结果将不同与原明文\n");

	return 0;
}
