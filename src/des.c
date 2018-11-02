#include <stdlib.h>
#include <stdio.h>
#include "tables.h"
#include "des.h"

/**
 * Feistel 轮函数，用于进行16次迭代
 * @param R      32位数据
 * @param K      48位子密钥
 * @param output 32位输出
 */
void Feistel(bool* R, bool* K, bool* output) {
	// 1) 将32位的串R作E-扩展，成为48位的串
	int i;
	bool expandR[48];
	for (i = 0; i < 48; ++i)
	{
		expandR[i] = R[E[i] - 1];
	}

	// 2) expandR 与 K 异或
	for (i = 0; i < 48; ++i)
	{
		expandR[i] = expandR[i] == K[i] ? 0 :1;
	}

	// 3) 用S-盒分别对8个组进行 6-4 转换
	bool temp[32];
	for (i = 0; i < 8; ++i)
	{
		int j = i * 6;
		int row = expandR[j] * 2 + expandR[j+5];
		int col = expandR[j+1]*8 + expandR[j+2]*4 + expandR[j+3]*2 +expandR[j+4];
		int num = S_BOX[i][row][col];
		j = i * 4;
		int k;
		for (k = 3; k >= 0; --k)
		{
			temp[j + k] = num % 2;
			num /= 2;
		}
	}

	// 4) P-置换
	for (i = 0; i < 32; ++i)
	{
		output[i] = temp[P[i]-1];
	}

	return;
}

/**
 * 对56位密钥的前后部分进行左移
 * @param A     56位密钥
 * @param shift 偏移量
 */
void LeftShift(bool* A, int shift) {
	int temp0 = A[0], temp1 = A[1];
	int i;
	for (i = 0; i < 26; ++i) {
		A[i] = A[i+shift];
	}
	if (shift == 1) {
		A[26] = A[27];
		A[27] = temp0;
	} else if (shift == 2) {
		A[26] = temp0;
		A[27] = temp1;
	}
}

/**
 * 生成16个48位的子密钥
 */
void GenerateSubKeys() {
	bool realKey[56];
	bool left[28];
	bool right[28];
	int i;

	// 对密钥的56个非校验位实行PC-1置换
	for (i = 0; i < 56; ++i)
	{
		realKey[i] = key[PC_1[i] - 1];
	}

	// 生成子密钥并保存
	for (i = 0; i < 16; ++i)
	{
		int j;
		// 提取realKey的前28位和后28位
		for (j = 0; j < 28; ++j)
		{
			left[j] = realKey[j];
		}
		for (j = 0; j < 28; ++j)
		{
			right[j] = realKey[j+28];
		}
		// 左移
		LeftShift(left, shiftBits[i]);
		LeftShift(right,shiftBits[i]);
		// 恢复
		for (j = 0; j < 28; ++j)
		{
			realKey[j] = left[j];
		}
		for (j = 0; j < 28; ++j)
		{
			realKey[j] = right[j+28];
		}
		// PC-2压缩置换
		for (j = 0; j < 48; ++j)
		{
			subKey[i][j] = realKey[PC_2[j]-1];
		}
	}
}

/**
 * DES加密
 * @param plain  明文
 * @param cipher 加密得到的密文
 */
void encrypt(bool* plain, bool* cipher) {
	bool temp[64];
	bool left[32];
	bool right[32];
	bool newLeft[32];
	int i, round;


	// 1) 初始置换IP
	for (i = 0; i < 64; ++i)
	{
		temp[i] = plain[IP[i]-1];
	}
	// 2) 16轮迭代
	for (i = 0; i < 32; ++i)
	{
		left[i] = temp[i];
	}
	for (i = 0; i < 32; ++i)
	{
		right[i] = temp[i+32];
	}
	for (round = 0; round < 16; ++round)
	{
		for (i = 0; i < 32; ++i)
		{
			newLeft[i] = right[i];
		}
		bool fresult[32];
		Feistel(right, subKey[round], fresult);
		for (i = 0; i < 32; ++i)
		{
			right[i] = left[i] == fresult[i] ? 0 : 1;
		}
		for (i = 0; i < 32; ++i)
		{
			left[i] = newLeft[i];
		}
	}
	// 3) 交换置换
	for (i = 0; i < 32; ++i)
	{
		temp[i] = right[i];
	}
	for (i = 0; i < 32; ++i)
	{
		temp[i+32] = left[i];
	}
	// 4) 逆置换
	for (i = 0; i < 64; ++i)
	{
		cipher[i] = temp[IP_1[i]-1];
	}
	return;
}

/**
 * DES解密
 * @param cipher 密文
 * @param plain  解密得到的明文
 */
void decrypt(bool* cipher, bool* plain) {
	bool temp[64];
	bool left[32];
	bool right[32];
	bool newLeft[32];
	int i, round;


	// 1) 初始置换IP
	for (i = 0; i < 64; ++i)
	{
		temp[i] = cipher[IP[i]-1];
	}
	// 2) 16轮迭代
	for (i = 0; i < 32; ++i)
	{
		left[i] = temp[i];
	}
	for (i = 0; i < 32; ++i)
	{
		right[i] = temp[i+32];
	}
	for (round = 0; round < 16; ++round)
	{
		for (i = 0; i < 32; ++i)
		{
			newLeft[i] = right[i];
		}
		bool fresult[32];
		Feistel(right, subKey[15-round], fresult);
		for (i = 0; i < 32; ++i)
		{
			right[i] = left[i] == fresult[i] ? 0 : 1;
		}
		for (i = 0; i < 32; ++i)
		{
			left[i] = newLeft[i];
		}
	}
	// 3) 交换置换
	for (i = 0; i < 32; ++i)
	{
		temp[i] = right[i];
	}
	for (i = 0; i < 32; ++i)
	{
		temp[i+32] = left[i];
	}
	// 4) 逆置换
	for (i = 0; i < 64; ++i)
	{
		plain[i] = temp[IP_1[i]-1];
	}
	return;
}

/**
 * 将8个字节转换成64位
 * @param s      8个字节的char数组
 * @param bitset 位数组
 */
void BytesToBits(char* s, bool* bitset) {
	int i, j;
	for (i = 0; i < 8; ++i)
	{
		for (j = 0; j < 8; ++j)
		{
			bitset[8*i+j] = (s[i]>>j)&1;
		}
	}
	return;
}

void BitsToBytes(bool* bitset, char* s) {
	int i, j;
	for (i = 0; i < 8; ++i)
	{
		for (j = 0; j < 8; ++j)
		{
			s[i] |= ((int)bitset[8*i+j])<<j;
		}
	}
	s[8] = '\0';
	return;
}
