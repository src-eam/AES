#include "EncryptAES.h"
#include <iostream>

EncryptAES::EncryptAES() {
	initAes(128, "");
}

EncryptAES::EncryptAES(const std::string &txt) {
	initAes(128, txt);
}

EncryptAES::EncryptAES(const unsigned int &ver) {
	initAes(ver, "");
}

EncryptAES::EncryptAES(const unsigned int &ver, const std::string &txt) {
	initAes(ver, txt);
}

void EncryptAES::subBytes() {
	uint8_t curElem;
	for (uint8_t elem = 0; elem < 4; elem++) {
		for (uint8_t elem2 = 0; elem2 < 4; elem2++) {
			curElem = state[elem][elem2];
			state[elem][elem2] = S_BOX[uint8_t(
					(0xf0 & curElem) | (0x0f & curElem))];
		}
	}
}

void EncryptAES::shiftRows() {
	std::vector<uint8_t> tmp(4);
	for (uint8_t r = 1; r < 4; r++) {
		for (uint8_t c = 0; c < Nb; c++) {
			tmp[c] = state[r][(c + r) & 3];
		}
		state[r] = tmp;
	}
}

void EncryptAES::mixColumns() {
	uint8_t a, b, e, d;
	for (uint8_t c = 0; c < Nb; c++) {
		a = g_mul(0x02, state[0][c]) ^ g_mul(0x03, state[1][c]) ^ state[2][c]
				^ state[3][c];
		b = state[0][c] ^ g_mul(0x02, state[1][c]) ^ g_mul(0x03, state[2][c])
				^ state[3][c];
		e = state[0][c] ^ state[1][c] ^ g_mul(0x02, state[2][c])
				^ g_mul(0x03, state[3][c]);
		d = g_mul(0x03, state[0][c]) ^ state[1][c] ^ state[2][c]
				^ g_mul(0x02, state[3][c]);
		state[0][c] = a;
		state[1][c] = b;
		state[2][c] = e;
		state[3][c] = d;
	}
}

void EncryptAES::encryptAes() {
	addRoundKey(0);
	for (uint8_t round = 1; round < Nr; round++) {
		subBytes();
		shiftRows();
		mixColumns();
		addRoundKey(round);
	}
	subBytes();
	shiftRows();
	addRoundKey(Nr);
}

void EncryptAES::encrypt(std::string &resultEncrypt,
		const std::vector<uint8_t> &k) {
	keyExpansion(k);
	if (resultEncrypt.capacity() < text.size())
		resultEncrypt.reserve(this->text.size());
	int index = 0, jndex = 0,ind_str = 0;
	for (auto iter = this->text.begin(); iter != this->text.end();
			iter++, index++) {
		state[index][jndex] = (*iter);
		if (index == 3) {
			index = -1;
			if (jndex == 3) {
				encryptAes();
				for (int i = 0; i < 4; i++)
					for (int j = 0; j < 4; j++)
						resultEncrypt += state[j][i];
				jndex = 0;
			}
			else
				jndex++;
		}
	}
}

std::string EncryptAES::encrypt(const std::vector<uint8_t> &key) {
	std::string result = "";
	encrypt(result, key);
	return result;
}
