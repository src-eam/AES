#include "AES.h"

const uint8_t AES::S_BOX[] = { 99, 124, 119, 123, 242, 107, 111, 197, 48, 1,
		103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173,
		212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204,
		52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154,
		7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160,
		82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91,
		106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133,
		69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245,
		188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23,
		196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136,
		70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194,
		211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169,
		108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180,
		198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3,
		246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105,
		217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13,
		191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22 };

void AES::initAes(const unsigned int &ver, const std::string &txt) {
	if (ver == 256) {
		Nb = 4;
		Nk = 8;
		Nr = 14;
	}
	else if (ver == 192) {
		Nb = 4;
		Nk = 6;
		Nr = 12;
	}
	//default: ver = 128
	else {
		Nb = 4;
		Nk = 4;
		Nr = 10;
	}
	this->version = ver;
	this->text = txt;
	while (this->text.length() & 0xf)
		this->text += " ";

	wwKey.resize(Nb * (Nr + 1), std::vector<uint8_t>(4));
	state.resize(4, std::vector<uint8_t>(4));
}

void AES::subWord(std::vector<uint8_t> &tmp) const {
	uint8_t cur;
	for (uint8_t k = 0; k < 4; ++k) {
		cur = tmp[k];
		tmp[k] = S_BOX[((0xf0 & cur) | (0x0f & cur))];
	}
}

void AES::rotWord(std::vector<uint8_t> &tmp) const {
	std::rotate(tmp.begin(), tmp.begin() + 1, tmp.end());
}

void AES::keyExpansion(const std::vector<uint8_t> &key) {
	std::vector<uint8_t> tmp(4);
	for (unsigned int index = 0; index < Nk; index++) {
		for (uint8_t j = 0; j < 4; j++)
			wwKey[index][j] = key[4 * index + j];
	}
	int len = Nb * (Nr + 1), rcon;
	for (unsigned int index = Nk; index < len; index++) {
		tmp = wwKey[index - 1];
		if ((index % Nk) == 0) {
			rotWord(tmp);
			subWord(tmp);
			rcon = index / Nk;
			if (rcon < 9)
				rcon = (rcon != 0) ? (1 << (rcon - 1)) : 1;
			else if (rcon == 10)
				rcon = 0x36;
			else
				rcon = 0x1b;
			tmp[0] ^= rcon;
		}
		else if ((Nk > 6) && ((index % Nk) == 4)) {
			subWord(tmp);
		}
		for (int j = 0; j < 4; j++) {
			wwKey[index][j] = wwKey[index - Nk][j] ^ tmp[j];
		}
	}
}

uint8_t AES::g_mul(uint8_t a, uint8_t b) const {
	uint8_t result = 0;
	uint8_t prom;
	for (uint8_t index = 0; index < 8; index++) {
		if (b & 1)
			result ^= a;
		prom = (a & 0x80);
		a <<= 1;
		if (prom)
			a ^= 0x1b;
		b >>= 1;
	}
	return result;
}

void AES::addRoundKey(const uint8_t &round) {
	int pos;
	for (uint8_t c = 0; c < Nb; c++) {
		pos = Nb * round + c;
		for (uint8_t j = 0; j < 4; j++) {
			state[j][c] ^= wwKey[pos][j];
		}
	}
}

AES::~AES() {;}
