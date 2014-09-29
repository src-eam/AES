#ifndef AES_H_
#define AES_H_

#include <vector>
#include <string>
#include <algorithm>
#include <stdint.h>

class AES {
protected:
	unsigned int Nk, Nb, Nr, version;
	static const uint8_t S_BOX [];

	std::vector<std::vector<uint8_t>> wwKey;
	std::vector<std::vector<uint8_t>> state;
	std::string text;

	void initAes(const unsigned int &ver, const std::string &txt);
	uint8_t g_mul(uint8_t a,uint8_t b) const;

	void subWord(std::vector<uint8_t> &tmp) const;
	void rotWord(std::vector<uint8_t> &tmp) const;
	void keyExpansion(const std::vector<uint8_t> &key);
	void addRoundKey(const uint8_t &round);

public:
	virtual ~AES() = 0;

};

#endif /* AES_H_ */
