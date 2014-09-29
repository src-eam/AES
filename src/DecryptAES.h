#ifndef DECRYPTAES_H_
#define DECRYPTAES_H_

#include "AES.h"

class DecryptAES: public AES {
protected:
	const static uint8_t INV_S_BOX[];

	void invSubBytes();
	void invShiftRows();
	void invMixColumns ();
	void decryptAes();

public:
	DecryptAES();
	explicit DecryptAES(const unsigned int &ver);
	explicit DecryptAES(const std::string &txt);
	DecryptAES(const unsigned int &ver, const std::string &txt);

	std::string decrypt(const std::vector<uint8_t> &key);
	void decrypt(std::string & resultEncrypt, const std::vector<uint8_t> &k);

	~DecryptAES() { };
};

#endif /* DECRYPTAES_H_ */
