#ifndef ENCRYPTAES_H_
#define ENCRYPTAES_H_

#include "AES.h"

class EncryptAES: public AES {
protected:
	void subBytes();
	void shiftRows();
	void mixColumns ();
	void encryptAes();

public:
	EncryptAES();
	explicit EncryptAES(const unsigned int &ver);
	explicit EncryptAES(const std::string &txt);
	EncryptAES(const unsigned int &ver, const std::string &txt);

	std::string encrypt(const std::vector<uint8_t> &key);
	void encrypt(std::string & resultEncrypt, const std::vector<uint8_t> &k);

	~EncryptAES() { };
};

#endif /* ENCRYPTAES_H_ */
