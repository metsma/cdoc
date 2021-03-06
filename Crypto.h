#pragma once

#include <cstdint>
#include <iomanip>
#include <memory>
#include <string>
#include <sstream>
#include <vector>

typedef unsigned char uchar;
typedef struct evp_cipher_st EVP_CIPHER;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct x509_st X509;
#define SCOPE(TYPE, VAR, DATA) std::unique_ptr<TYPE,decltype(&TYPE##_free)> VAR(DATA, TYPE##_free)

class Crypto
{
public:
	static const std::string SHA256_MTH, SHA384_MTH, SHA512_MTH;
	static const std::string KWAES128_MTH, KWAES192_MTH, KWAES256_MTH;
	static const std::string AES128CBC_MTH, AES192CBC_MTH, AES256CBC_MTH, AES128GCM_MTH, AES192GCM_MTH, AES256GCM_MTH;
	static const std::string RSA_MTH, CONCATKDF_MTH, AGREEMENT_MTH;

	struct Key { std::vector<uchar> key, iv; };

	static std::vector<uchar> AESWrap(const std::vector<uchar> &key, const std::vector<uchar> &data, bool encrypt);
	static const EVP_CIPHER *cipher(const std::string &algo);
	static std::vector<uchar> concatKDF(const std::string &hashAlg, uint32_t keyDataLen, const std::vector<uchar> &z, const std::vector<uchar> &otherInfo);
	static std::vector<uchar> concatKDF(const std::string &hashAlg, uint32_t keyDataLen, const std::vector<uchar> &z,
		const std::vector<uchar> &AlgorithmID, const std::vector<uchar> &PartyUInfo, const std::vector<uchar> &PartyVInfo);
	static std::vector<uchar> encrypt(const std::string &method, const Key &key, std::istream &in);
	static std::vector<uchar> decrypt(const std::string &method, const std::vector<uchar> &key, const std::vector<uchar> &data);
	static std::vector<uchar> decodeBase64(const uchar *data);
	static std::vector<uchar> deriveSharedSecret(EVP_PKEY *pkey, EVP_PKEY *peerPKey);
	static Key generateKey(const std::string &method);
	static uint32_t keySize(const std::string &algo);
	static std::string toBase64(const uchar *data, size_t len);
	template <typename F>
	static std::string toHex(const F &data)
	{
		std::stringstream os;
		os << std::hex << std::uppercase << std::setfill('0');
		for(const auto &i: data)
			os << std::setw(2) << (static_cast<int>(i) & 0xFF);
		return os.str();
	}
	static X509* toX509(const std::vector<uchar> &data);
};
