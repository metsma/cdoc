#include "Crypto.h"

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <cmath>
#include <cstring>

const std::string Crypto::SHA256_MTH = "http://www.w3.org/2001/04/xmlenc#sha256";
const std::string Crypto::SHA384_MTH = "http://www.w3.org/2001/04/xmlenc#sha384";
const std::string Crypto::SHA512_MTH = "http://www.w3.org/2001/04/xmlenc#sha512";
const std::string Crypto::KWAES128_MTH = "http://www.w3.org/2001/04/xmlenc#kw-aes128";
const std::string Crypto::KWAES192_MTH = "http://www.w3.org/2001/04/xmlenc#kw-aes192";
const std::string Crypto::KWAES256_MTH = "http://www.w3.org/2001/04/xmlenc#kw-aes256";
const std::string Crypto::AES128CBC_MTH = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
const std::string Crypto::AES192CBC_MTH = "http://www.w3.org/2001/04/xmlenc#aes192-cbc";
const std::string Crypto::AES256CBC_MTH = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
const std::string Crypto::AES128GCM_MTH = "http://www.w3.org/2009/xmlenc11#aes128-gcm";
const std::string Crypto::AES192GCM_MTH = "http://www.w3.org/2009/xmlenc11#aes192-gcm";
const std::string Crypto::AES256GCM_MTH = "http://www.w3.org/2009/xmlenc11#aes256-gcm";
const std::string Crypto::RSA_MTH = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
const std::string Crypto::CONCATKDF_MTH = "http://www.w3.org/2009/xmlenc11#ConcatKDF";
const std::string Crypto::AGREEMENT_MTH = "http://www.w3.org/2009/xmlenc11#ECDH-ES";

std::vector<uchar> Crypto::AESWrap(const std::vector<uchar> &key, const std::vector<uchar> &data, bool encrypt)
{
	AES_KEY aes;
	encrypt ?
		AES_set_encrypt_key(key.data(), int(key.size()) * 8, &aes) :
		AES_set_decrypt_key(key.data(), int(key.size()) * 8, &aes);
	std::vector<uchar> result(data.size() + 8);
	int size = encrypt ?
		AES_wrap_key(&aes, nullptr, result.data(), data.data(), data.size()) :
		AES_unwrap_key(&aes, nullptr, result.data(), data.data(), data.size());
	if(size > 0)
		result.resize(size_t(size));
	else
		result.clear();
	return result;
}

const EVP_CIPHER *Crypto::cipher(const std::string &algo)
{
	if(algo == AES128CBC_MTH) return EVP_aes_128_cbc();
	if(algo == AES192CBC_MTH) return EVP_aes_192_cbc();
	if(algo == AES256CBC_MTH) return EVP_aes_256_cbc();
	if(algo == AES128GCM_MTH) return EVP_aes_128_gcm();
	if(algo == AES192GCM_MTH) return EVP_aes_192_gcm();
	if(algo == AES256GCM_MTH) return EVP_aes_256_gcm();
	return nullptr;
}

std::vector<uchar> Crypto::concatKDF(const std::string &hashAlg, uint32_t keyDataLen,
	const std::vector<uchar> &z, const std::vector<uchar> &otherInfo)
{
	std::vector<uchar> key;
	uint32_t hashLen = SHA384_DIGEST_LENGTH;
	if(hashAlg == SHA256_MTH) hashLen = SHA256_DIGEST_LENGTH;
	else if(hashAlg == SHA384_MTH) hashLen = SHA384_DIGEST_LENGTH;
	else if(hashAlg == SHA512_MTH) hashLen = SHA512_DIGEST_LENGTH;
	else return key;

	SHA256_CTX sha256;
	SHA512_CTX sha512;
	std::vector<uchar> hash(hashLen, 0), intToFourBytes(4, 0);
	uint32_t reps = uint32_t(std::ceil(double(keyDataLen) / double(hashLen)));
	for(uint32_t i = 1; i <= reps; i++)
	{
		intToFourBytes[0] = uchar(i >> 24);
		intToFourBytes[1] = uchar(i >> 16);
		intToFourBytes[2] = uchar(i >> 8);
		intToFourBytes[3] = uchar(i >> 0);
		switch(hashLen)
		{
		case SHA256_DIGEST_LENGTH:
			SHA256_Init(&sha256);
			SHA256_Update(&sha256, intToFourBytes.data(), intToFourBytes.size());
			SHA256_Update(&sha256, z.data(), z.size());
			SHA256_Update(&sha256, otherInfo.data(), otherInfo.size());
			SHA256_Final(hash.data(), &sha256);
			break;
		case SHA384_DIGEST_LENGTH:
			SHA384_Init(&sha512);
			SHA384_Update(&sha512, intToFourBytes.data(), intToFourBytes.size());
			SHA384_Update(&sha512, z.data(), z.size());
			SHA384_Update(&sha512, otherInfo.data(), otherInfo.size());
			SHA384_Final(hash.data(), &sha512);
			break;
		case SHA512_DIGEST_LENGTH:
			SHA512_Init(&sha512);
			SHA512_Update(&sha512, intToFourBytes.data(), intToFourBytes.size());
			SHA512_Update(&sha512, otherInfo.data(), otherInfo.size());
			SHA512_Final(hash.data(), &sha512);
			break;
		default: return key;
		}
		key.insert(key.cend(), hash.cbegin(), hash.cend());
	}
	key.resize(size_t(keyDataLen));
	return key;
}

std::vector<uchar> Crypto::concatKDF(const std::string &hashAlg, uint32_t keyDataLen, const std::vector<uchar> &z,
	const std::vector<uchar> &AlgorithmID, const std::vector<uchar> &PartyUInfo, const std::vector<uchar> &PartyVInfo)
{
#ifndef NDEBUG
	printf("Ksr %s\n", Crypto::toHex(z).c_str());
	printf("AlgorithmID %s\n", Crypto::toHex(AlgorithmID).c_str());
	printf("PartyUInfo %s\n", Crypto::toHex(PartyUInfo).c_str());
	printf("PartyVInfo %s\n", Crypto::toHex(PartyVInfo).c_str());
#endif
	std::vector<uchar> otherInfo;
	otherInfo.insert(otherInfo.cend(), AlgorithmID.cbegin(), AlgorithmID.cend());
	otherInfo.insert(otherInfo.cend(), PartyUInfo.cbegin(), PartyUInfo.cend());
	otherInfo.insert(otherInfo.cend(), PartyVInfo.cbegin(), PartyVInfo.cend());
	return concatKDF(hashAlg, keyDataLen, z, otherInfo);
}

std::vector<uchar> Crypto::encrypt(const std::string &method, const Key &key, const std::vector<uchar> &data)
{
	const EVP_CIPHER *c = cipher(method);
	SCOPE(EVP_CIPHER_CTX, ctx, EVP_CIPHER_CTX_new());
	EVP_CipherInit(ctx.get(), c, key.key.data(), key.iv.data(), 1);
	int size = 0;
	std::vector<uchar> result(data.size() + size_t(EVP_CIPHER_CTX_block_size(ctx.get())), 0);
	EVP_CipherUpdate(ctx.get(), result.data(), &size, data.data(), int(data.size()));
	int size2 = 0;
	EVP_CipherFinal(ctx.get(), &result[size_t(size)], &size2);
	result.resize(size_t(size + size2));
	result.insert(result.cbegin(), key.iv.cbegin(), key.iv.cend());
	if(EVP_CIPHER_mode(c) == EVP_CIPH_GCM_MODE)
	{
		std::vector<uchar> tag(16, 0);
		EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, int(tag.size()), tag.data());
		result.insert(result.cend(), tag.cbegin(), tag.cend());
#ifndef NDEBUG
		printf("GCM TAG %s\n", Crypto::toHex(tag).c_str());
#endif
	}
	return result;
}

std::vector<uchar> Crypto::decodeBase64(const uchar *data)
{
	std::vector<uchar> result(strlen((const char*)data), 0);
	EVP_ENCODE_CTX ctx;
	EVP_DecodeInit(&ctx);
	int size1 = 0, size2 = 0;
	if(EVP_DecodeUpdate(&ctx, result.data(), &size1, data, int(result.size())) == -1)
	{
		result.clear();
		return result;
	}
	if(EVP_DecodeFinal(&ctx, result.data(), &size2) == 1)
		result.resize(size_t(size1 + size2));
	else
		result.clear();
	return result;
}

std::vector<uchar> Crypto::deriveSharedSecret(EVP_PKEY *pkey, EVP_PKEY *peerPKey)
{
	std::vector<uchar> sharedSecret;
	size_t sharedSecretLen = 0;
	SCOPE(EVP_PKEY_CTX, ctx, EVP_PKEY_CTX_new(pkey, nullptr));
	if(!ctx ||
		EVP_PKEY_derive_init(ctx.get()) <= 0 ||
		EVP_PKEY_derive_set_peer(ctx.get(), peerPKey) <= 0 ||
		EVP_PKEY_derive(ctx.get(), nullptr, &sharedSecretLen) <= 0)
		return sharedSecret;
	sharedSecret.resize(sharedSecretLen);
	if(EVP_PKEY_derive(ctx.get(), sharedSecret.data(), &sharedSecretLen) <= 0)
		sharedSecret.clear();
	return sharedSecret;
}

Crypto::Key Crypto::generateKey(const std::string &method)
{
	const EVP_CIPHER *c = cipher(method);
#ifdef WIN32
	RAND_screen();
#else
	RAND_load_file("/dev/urandom", 1024);
#endif
	Key key = {
		std::vector<uchar>(size_t(EVP_CIPHER_key_length(c)), 0),
		std::vector<uchar>(size_t(EVP_CIPHER_iv_length(c)), 0)
	};
	uchar salt[PKCS5_SALT_LEN], indata[128];
	RAND_bytes(salt, sizeof(salt));
	RAND_bytes(indata, sizeof(indata));
	EVP_BytesToKey(c, EVP_sha256(), salt, indata, sizeof(indata), 1, key.key.data(), key.iv.data());
	return key;
}

uint32_t Crypto::keySize(const std::string &algo)
{
	if(algo == KWAES128_MTH) return 16;
	if(algo == KWAES192_MTH) return 24;
	if(algo == KWAES256_MTH) return 32;
	return 0;
}

std::string Crypto::toBase64(const std::vector<uchar> &data)
{
	std::string result(((data.size() + 2) / 3) * 4, 0);
	int size = EVP_EncodeBlock((uchar*)&result[0], data.data(), int(data.size()));
	result.resize(size_t(size));
	return result;
}

X509* Crypto::toX509(const std::vector<uchar> &data)
{
	const uchar *p = data.data();
	return d2i_X509(nullptr, &p, int(data.size()));
}
