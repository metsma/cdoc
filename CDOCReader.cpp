#include "CDOCReader.h"

#include "Crypto.h"
#include "Token.h"
#include "XMLReader.h"

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <map>

/**
 * @class CDOCReader
 * @brief CDOCReader is used for decrypt data.
 */

class CDOCReader::Private
{
public:
	struct Key
	{
		std::string id, recipient, name;
		std::string method, agreement, derive, concatDigest;
		std::vector<uchar> cert, publicKey, cipher;
		std::vector<uchar> AlgorithmID, PartyUInfo, PartyVInfo;
	};
	struct File
	{
		std::string name, size, mime, id;
	};

	std::string file, mime, method;
	std::vector<Key> keys;
	std::vector<File> files;
	std::map<std::string,std::string> properties;
};

/**
 * CDOCReader constructor.
 * @param file File to open reading
 */
CDOCReader::CDOCReader(const std::string &file)
	: d(new Private)
{
	d->file = file;
	auto hex2bin = [](const std::string &in) {
		std::vector<uchar> out;
		char data[] = "00";
		for(std::string::const_iterator i = in.cbegin(); distance(i, in.cend()) >= 2;)
		{
			data[0] = *(i++);
			data[1] = *(i++);
			out.push_back(static_cast<uchar>(strtoul(data, 0, 16)));
		}
		if(out[0] == 0x00)
			out.erase(out.cbegin());
		return out;
	};

	XMLReader reader(file);
	while (reader.read()) {
		if(reader.isEndElement())
			continue;
		// EncryptedData
		else if(reader.isElement("EncryptedData"))
			d->mime = reader.attribute("MimeType");
		// EncryptedData/EncryptionMethod
		else if(reader.isElement("EncryptionMethod"))
			d->method = reader.attribute("Algorithm");
		// EncryptedData/EncryptionProperties/EncryptionProperty
		else if(reader.isElement("EncryptionProperty"))
		{
			std::string attr = reader.attribute("Name");
			std::string value = reader.readText();
			if(attr == "orig_file")
			{
				Private::File file;
				size_t pos = 0, oldpos = 0;
				file.name = value.substr(oldpos, (pos = value.find("|", oldpos)) - oldpos);
				oldpos = pos + 1;
				file.size = value.substr(oldpos, (pos = value.find("|", oldpos)) - oldpos);
				oldpos = pos + 1;
				file.mime = value.substr(oldpos, (pos = value.find("|", oldpos)) - oldpos);
				oldpos = pos + 1;
				file.id = value.substr(oldpos, (pos = value.find("|", oldpos)) - oldpos);
				d->files.push_back(file);
			}
			else
				d->properties[attr] = value;
		}
		// EncryptedData/KeyInfo/EncryptedKey
		else if(reader.isElement("EncryptedKey"))
		{
			Private::Key key;
			key.id = reader.attribute("Id");
			key.recipient = reader.attribute("Recipient");
			while(reader.read())
			{
				if(reader.isElement("EncryptedKey") && reader.isEndElement())
					break;
				else if(reader.isEndElement())
					continue;
				// EncryptedData/KeyInfo/KeyName
				if(reader.isElement("KeyName"))
					key.name = reader.readText();
				// EncryptedData/KeyInfo/EncryptedKey/EncryptionMethod
				else if(reader.isElement("EncryptionMethod"))
					key.method = reader.attribute("Algorithm");
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/AgreementMethod
				else if(reader.isElement("AgreementMethod"))
					key.agreement = reader.attribute("Algorithm");
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/AgreementMethod/KeyDerivationMethod
				else if(reader.isElement("KeyDerivationMethod"))
					key.derive = reader.attribute("Algorithm");
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/AgreementMethod/KeyDerivationMethod/ConcatKDFParams
				else if(reader.isElement("ConcatKDFParams"))
				{
					key.AlgorithmID = hex2bin(reader.attribute("AlgorithmID"));
					key.PartyUInfo = hex2bin(reader.attribute("PartyUInfo"));
					key.PartyVInfo = hex2bin(reader.attribute("PartyVInfo"));
				}
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/AgreementMethod/KeyDerivationMethod/ConcatKDFParams/DigestMethod
				else if(reader.isElement("DigestMethod"))
					key.concatDigest = reader.attribute("Algorithm");
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/AgreementMethod/OriginatorKeyInfo/KeyValue/ECKeyValue/PublicKey
				else if(reader.isElement("PublicKey"))
					key.publicKey = reader.readBase64();
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/X509Data/X509Certificate
				else if(reader.isElement("X509Certificate"))
					key.cert = reader.readBase64();
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/CipherData/CipherValue
				else if(reader.isElement("CipherValue"))
					key.cipher = reader.readBase64();
			}
			d->keys.push_back(key);
		}
	}
}

CDOCReader::~CDOCReader()
{
	delete d;
}

/**
 * Returns decrypted mime type
 */
std::string CDOCReader::mimeType() const
{
	return d->mime;
}

/**
 * Returns decrypted filename
 */
std::string CDOCReader::fileName() const
{
	return d->properties["Filename"];
}

/**
 * Returns decrypted data
 * @param key Transport key to used for decrypt data
 */
std::vector<uchar> CDOCReader::decryptData(const std::vector<uchar> &key)
{
	XMLReader reader(d->file);
	std::vector<uchar> data;
	int skipKeyInfo = 0;
	while (reader.read()) {
		// EncryptedData/KeyInfo
		if(reader.isElement("KeyInfo") && reader.isEndElement())
			--skipKeyInfo;
		else if(reader.isElement("KeyInfo"))
			++skipKeyInfo;
		else if(skipKeyInfo > 0)
			continue;
		// EncryptedData/CipherData/CipherValue
		else if(reader.isElement("CipherValue"))
		{
			data = reader.readBase64();
			break;
		}
	}

	std::vector<uchar> result;
	if(data.empty())
		return result;

	const EVP_CIPHER *cipher = Crypto::cipher(d->method);
	std::vector<uchar> iv(data.cbegin(), data.cbegin() + EVP_CIPHER_iv_length(cipher));
	data.erase(data.cbegin(), data.cbegin() + iv.size());

#ifndef NDEBUG
	printf("iv %s\n", Crypto::toHex(iv).c_str());
	printf("transport %s\n", Crypto::toHex(key).c_str());
#endif

	SCOPE(EVP_CIPHER_CTX, ctx, EVP_CIPHER_CTX_new());
	int err = EVP_CipherInit(ctx.get(), cipher, key.data(), iv.data(), 0);

	if(EVP_CIPHER_mode(cipher) == EVP_CIPH_GCM_MODE)
	{
		std::vector<uchar> tag(data.cend() - 16, data.cend());
		EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, int(tag.size()), tag.data());
		data.resize(data.size() - tag.size());
#ifndef NDEBUG
		printf("GCM TAG %s\n", Crypto::toHex(tag).c_str());
#endif
	}

	int size = 0;
	result.resize(data.size() + size_t(EVP_CIPHER_CTX_block_size(ctx.get())));
	err = EVP_CipherUpdate(ctx.get(), result.data(), &size, data.data(), int(data.size()));

	int size2 = 0;
	err = EVP_CipherFinal(ctx.get(), result.data() + size, &size2);
	result.resize(size_t(size + size2));
	return result;
}

/**
 * Returns decrypted data
 * @param token Token to be used for decrypting data
 */
std::vector<uchar> CDOCReader::decryptData(Token *token)
{
	Private::Key k;
	std::vector<uchar> cert = token->cert();
	for(const Private::Key &key: d->keys)
		if(key.cert == cert)
			k = key;
	if(k.cert.empty())
		return std::vector<uchar>();
	SCOPE(X509, x509, Crypto::toX509(k.cert));
	SCOPE(EVP_PKEY, key, X509_get_pubkey(x509.get()));
	switch(EVP_PKEY_base_id(key.get()))
	{
	case EVP_PKEY_EC:
	{
		std::vector<uchar> derived = token->deriveConcatKDF(k.publicKey, k.concatDigest,
			Crypto::keySize(k.method), k.AlgorithmID, k.PartyUInfo, k.PartyVInfo);
#ifndef NDEBUG
		printf("Ss %s\n", Crypto::toHex(k.publicKey).c_str());
		printf("ConcatKDF %s\n", Crypto::toHex(derived).c_str());
#endif
		return decryptData(Crypto::AESWrap(derived, k.cipher, false));
	}
	case EVP_PKEY_RSA:
		return decryptData(token->decrypt(k.cipher));
	default:
		return std::vector<uchar>();
	}
}
