#include "CDOCReader.h"

#include "Crypto.h"
#include "Token.h"

#include <libxml/xmlreader.h>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <map>

typedef xmlChar *pxmlChar;
typedef const xmlChar *pcxmlChar;

class CDOCReader::CDOCReaderPrivate
{
public:
	std::string file, mime, method;
	std::vector<Key> keys;
	std::vector<File> files;
	std::map<std::string,std::string> properties;
};

CDOCReader::CDOCReader(const std::string &file)
	: d(new CDOCReaderPrivate)
{
	d->file = file;
	auto iselement = [](const xmlChar *name, const char *elem) {
		return xmlStrEqual(name, pcxmlChar(elem)) == 1;
	};
	auto tostring = [](const xmlChar *tmp) {
		std::string result;
		if(!tmp)
			return result;
		result = (const char*)tmp;
		return result;
	};
	auto attribute = [&](xmlTextReaderPtr reader, const char *attr){
		xmlChar *tmp = xmlTextReaderGetAttribute(reader, pcxmlChar(attr));
		std::string result = tostring(tmp);
		xmlFree(tmp);
		return result;
	};

	auto hex2bin = [](const std::string &in) {
		std::vector<uchar> out;
		char data[] = "00";
		for(std::string::const_iterator i = in.cbegin(); distance(i, in.cend()) >= 2;)
		{
			data[0] = *(i++);
			data[1] = *(i++);
			out.push_back(static_cast<uchar>(strtoul(data, 0, 16)));
		}
		return out;
	};

	xmlTextReaderPtr reader = xmlNewTextReaderFilename(file.c_str());
	int ret = 0;
	while ((ret = xmlTextReaderRead(reader)) == 1) {
		const xmlChar *name = xmlTextReaderConstLocalName(reader);
		if(xmlTextReaderNodeType(reader) == XML_READER_TYPE_END_ELEMENT)
			continue;
		// EncryptedData
		else if(iselement(name, "EncryptedData"))
			d->mime = attribute(reader, "MimeType");
		// EncryptedData/EncryptionMethod
		else if(iselement(name, "EncryptionMethod"))
			d->method = attribute(reader, "Algorithm");
		// EncryptedData/EncryptionProperties/EncryptionProperty
		else if(iselement(name, "EncryptionProperty"))
		{
			std::string attr = attribute(reader, "Name");
			ret = xmlTextReaderRead(reader);
			std::string value = tostring(xmlTextReaderConstValue(reader));
			if(attr == "orig_file")
			{
				File file;
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
		else if(iselement(name, "EncryptedKey"))
		{
			Key key;
			key.id = attribute(reader, "Id");
			key.recipient = attribute(reader, "Recipient");
			while((ret = xmlTextReaderRead(reader)) == 1)
			{
				const xmlChar *name = xmlTextReaderConstLocalName(reader);
				if(iselement(name, "EncryptedKey") && xmlTextReaderNodeType(reader) == XML_READER_TYPE_END_ELEMENT)
					break;
				else if(xmlTextReaderNodeType(reader) == XML_READER_TYPE_END_ELEMENT)
					continue;
				// EncryptedData/KeyInfo/KeyName
				if(iselement(name, "KeyName"))
				{
					ret = xmlTextReaderRead(reader);
					key.name = tostring(xmlTextReaderConstValue(reader));
				}
				// EncryptedData/KeyInfo/EncryptedKey/EncryptionMethod
				else if(iselement(name, "EncryptionMethod"))
					key.method = attribute(reader, "Algorithm");
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/AgreementMethod
				else if(iselement(name, "AgreementMethod"))
					key.agreement = attribute(reader, "Algorithm");
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/AgreementMethod/KeyDerivationMethod
				else if(iselement(name, "KeyDerivationMethod"))
					key.derive = attribute(reader, "Algorithm");
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/AgreementMethod/KeyDerivationMethod/ConcatKDFParams
				else if(iselement(name, "ConcatKDFParams"))
				{
					key.AlgorithmID = hex2bin(attribute(reader, "AlgorithmID"));
					key.PartyUInfo = hex2bin(attribute(reader, "PartyUInfo"));
					key.PartyVInfo = hex2bin(attribute(reader, "PartyVInfo"));
					if(key.AlgorithmID[0] == 0x00) key.AlgorithmID.erase(key.AlgorithmID.cbegin());
					if(key.PartyUInfo[0] == 0x00) key.PartyUInfo.erase(key.PartyUInfo.cbegin());
					if(key.PartyVInfo[0] == 0x00) key.PartyVInfo.erase(key.PartyVInfo.cbegin());
				}
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/AgreementMethod/KeyDerivationMethod/ConcatKDFParams/DigestMethod
				else if(iselement(name, "DigestMethod"))
					key.concatDigest = attribute(reader, "Algorithm");
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/AgreementMethod/OriginatorKeyInfo/KeyValue/ECKeyValue/PublicKey
				else if(iselement(name, "PublicKey"))
				{
					ret = xmlTextReaderRead(reader);
					key.publicKey = Crypto::decodeBase64(xmlTextReaderConstValue(reader));
				}
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/X509Data/X509Certificate
				else if(iselement(name, "X509Certificate"))
				{
					ret = xmlTextReaderRead(reader);
					key.cert = Crypto::decodeBase64(xmlTextReaderConstValue(reader));
				}
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/CipherData/CipherValue
				else if(iselement(name, "CipherValue"))
				{
					ret = xmlTextReaderRead(reader);
					key.cipher = Crypto::decodeBase64(xmlTextReaderConstValue(reader));
				}
			}
			d->keys.push_back(key);
		}
	}
	xmlFreeTextReader(reader);
}

CDOCReader::~CDOCReader()
{
	delete d;
}

std::vector<CDOCReader::Key> CDOCReader::keys() const
{
	return d->keys;
}

std::vector<uchar> CDOCReader::decryptData(const std::vector<uchar> &key)
{
	auto iselement = [](const xmlChar *name, const char *elem) {
		return xmlStrEqual(name, pcxmlChar(elem)) == 1;
	};
	xmlTextReaderPtr reader = xmlNewTextReaderFilename(d->file.c_str());
	const xmlChar *base64 = nullptr;
	int ret = 0;
	int skipKeyInfo = 0;
	while ((ret = xmlTextReaderRead(reader)) == 1) {
		const xmlChar *name = xmlTextReaderConstLocalName(reader);
		// EncryptedData/KeyInfo
		if(iselement(name, "KeyInfo") && xmlTextReaderNodeType(reader) == XML_READER_TYPE_END_ELEMENT)
			--skipKeyInfo;
		else if(iselement(name, "KeyInfo"))
			++skipKeyInfo;
		else if(skipKeyInfo > 0)
			continue;
		// EncryptedData/CipherData/CipherValue
		else if(iselement(name, "CipherValue"))
		{
			ret = xmlTextReaderRead(reader);
			base64 = xmlTextReaderConstValue(reader);
			break;
		}
	}

	std::vector<uchar> result;
	if(!base64)
	{
		xmlFreeTextReader(reader);
		return result;
	}

	std::vector<uchar> data = Crypto::decodeBase64(base64);
	xmlFreeTextReader(reader);

	const EVP_CIPHER *cipher = Crypto::cipher(d->method);
	std::vector<uchar> iv(data.cbegin(), data.cbegin() + EVP_CIPHER_iv_length(cipher));
	data.erase(data.cbegin(), data.cbegin() + iv.size());

	SCOPE(EVP_CIPHER_CTX, ctx, EVP_CIPHER_CTX_new());
	int err = EVP_CipherInit(ctx.get(), cipher, key.data(), iv.data(), 0);

	if(EVP_CIPHER_mode(cipher) == EVP_CIPH_GCM_MODE)
	{
		std::vector<uchar> tag(data.cend() - 16, data.cend());
		EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, int(tag.size()), tag.data());
		data.resize(data.size() - tag.size());
	}

	int size = 0;
	result.resize(data.size() + size_t(EVP_CIPHER_CTX_block_size(ctx.get())));
	err = EVP_CipherUpdate(ctx.get(), result.data(), &size, data.data(), int(data.size()));

	int size2 = 0;
	err = EVP_CipherFinal(ctx.get(), result.data() + size, &size2);
	result.resize(size_t(size + size2));
	return result;
}

std::vector<uchar> CDOCReader::decryptData(Token *token)
{
	Key k;
	for(const Key &key: d->keys)
		if(key.cert == token->cert())
			k = key;
	if(k.cert.empty())
		return std::vector<uchar>();
	const uchar *p = k.cert.data();
	SCOPE(X509, x509, d2i_X509(nullptr, &p, int(k.cert.size())));
	SCOPE(EVP_PKEY, key, X509_get_pubkey(x509.get()));
	switch(EVP_PKEY_base_id(key.get()))
	{
	case EVP_PKEY_EC:
	{
		std::vector<uchar> sharedSecret = token->derive(k.publicKey);
		std::vector<uchar> derived = Crypto::concatKDF(k.concatDigest, Crypto::keySize(k.method), sharedSecret, k.AlgorithmID, k.PartyUInfo, k.PartyVInfo);
		std::vector<uchar> transport = Crypto::AESDecWrap(derived, k.cipher);
		return decryptData(transport);
	}
	case EVP_PKEY_RSA:
	{
		std::vector<uchar> transport = token->decrypt(k.cipher);
		return decryptData(transport);
	}
	default: return std::vector<uchar>();
	}
}
