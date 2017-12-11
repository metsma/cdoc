#include "CDOCWriter.h"

#include "Crypto.h"
#include "Writer.h"

#include <openssl/x509.h>

#include <iomanip>
#include <sstream>

/**
 * @class CDOCWriter
 * @brief CDOCWriter is used for encrypt data.
 */

struct CDOCWriter::CDOCWriterPrivate: public Writer
{
	CDOCWriterPrivate(const std::string &file): Writer(file) {}
	static const NS DENC, DS, XENC11, DSIG11;
	std::string method, documentFormat = "ENCDOC-XML|1.1";
	Crypto::Key transportKey;
};

const Writer::NS CDOCWriter::CDOCWriterPrivate::DENC{ "denc", "http://www.w3.org/2001/04/xmlenc#" };
const Writer::NS CDOCWriter::CDOCWriterPrivate::DS{ "ds", "http://www.w3.org/2000/09/xmldsig#" };
const Writer::NS CDOCWriter::CDOCWriterPrivate::XENC11{ "xenc11", "http://www.w3.org/2009/xmlenc11#" };
const Writer::NS CDOCWriter::CDOCWriterPrivate::DSIG11{ "dsig11", "http://www.w3.org/2009/xmldsig11#" };



/**
 * CDOCWriter constructor.
 * @param file File to be created
 * @param method Encrypton method to be used
 */
CDOCWriter::CDOCWriter(const std::string &file, const std::string &method)
	: d(new CDOCWriterPrivate(file))
{
	d->transportKey = Crypto::generateKey(d->method = method);
	d->writeStartElement(d->DENC, "EncryptedData", {{"MimeType", "application/octet-stream"}});
	d->writeElement(d->DENC, "EncryptionMethod", {{"Algorithm", method}});
	d->writeStartElement(d->DS, "KeyInfo", {});
}

CDOCWriter::~CDOCWriter()
{
	delete d;
}

/**
 * Add X509 certificate recipient
 * @param recipient DER certificate to encrypted for
 */
void CDOCWriter::addRecipient(const std::vector<uchar> &recipient)
{
	const uchar *p = recipient.data();
	SCOPE(X509, peerCert, d2i_X509(nullptr, &p, int(recipient.size())));

	X509_NAME *name = X509_get_subject_name(peerCert.get());
	int pos = X509_NAME_get_index_by_NID(name, NID_commonName, 0);
	X509_NAME_ENTRY *e = X509_NAME_get_entry(name, pos);
	char *data = nullptr;
	int size = ASN1_STRING_to_UTF8((uchar**)&data, X509_NAME_ENTRY_get_data(e));
	std::string cn(data, size_t(size));
	OPENSSL_free(data);

	d->writeElement(d->DENC, "EncryptedKey", {{"Recipient", cn}}, [&]{
		std::vector<uchar> encryptedData;
		SCOPE(EVP_PKEY, peerPKey, X509_get_pubkey(peerCert.get()));
		switch(EVP_PKEY_base_id(peerPKey.get()))
		{
		case EVP_PKEY_RSA:
		{
			SCOPE(RSA, rsa, EVP_PKEY_get1_RSA(peerPKey.get()));
			encryptedData.resize(size_t(RSA_size(rsa.get())));
			RSA_public_encrypt(int(d->transportKey.key.size()), d->transportKey.key.data(),
				encryptedData.data(), rsa.get(), RSA_PKCS1_PADDING);
			d->writeElement(d->DENC, "EncryptionMethod", {{"Algorithm", Crypto::RSA_MTH}});
			d->writeElement(d->DS, "KeyInfo", [&]{
				d->writeElement(d->DS, "X509Data", [&]{
					d->writeBase64Element(d->DS, "X509Certificate", recipient);
				});
			});
			break;
		}
		case EVP_PKEY_EC:
		{
			SCOPE(EC_KEY, peerECKey, EVP_PKEY_get1_EC_KEY(peerPKey.get()));
			int curveName = EC_GROUP_get_curve_name(EC_KEY_get0_group(peerECKey.get()));
			SCOPE(EC_KEY, priv, EC_KEY_new_by_curve_name(curveName));
			EC_KEY_generate_key(priv.get());
			SCOPE(EVP_PKEY, pkey, EVP_PKEY_new());
			EVP_PKEY_set1_EC_KEY(pkey.get(), priv.get());
			std::vector<uchar> sharedSecret = Crypto::deriveSharedSecret(pkey.get(), peerPKey.get());

			std::string oid(50, 0);
			oid.resize(size_t(OBJ_obj2txt(&oid[0], int(oid.size()), OBJ_nid2obj(curveName), 1)));
			std::vector<uchar> SsDer(size_t(i2d_PublicKey(pkey.get(), nullptr)), 0);
			uchar *p = SsDer.data();
			i2d_PublicKey(pkey.get(), &p);

			std::string encryptionMethod = Crypto::KWAES256_MTH;
			std::string concatDigest = Crypto::SHA384_MTH;
			switch ((SsDer.size() - 1) / 2) {
			case 32: concatDigest = Crypto::SHA256_MTH; break;
			case 48: concatDigest = Crypto::SHA384_MTH; break;
			default: concatDigest = Crypto::SHA512_MTH; break;
			}

			std::vector<uchar> AlgorithmID(d->documentFormat.cbegin(), d->documentFormat.cend());
			std::vector<uchar> encryptionKey = Crypto::concatKDF(concatDigest, Crypto::keySize(encryptionMethod), sharedSecret,
				AlgorithmID, SsDer, recipient);
			encryptedData = Crypto::AESWrap(encryptionKey, d->transportKey.key, true);

#ifndef NDEBUG
			printf("Ss %s\n", Crypto::toHex(SsDer).c_str());
			printf("Ksr %s\n", Crypto::toHex(sharedSecret).c_str());
			printf("Concat %s\n", Crypto::toHex(encryptionKey).c_str());
			printf("iv %s\n", Crypto::toHex(d->transportKey.iv).c_str());
			printf("transport %s\n", Crypto::toHex(d->transportKey.key).c_str());
#endif

			d->writeElement(d->DENC, "EncryptionMethod", {{"Algorithm", encryptionMethod}});
			d->writeElement(d->DS, "KeyInfo", [&]{
				d->writeElement(d->DENC, "AgreementMethod", {{"Algorithm", Crypto::AGREEMENT_MTH}}, [&]{
					d->writeElement(d->XENC11, "KeyDerivationMethod", {{"Algorithm", Crypto::CONCATKDF_MTH}}, [&]{
						d->writeElement(d->XENC11, "ConcatKDFParams", {
							{"AlgorithmID", "00" + Crypto::toHex(AlgorithmID)},
							{"PartyUInfo", "00" + Crypto::toHex(SsDer)},
							{"PartyVInfo", "00" + Crypto::toHex(recipient)}}, [&]{
							d->writeElement(d->DS, "DigestMethod", {{"Algorithm", concatDigest}});
						});
					});
					d->writeElement(d->DENC, "OriginatorKeyInfo", [&]{
						d->writeElement(d->DS, "KeyValue", [&]{
							d->writeElement(d->DSIG11, "ECKeyValue", [&]{
								d->writeElement(d->DSIG11, "NamedCurve", {{"URI", "urn:oid:" + oid}});
								d->writeBase64Element(d->DSIG11, "PublicKey", SsDer);
							});
						});
					});
					d->writeElement(d->DENC, "RecipientKeyInfo", [&]{
						d->writeElement(d->DS, "X509Data", [&]{
							d->writeBase64Element(d->DS, "X509Certificate", recipient);
						});
					});
				});
			 });
			d->writeElement(d->DENC, "CipherData", [&]{
				d->writeBase64Element(d->DENC, "CipherValue", encryptedData);
			});
			break;
		}
		default: break;
		}
	});
}

/**
 * Encrypt data
 * @param name Filename of encrypted data
 * @param data File content to be encrypted
 */
void CDOCWriter::encryptData(const std::string &name, const std::vector<uchar> &data)
{
	d->writeEndElement(d->DS); // KeyInfo

	const EVP_CIPHER *cipher = Crypto::cipher(d->method);
	SCOPE(EVP_CIPHER_CTX, ctx, EVP_CIPHER_CTX_new());
	EVP_CipherInit(ctx.get(), cipher, d->transportKey.key.data(), d->transportKey.iv.data(), 1);
	int size = 0;
	std::vector<uchar> result(data.size() + size_t(EVP_CIPHER_CTX_block_size(ctx.get())), 0);
	EVP_CipherUpdate(ctx.get(), result.data(), &size, data.data(), int(data.size()));
	int size2 = 0;
	EVP_CipherFinal(ctx.get(), &result[size_t(size)], &size2);
	result.resize(size_t(size + size2));
	result.insert(result.cbegin(), d->transportKey.iv.cbegin(), d->transportKey.iv.cend());
	if(EVP_CIPHER_mode(cipher) == EVP_CIPH_GCM_MODE)
	{
		std::vector<uchar> tag(16, 0);
		EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, int(tag.size()), tag.data());
		result.insert(result.cend(), tag.cbegin(), tag.cend());
	}

	d->writeElement(d->DENC, "CipherData", [&]{
		d->writeBase64Element(d->DENC, "CipherValue", result);
	});

	d->writeElement(d->DENC, "EncryptionProperties", [&]{
		d->writeTextElement(d->DENC, "EncryptionProperty", {{"Name", "LibraryVersion"}}, "cdoc|0.0.1");
		d->writeTextElement(d->DENC, "EncryptionProperty", {{"Name", "DocumentFormat"}}, d->documentFormat);
		d->writeTextElement(d->DENC, "EncryptionProperty", {{"Name", "Filename"}}, name);
		d->writeTextElement(d->DENC, "EncryptionProperty", {{"Name", "orig_file"}},
			name + "|" + std::to_string(data.size()) + "|application/octet-stream|D0");
	});

	d->writeEndElement(d->DENC); // EncryptedData
}
