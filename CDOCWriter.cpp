#include "CDOCWriter.h"

#include "Crypto.h"
#include "DDOCWriter.h"
#include "XMLWriter.h"

#include <openssl/x509.h>

/**
 * @class CDOCWriter
 * @brief CDOCWriter is used for encrypt data.
 */

struct CDOCWriter::Private: public XMLWriter
{
	Private(const std::string &file): XMLWriter(file) {}
	static const NS DENC, DS, XENC11, DSIG11;
	std::string method, documentFormat = "ENCDOC-XML|1.1";
	Crypto::Key transportKey;
	struct File
	{
		std::string filename, mime;
		std::vector<uchar> data;
	};
	std::vector<File> files;
	std::vector<std::vector<uchar>> recipients;
	void writeRecipient(const std::vector<uchar> &recipient);
};

const XMLWriter::NS CDOCWriter::Private::DENC{ "denc", "http://www.w3.org/2001/04/xmlenc#" };
const XMLWriter::NS CDOCWriter::Private::DS{ "ds", "http://www.w3.org/2000/09/xmldsig#" };
const XMLWriter::NS CDOCWriter::Private::XENC11{ "xenc11", "http://www.w3.org/2009/xmlenc11#" };
const XMLWriter::NS CDOCWriter::Private::DSIG11{ "dsig11", "http://www.w3.org/2009/xmldsig11#" };



/**
 * CDOCWriter constructor.
 * @param file File to be created
 * @param method Encrypton method to be used
 */
CDOCWriter::CDOCWriter(const std::string &file, const std::string &method)
	: d(new Private(file))
{
	d->transportKey = Crypto::generateKey(d->method = method);
}

CDOCWriter::~CDOCWriter()
{
	delete d;
}

/**
 * @param filename Filename of encrypted file
 * @param mime Mime type of encrypted file
 * @param data Content of encrypted file
 */
void CDOCWriter::addFile(const std::string &filename,
	const std::string &mime, const std::vector<uchar> &data)
{
	d->files.push_back({filename, mime, data});
}

/**
 * Add X509 certificate recipient
 * @param recipient DER certificate to encrypted for
 */
void CDOCWriter::addRecipient(const std::vector<uchar> &recipient)
{
	d->recipients.push_back(recipient);
}

void CDOCWriter::Private::writeRecipient(const std::vector<uchar> &recipient)
{
	SCOPE(X509, peerCert, Crypto::toX509(recipient));
	X509_NAME *name = X509_get_subject_name(peerCert.get());
	int pos = X509_NAME_get_index_by_NID(name, NID_commonName, 0);
	X509_NAME_ENTRY *e = X509_NAME_get_entry(name, pos);
	char *data = nullptr;
	int size = ASN1_STRING_to_UTF8((uchar**)&data, X509_NAME_ENTRY_get_data(e));
	std::string cn(data, size_t(size));
	OPENSSL_free(data);

	writeElement(Private::DENC, "EncryptedKey", {{"Recipient", cn}}, [&]{
		std::vector<uchar> encryptedData;
		SCOPE(EVP_PKEY, peerPKey, X509_get_pubkey(peerCert.get()));
		switch(EVP_PKEY_base_id(peerPKey.get()))
		{
		case EVP_PKEY_RSA:
		{
			SCOPE(RSA, rsa, EVP_PKEY_get1_RSA(peerPKey.get()));
			encryptedData.resize(size_t(RSA_size(rsa.get())));
			RSA_public_encrypt(int(transportKey.key.size()), transportKey.key.data(),
				encryptedData.data(), rsa.get(), RSA_PKCS1_PADDING);
			writeElement(Private::DENC, "EncryptionMethod", {{"Algorithm", Crypto::RSA_MTH}});
			writeElement(Private::DS, "KeyInfo", [&]{
				writeElement(Private::DS, "X509Data", [&]{
					writeBase64Element(Private::DS, "X509Certificate", recipient);
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

			std::vector<uchar> AlgorithmID(documentFormat.cbegin(), documentFormat.cend());
			std::vector<uchar> encryptionKey = Crypto::concatKDF(concatDigest, Crypto::keySize(encryptionMethod), sharedSecret,
				AlgorithmID, SsDer, recipient);
			encryptedData = Crypto::AESWrap(encryptionKey, transportKey.key, true);

#ifndef NDEBUG
			printf("Ss %s\n", Crypto::toHex(SsDer).c_str());
			printf("Ksr %s\n", Crypto::toHex(sharedSecret).c_str());
			printf("ConcatKDF %s\n", Crypto::toHex(encryptionKey).c_str());
			printf("iv %s\n", Crypto::toHex(transportKey.iv).c_str());
			printf("transport %s\n", Crypto::toHex(transportKey.key).c_str());
#endif

			writeElement(Private::DENC, "EncryptionMethod", {{"Algorithm", encryptionMethod}});
			writeElement(Private::DS, "KeyInfo", [&]{
				writeElement(Private::DENC, "AgreementMethod", {{"Algorithm", Crypto::AGREEMENT_MTH}}, [&]{
					writeElement(Private::XENC11, "KeyDerivationMethod", {{"Algorithm", Crypto::CONCATKDF_MTH}}, [&]{
						writeElement(Private::XENC11, "ConcatKDFParams", {
							{"AlgorithmID", "00" + Crypto::toHex(AlgorithmID)},
							{"PartyUInfo", "00" + Crypto::toHex(SsDer)},
							{"PartyVInfo", "00" + Crypto::toHex(recipient)}}, [&]{
							writeElement(Private::DS, "DigestMethod", {{"Algorithm", concatDigest}});
						});
					});
					writeElement(Private::DENC, "OriginatorKeyInfo", [&]{
						writeElement(Private::DS, "KeyValue", [&]{
							writeElement(Private::DSIG11, "ECKeyValue", [&]{
								writeElement(Private::DSIG11, "NamedCurve", {{"URI", "urn:oid:" + oid}});
								writeBase64Element(Private::DSIG11, "PublicKey", SsDer);
							});
						});
					});
					writeElement(Private::DENC, "RecipientKeyInfo", [&]{
						writeElement(Private::DS, "X509Data", [&]{
							writeBase64Element(Private::DS, "X509Certificate", recipient);
						});
					});
				});
			 });
			break;
		}
		default: break;
		}
		writeElement(Private::DENC, "CipherData", [&]{
			writeBase64Element(Private::DENC, "CipherValue", encryptedData);
		});
	});
}

/**
 * Encrypt data
 */
void CDOCWriter::encrypt()
{
	d->writeStartElement(Private::DENC, "EncryptedData", {{"MimeType", d->files.size() > 1 ? "http://www.sk.ee/DigiDoc/v1.3.0/digidoc.xsd" : "application/octet-stream"}});
	d->writeElement(Private::DENC, "EncryptionMethod", {{"Algorithm", d->method}});
	d->writeStartElement(Private::DS, "KeyInfo", {});
	for(const std::vector<uchar> &recipient: d->recipients)
		d->writeRecipient(recipient);
	d->writeEndElement(Private::DS); // KeyInfo

	std::vector<uchar> data;
	d->writeElement(Private::DENC, "CipherData", [&]{
		if(d->files.size() > 1)
		{
			DDOCWriter ddoc("");
			for(const Private::File &file: d->files)
				ddoc.addFile(file.filename, file.mime, file.data);
			ddoc.close();
			d->writeBase64Element(Private::DENC, "CipherValue", Crypto::encrypt(d->method, d->transportKey, ddoc.data()));
		}
		else
			d->writeBase64Element(Private::DENC, "CipherValue", Crypto::encrypt(d->method, d->transportKey, d->files.at(0).data));
	});
	d->writeElement(Private::DENC, "EncryptionProperties", [&]{
		d->writeTextElement(Private::DENC, "EncryptionProperty", {{"Name", "LibraryVersion"}}, "cdoc|0.0.1");
		d->writeTextElement(Private::DENC, "EncryptionProperty", {{"Name", "DocumentFormat"}}, d->documentFormat);
		d->writeTextElement(Private::DENC, "EncryptionProperty", {{"Name", "Filename"}}, "tmp.ddoc");
		for(const Private::File &file: d->files)
		{
			d->writeTextElement(Private::DENC, "EncryptionProperty", {{"Name", "orig_file"}},
				file.filename + "|" + std::to_string(file.data.size()) + "|" + file.mime + "|D0");
		}
	});
	d->writeEndElement(Private::DENC); // EncryptedData
}
