#include "CDOCWriter.h"
#include "CDOCReader.h"
#include "Crypto.h"
#include "Token.h"

#include <fstream>

int main(int argc, char *argv[])
{
	if (argc != 4)
	{
		printf("cdoc [encrypt|decrypt] Recipient File");
		return 0;
	}

	if(strcmp(argv[1], "decrypt") == 0)
	{
		CDOCReader r("cipherText__EC-P256__aes128-gcm__kw-aes128__ECDH-ES__ConcatKDF.xml");
		PKCS12Token t("EC-P256_SHA256WithECDSA.p12");
		//PKCS11Token t("/usr/local/lib/opensc-pkcs11.so");
		CDOCReader::Key k = r.keys().at(0);
		std::vector<uchar> sharedSecret = t.derive(k.cert, "passwd", k.publicKey); // , "signerEC"
		std::vector<uchar> derived = Crypto::concatKDF(k.concatDigest, Crypto::keySize(k.method), sharedSecret, k.AlgorithmID, k.PartyUInfo, k.PartyVInfo);
		std::vector<uchar> transport = Crypto::AESDecWrap(derived, k.cipher);
		std::vector<unsigned char> data = r.decryptData(transport);
	}
	else if(strcmp(argv[1], "encrypt") == 0)
	{
		std::ifstream f(argv[2]);

		f.seekg(0, std::ifstream::end);
		std::vector<unsigned char> recipient(size_t(f.tellg()), 0);
		f.clear();
		f.seekg(0);
		f.read((char*)recipient.data(), recipient.size());
		f.close();

		CDOCWriter w(argv[2], Crypto::AES256GCM_MTH);
		w.addRecipient(recipient);
		w.encryptData("test.txt", {0x30, 0x31, 0x32, 0x33, 0x34});
	}
	return 0;
}
