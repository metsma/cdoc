#include "CDOCWriter.h"
#include "CDOCReader.h"
#include "Crypto.h"
#include "Token.h"

#include <fstream>
#include <iostream>

int main(int argc, char *argv[])
{
	if(argc == 4 && strcmp(argv[1], "encrypt") == 0)
	{
		std::ifstream f(argv[2]);

		f.seekg(0, std::ifstream::end);
		std::vector<unsigned char> recipient(size_t(f.tellg()), 0);
		f.clear();
		f.seekg(0);
		f.read((char*)recipient.data(), recipient.size());
		f.close();

		CDOCWriter w(argv[3], Crypto::AES256GCM_MTH);
		w.addRecipient(recipient);
		w.encryptData("test.txt", {0x30, 0x31, 0x32, 0x33, 0x34});
	}
	else if(argc == 6 && strcmp(argv[1], "decrypt") == 0)
	{
		std::unique_ptr<Token> token;
		if (strcmp(argv[2], "pkcs11") == 0)
			token.reset(new PKCS11Token(argv[3], argv[4]));
		else if (strcmp(argv[2], "pkcs12") == 0)
			token.reset(new PKCS12Token(argv[3], argv[4]));
		CDOCReader r(argv[5]);
		std::vector<unsigned char> data = r.decryptData(token.get());
		std::cout << std::string(data.cbegin(), data.cend());
	}
	else
	{
		printf("cdoc encrypt X509DerRecipientCert OutFile");
		printf("cdoc decrypt pkcs11 path/to/so pin InFile");
		printf("cdoc decrypt pkcs12 path/to/pkcs12 pin InFile");
	}

	return 0;
}
