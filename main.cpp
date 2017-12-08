#include "CDOCWriter.h"
#include "CDOCReader.h"
#include "Crypto.h"
#include "Token.h"

#include <iostream>
#include <fstream>

static std::vector<unsigned char> readFile(const std::string &path)
{
	std::ifstream f(path);
	f.seekg(0, std::ifstream::end);
	std::vector<unsigned char> data(size_t(f.tellg()), 0);
	f.clear();
	f.seekg(0);
	f.read((char*)data.data(), data.size());
	return data;
}

int main(int argc, char *argv[])
{
	if(argc == 5 && strcmp(argv[1], "encrypt") == 0)
	{
		CDOCWriter w(argv[4], "http://www.w3.org/2009/xmlenc11#aes256-gcm");
		w.addRecipient(readFile(argv[2]));
		std::string inFile = argv[3];
		size_t pos = inFile.find_last_of("/\\");
		w.encryptData(pos == std::string::npos ? inFile : inFile.substr(pos + 1), readFile(inFile));
	}
	else if(argc == 7 && strcmp(argv[1], "decrypt") == 0)
	{
		std::unique_ptr<Token> token;
		if (strcmp(argv[2], "pkcs11") == 0)
			token.reset(new PKCS11Token(argv[3], argv[4]));
		else if (strcmp(argv[2], "pkcs12") == 0)
			token.reset(new PKCS12Token(argv[3], argv[4]));
		CDOCReader r(argv[5]);
		std::ofstream f(argv[6]);
		std::vector<unsigned char> data = r.decryptData(token.get());
		f.write((const char*)data.data(), data.size());
	}
	else
	{
		std::cout
			<< "cdoc encrypt X509DerRecipientCert InFile OutFile" << std::endl
			<< "cdoc decrypt pkcs11 path/to/so pin InFile OutFile" << std::endl
			<< "cdoc decrypt pkcs12 path/to/pkcs12 pin InFile OutFile" << std::endl;
	}
	return 0;
}
