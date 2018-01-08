#include "CDOCWriter.h"
#include "CDOCReader.h"
#include "Crypto.h"
#include "Token.h"
#include "DDOCReader.h"

#include <cstring>
#include <iostream>
#include <fstream>

static std::vector<unsigned char> readFile(const std::string &path)
{
	std::ifstream f(path, std::ifstream::binary);
	f.seekg(0, std::ifstream::end);
	std::vector<unsigned char> data(size_t(f.tellg()), 0);
	f.clear();
	f.seekg(0);
	f.read((char*)data.data(), std::streamsize(data.size()));
	return data;
}

int main(int argc, char *argv[])
{
	if(argc >= 5 && strcmp(argv[1], "encrypt") == 0)
	{
		CDOCWriter w(argv[argc-1], "http://www.w3.org/2009/xmlenc11#aes256-gcm");
		for(int i = 3; i < argc - 1; ++i)
		{
			std::string inFile = argv[i];
			size_t pos = inFile.find_last_of("/\\");
			w.addFile(pos == std::string::npos ? inFile : inFile.substr(pos + 1), "application/octet-stream", readFile(inFile));
		}
		w.addRecipient(readFile(argv[2]));
		w.encrypt();
	}
	else if(argc == 7 && strcmp(argv[1], "decrypt") == 0)
	{
		std::unique_ptr<Token> token;
		if (strcmp(argv[2], "pkcs11") == 0)
			token.reset(new PKCS11Token(argv[3], argv[4]));
		else if (strcmp(argv[2], "pkcs12") == 0)
			token.reset(new PKCS12Token(argv[3], argv[4]));
#ifdef _WIN32
		else if (strcmp(argv[2], "win") == 0)
			token.reset(new WinToken(strcmp(argv[3], "ui") == 0, argv[4]));
#endif
		CDOCReader r(argv[5]);
		std::vector<unsigned char> data = r.decryptData(token.get());
		if(r.mimeType() == "http://www.sk.ee/DigiDoc/v1.3.0/digidoc.xsd")
		{
			for(const DDOCReader::File &file: DDOCReader::files(data))
			{
				std::string path = std::string(argv[6]) + "/" + file.name;
				std::ofstream f(path.c_str());
				f.write((const char*)file.data.data(), std::streamsize(file.data.size()));
			}
		}
		else
		{
			std::string path = std::string(argv[6]) + "/" + r.fileName();
			std::ofstream f(path.c_str());
			f.write((const char*)data.data(), std::streamsize(data.size()));
		}
	}
	else
	{
		std::cout
			<< "cdoc-tool encrypt X509DerRecipientCert InFile [InFile [InFile [...]]] OutFile" << std::endl
#ifdef _WIN32
			<< "cdoc-tool decrypt win [ui|noui] pin InFile OutFolder" << std::endl
#endif
			<< "cdoc-tool decrypt pkcs11 path/to/so pin InFile OutFolder" << std::endl
			<< "cdoc-tool decrypt pkcs12 path/to/pkcs12 pin InFile OutFolder" << std::endl;
	}
	return 0;
}
