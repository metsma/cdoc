#include "CDOCWriter.h"
#include "CDOCReader.h"
#include "Crypto.h"
#include "Token.h"
#include "DDOCReader.h"

#include <cstring>
#include <iostream>
#include <fstream>

#ifdef _WIN32
#include <Windows.h>

static std::wstring toWide(UINT codePage, const std::string &in)
{
	std::wstring result;
	if(in.empty())
		return result;
	int len = MultiByteToWideChar(codePage, 0, in.data(), int(in.size()), nullptr, 0);
	result.resize(size_t(len), 0);
	len = MultiByteToWideChar(codePage, 0, in.data(), int(in.size()), &result[0], len);
	return result;
}

static std::string toMultiByte(UINT codePage, const std::wstring &in)
{
	std::string result;
	if(in.empty())
		return result;
	int len = WideCharToMultiByte(codePage, 0, in.data(), int(in.size()), nullptr, 0, nullptr, nullptr);
	result.resize(size_t(len), 0);
	len = WideCharToMultiByte(codePage, 0, in.data(), int(in.size()), &result[0], len, nullptr, nullptr);
	return result;
}
#endif

static std::string toUTF8(const std::string &in)
{
#ifdef _WIN32
	return toMultiByte(CP_UTF8, toWide(CP_ACP, in));
#else
	return in;
#endif
}

static std::vector<unsigned char> readFile(const std::string &path)
{
#ifdef _WIN32
	std::ifstream f(toWide(CP_UTF8, path).c_str(), std::ifstream::binary);
#else
	std::ifstream f(path, std::ifstream::binary);
#endif
	f.seekg(0, std::ifstream::end);
	std::vector<unsigned char> data(size_t(f.tellg()), 0);
	f.clear();
	f.seekg(0);
	f.read((char*)data.data(), std::streamsize(data.size()));
	return data;
}

static void writeFile(const std::string &path, const std::vector<unsigned char> &data)
{
#ifdef _WIN32
	std::ofstream f(toWide(CP_UTF8, path).c_str(), std::ofstream::binary);
#else
	std::ofstream f(path.c_str(), std::ofstream::binary);
#endif
	f.write((const char*)data.data(), std::streamsize(data.size()));
}

int main(int argc, char *argv[])
{
	if(argc >= 5 && strcmp(argv[1], "encrypt") == 0)
	{
		CDOCWriter w(toUTF8(argv[argc-1]), "http://www.w3.org/2009/xmlenc11#aes256-gcm");
		for(int i = 3; i < argc - 1; ++i)
		{
			std::string inFile = toUTF8(argv[i]);
			size_t pos = inFile.find_last_of("/\\");
			w.addFile(pos == std::string::npos ? inFile : inFile.substr(pos + 1), "application/octet-stream", readFile(inFile));
		}
		w.addRecipient(readFile(toUTF8(argv[2])));
		w.encrypt();
	}
	else if(argc == 7 && strcmp(argv[1], "decrypt") == 0)
	{
		std::unique_ptr<Token> token;
		if (strcmp(argv[2], "pkcs11") == 0)
			token.reset(new PKCS11Token(toUTF8(argv[3]), argv[4]));
		else if (strcmp(argv[2], "pkcs12") == 0)
			token.reset(new PKCS12Token(toUTF8(argv[3]), argv[4]));
#ifdef _WIN32
		else if (strcmp(argv[2], "win") == 0)
			token.reset(new WinToken(strcmp(argv[3], "ui") == 0, argv[4]));
#endif
		CDOCReader r(toUTF8(argv[5]));
		std::vector<unsigned char> data = r.decryptData(token.get());
		if(r.mimeType() == "http://www.sk.ee/DigiDoc/v1.3.0/digidoc.xsd")
		{
			for(const DDOCReader::File &file: DDOCReader::files(data))
				writeFile(toUTF8(argv[6]) + "/" + file.name, file.data);
		}
		else
			writeFile(toUTF8(argv[6]) + "/" + r.fileName(), data);
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
