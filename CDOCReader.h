#pragma once

#include <CDOCExport.h>

#include <string>
#include <vector>

class Token;
class CDOC_EXPORT CDOCReader
{
public:
	struct Key
	{
		std::string id, recipient, name;
		std::string method, agreement, derive, concatDigest;
		std::vector<unsigned char> cert, publicKey, cipher;
		std::vector<unsigned char> AlgorithmID, PartyUInfo, PartyVInfo;
	};
	struct File
	{
		std::string name, size, mime, id;
	};

	CDOCReader(const std::string &file);
	~CDOCReader();

	std::vector<Key> keys() const;
	std::vector<unsigned char> decryptData(const std::vector<unsigned char> &key);
	std::vector<unsigned char> decryptData(Token *token);

private:
	class CDOCReaderPrivate;
	CDOCReaderPrivate *d;
};
