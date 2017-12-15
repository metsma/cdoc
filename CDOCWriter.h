#pragma once

#include <CDOCExport.h>

#include <string>
#include <vector>

class CDOC_EXPORT CDOCWriter
{
public:
	struct File
	{
		std::string filename, mime;
		std::vector<unsigned char> data;
	};
	CDOCWriter(const std::string &file, const std::string &method = "http://www.w3.org/2009/xmlenc11#aes256-gcm",
		const std::string &mime = "application/octet-stream");
	~CDOCWriter();

	void addRecipient(const std::vector<unsigned char> &recipient);
	void encryptData(const std::vector<File> &files);

private:
	CDOCWriter(const CDOCWriter &) = delete;
	CDOCWriter &operator=(const CDOCWriter &) = delete;
	struct CDOCWriterPrivate;
	CDOCWriterPrivate *d;
};
