#pragma once

#include <CDOCExport.h>

#include <string>
#include <vector>

class CDOC_EXPORT CDOCWriter
{
public:
	CDOCWriter(const std::string &file, const std::string &method);
	~CDOCWriter();

	void addRecipient(const std::vector<unsigned char> &recipient);
	void encryptData(const std::string &name, const std::vector<unsigned char> &data);

private:
	CDOCWriter(const CDOCWriter &) = delete;
	CDOCWriter &operator=(const CDOCWriter &) = delete;
	struct CDOCWriterPrivate;
	CDOCWriterPrivate *d;
};
