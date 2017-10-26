#pragma once

#include <string>
#include <vector>

class CDOCWriter
{
public:
	CDOCWriter(const std::string &file, const std::string &method);
	~CDOCWriter();

	void addRecipient(const std::vector<unsigned char> &recipient);
	void encryptData(const std::string &name, const std::vector<unsigned char> &data);

private:
	struct CDOCWriterPrivate;
	CDOCWriterPrivate *d;
};
