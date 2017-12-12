#pragma once

#include <CDOCExport.h>

#include <string>
#include <vector>

class CDOC_EXPORT DDOCWriter
{
public:
	DDOCWriter(const std::string &file);
	~DDOCWriter();

	void addFile(const std::string &name, const std::string &mime, const std::vector<unsigned char> &data);

private:
	DDOCWriter(const DDOCWriter &) = delete;
	DDOCWriter &operator=(const DDOCWriter &) = delete;
	struct DDOCWriterPrivate;
	DDOCWriterPrivate *d;
};
