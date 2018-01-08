#pragma once

#include "XMLWriter.h"

#include <string>

class DDOCWriter: public XMLWriter
{
public:
	DDOCWriter(const std::string &file);
	~DDOCWriter();

	void addFile(const std::string &name, const std::string &mime, const std::vector<unsigned char> &data);
	void close() override;

private:
	DDOCWriter(const DDOCWriter &) = delete;
	DDOCWriter &operator=(const DDOCWriter &) = delete;
	struct Private;
	Private *d;
};
