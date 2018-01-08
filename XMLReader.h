#pragma once

#include <string>
#include <vector>

class XMLReader
{
public:
	XMLReader(const std::string &file);
	XMLReader(const std::vector<unsigned char> &data);
	~XMLReader();

	std::string attribute(const char *attr) const;
	bool isElement(const char *element) const;
	bool isEndElement() const;
	bool read();
	std::vector<unsigned char> readBase64();
	std::string readText();

private:
	struct Private;
	Private *d;
};
