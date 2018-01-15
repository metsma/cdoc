#include "XMLReader.h"

#include "Crypto.h"

#include <libxml/xmlreader.h>

typedef xmlChar *pxmlChar;
typedef const xmlChar *pcxmlChar;

struct XMLReader::Private
{
	xmlParserInputBufferPtr in = nullptr;
	xmlTextReaderPtr reader = nullptr;

	std::string tostring(const xmlChar *tmp)
	{
		std::string result;
		if(!tmp)
			return result;
		result = (const char*)tmp;
		return result;
	}
};

XMLReader::XMLReader(const std::string &file)
	: d(new Private)
{
	d->reader = xmlNewTextReaderFilename(file.c_str());
}

XMLReader::XMLReader(const std::vector<uchar> &data)
	: d(new Private)
{
	d->in = xmlParserInputBufferCreateMem((const char*)data.data(), int(data.size()), XML_CHAR_ENCODING_UTF8);
	d->reader = xmlNewTextReader(d->in, nullptr);
}

XMLReader::~XMLReader()
{
	if(d->reader)
		xmlFreeTextReader(d->reader);
	if(d->in)
		xmlFreeParserInputBuffer(d->in);
	delete d;
}

std::string XMLReader::attribute(const char *attr) const
{
	xmlChar *tmp = xmlTextReaderGetAttribute(d->reader, pcxmlChar(attr));
	std::string result = d->tostring(tmp);
	xmlFree(tmp);
	return result;
}

bool XMLReader::isEndElement() const
{
	return xmlTextReaderNodeType(d->reader) == XML_READER_TYPE_END_ELEMENT;
}

bool XMLReader::isElement(const char *elem) const
{
	return xmlStrEqual(xmlTextReaderConstLocalName(d->reader), pcxmlChar(elem)) == 1;
}

bool XMLReader::read()
{
	return xmlTextReaderRead(d->reader) == 1;
}

std::vector<uchar> XMLReader::readBase64()
{
	return Crypto::decodeBase64(xmlTextReaderConstValue(d->reader));
}

std::string XMLReader::readText()
{
	xmlTextReaderRead(d->reader);
	return d->tostring(xmlTextReaderConstValue(d->reader));
}
