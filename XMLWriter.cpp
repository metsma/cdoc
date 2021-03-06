#include "XMLWriter.h"

#include "Crypto.h"

#include <libxml/xmlwriter.h>

#include <algorithm>

typedef xmlChar *pxmlChar;
typedef const xmlChar *pcxmlChar;

struct XMLWriter::Private
{
	xmlBufferPtr buf = nullptr;
	xmlTextWriterPtr w = nullptr;
	std::map<std::string, int> nsmap;
};

XMLWriter::XMLWriter(const std::string &path)
	: d(new Private)
{
	if(path.empty())
	{
		d->buf = xmlBufferCreate();
		d->w = xmlNewTextWriterMemory(d->buf, 0);
	}
	else
		d->w = xmlNewTextWriterFilename(path.c_str(), 0);
	xmlTextWriterStartDocument(d->w, nullptr, "UTF-8", nullptr);
}

XMLWriter::~XMLWriter()
{
	close();
	if(d->buf)
		xmlBufferFree(d->buf);
	delete d;
}

std::vector<unsigned char> XMLWriter::data() const
{
	std::vector<unsigned char> result;
	if(d->buf)
		result.assign(xmlBufferContent(d->buf), xmlBufferContent(d->buf) + xmlBufferLength(d->buf));
	return result;
}

void XMLWriter::close()
{
	if(!d->w)
		return;
	xmlTextWriterEndDocument(d->w);
	xmlFreeTextWriter(d->w);
	d->w = nullptr;
}

void XMLWriter::writeStartElement(const NS &ns, const std::string &name, const std::map<std::string, std::string> &attr)
{
	std::map<std::string, int>::iterator pos = d->nsmap.find(ns.prefix);
	if (pos != d->nsmap.cend())
		pos->second++;
	else
		pos = d->nsmap.insert({ns.prefix, 1}).first;
	if(!d->w)
		return;
	xmlTextWriterStartElementNS(d->w, ns.prefix.empty() ? nullptr : pcxmlChar(ns.prefix.c_str()),
		pcxmlChar(name.c_str()), pos->second > 1 ? nullptr : pcxmlChar(ns.ns.c_str()));
	for(auto i = attr.cbegin(), end = attr.cend(); i != end; ++i)
		xmlTextWriterWriteAttribute(d->w, pcxmlChar(i->first.c_str()), pcxmlChar(i->second.c_str()));
}

void XMLWriter::writeEndElement(const NS &ns)
{
	if(d->w)
		xmlTextWriterEndElement(d->w);
	std::map<std::string, int>::iterator pos = d->nsmap.find(ns.prefix);
	if (pos != d->nsmap.cend())
		pos->second--;
}

void XMLWriter::writeElement(const NS &ns, const std::string &name, const std::function<void()> &f)
{
	writeStartElement(ns, name, {});
	if(f)
		f();
	writeEndElement(ns);
}

void XMLWriter::writeElement(const NS &ns, const std::string &name, const std::map<std::string, std::string> &attr, const std::function<void()> &f)
{
	writeStartElement(ns, name, attr);
	if(f)
		f();
	writeEndElement(ns);
}

void XMLWriter::writeBase64Element(const NS &ns, const std::string &name, const std::vector<xmlChar> &data, const std::map<std::string, std::string> &attr)
{
	if (!d->w)
		return;
	writeStartElement(ns, name, attr);
	static const size_t bufLen = 48 * 10240;
	for (size_t i = 0; i < data.size(); i += bufLen)
	{
		std::string b64 = Crypto::toBase64(&data[i], std::min<size_t>(data.size() - i, bufLen));
		xmlTextWriterWriteRaw(d->w, (const xmlChar*)b64.c_str());
	}
	writeEndElement(ns);
}

void XMLWriter::writeTextElement(const NS &ns, const std::string &name, const std::map<std::string, std::string> &attr, const std::string &data)
{
	writeStartElement(ns, name, attr);
	if(d->w)
		xmlTextWriterWriteString(d->w, pcxmlChar(data.c_str()));
	writeEndElement(ns);
}
