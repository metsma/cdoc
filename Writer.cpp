#include "Writer.h"

#include "Crypto.h"

#include <libxml/xmlwriter.h>

typedef xmlChar *pxmlChar;
typedef const xmlChar *pcxmlChar;

struct Writer::WriterPrivate
{
	xmlTextWriterPtr w = nullptr;
	std::map<std::string, int> nsmap;
};

Writer::Writer(const std::string &path)
	: d(new WriterPrivate)
{
	d->w = xmlNewTextWriterFilename(path.c_str(), 0);
	xmlTextWriterStartDocument(d->w, nullptr, "UTF-8", nullptr);
}

Writer::~Writer()
{
	xmlTextWriterEndDocument(d->w);
	xmlFreeTextWriter(d->w);
	delete d;
}

void Writer::writeStartElement(const NS &ns, const std::string &name, const std::map<std::string, std::string> &attr)
{
	std::map<std::string, int>::iterator pos = d->nsmap.find(ns.prefix);
	if (pos != d->nsmap.cend())
		pos->second++;
	else
		pos = d->nsmap.insert({ns.prefix, 1}).first;
	xmlTextWriterStartElementNS(d->w, pcxmlChar(ns.prefix.c_str()),
		pcxmlChar(name.c_str()), pos->second > 1 ? nullptr : pcxmlChar(ns.ns.c_str()));
	for(auto i = attr.cbegin(), end = attr.cend(); i != end; ++i)
		xmlTextWriterWriteAttribute(d->w, pcxmlChar(i->first.c_str()), pcxmlChar(i->second.c_str()));
}

void Writer::writeEndElement(const NS &ns)
{
	xmlTextWriterEndElement(d->w);
	std::map<std::string, int>::iterator pos = d->nsmap.find(ns.prefix);
	if (pos != d->nsmap.cend())
		pos->second--;
}

void Writer::writeElement(const NS &ns, const std::string &name, const std::function<void()> &f)
{
	writeStartElement(ns, name, {});
	if(f)
		f();
	writeEndElement(ns);
}

void Writer::writeElement(const NS &ns, const std::string &name, const std::map<std::string, std::string> &attr, const std::function<void()> &f)
{
	writeStartElement(ns, name, attr);
	if(f)
		f();
	writeEndElement(ns);
}

void Writer::writeBase64Element(const NS &ns, const std::string &name, const std::vector<xmlChar> &data)
{
	writeTextElement(ns, name, {}, Crypto::encodeBase64(data));
#if 0
	writeStartElement(ns, name, {});
	xmlTextWriterWriteBase64(d->w, (const char*)data.data(), 0, int(data.size()));
	writeEndElement(ns);
#endif
}

void Writer::writeTextElement(const NS &ns, const std::string &name, const std::map<std::string, std::string> &attr, const std::string &data)
{
	writeStartElement(ns, name, attr);
	xmlTextWriterWriteString(d->w, pcxmlChar(data.c_str()));
	writeEndElement(ns);
}
