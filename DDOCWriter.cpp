#include "DDOCWriter.h"

#include "Writer.h"

/**
 * @class DDOCWriter
 * @brief DDOCWriter is used for storing multiple files.
 */

struct DDOCWriter::DDOCWriterPrivate
{
	static const NS DDOC;
	int fileCount = 0;
};

const Writer::NS DDOCWriter::DDOCWriterPrivate::DDOC{ "", "http://www.sk.ee/DigiDoc/v1.3.0#" };

/**
 * DDOCWriter constructor.
 * @param file File to be created
 */
DDOCWriter::DDOCWriter(const std::string &file)
	: Writer(file)
	, d(new DDOCWriterPrivate)
{
	writeStartElement(d->DDOC, "SignedDoc", {{"format", "DIGIDOC-XML"}, {"version", "1.3"}});
}

DDOCWriter::~DDOCWriter()
{
	delete d;
}

void DDOCWriter::close()
{
	writeEndElement(d->DDOC); // SignedDoc
	Writer::close();
}

/**
 * Add File to container
 * @param file Filename
 * @param mime File mime type
 * @param data File content
 */
void DDOCWriter::addFile(const std::string &file, const std::string &mime, const std::vector<unsigned char> &data)
{
	writeBase64Element(d->DDOC, "DataFile", data, {
		{"ContentType", "EMBEDDED_BASE64"},
		{"Filename", file},
		{"Id", "D" + std::to_string(d->fileCount++)},
		{"MimeType", mime},
		{"Size", std::to_string(data.size())}
	});
}