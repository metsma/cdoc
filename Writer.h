#pragma once

#include <map>
#include <string>
#include <vector>

class Writer
{
public:
	struct NS { std::string prefix, ns; };

	Writer(const std::string &path);
	virtual ~Writer();

	void writeStartElement(const NS &ns, const std::string &name, const std::map<std::string, std::string> &attr);
	void writeEndElement(const NS &ns);
	void writeElement(const NS &ns, const std::string &name, const std::function<void()> &f = nullptr);
	void writeElement(const NS &ns, const std::string &name, const std::map<std::string, std::string> &attr, const std::function<void()> &f = nullptr);
	void writeBase64Element(const NS &ns, const std::string &name, const std::vector<unsigned char> &data);
	void writeTextElement(const NS &ns, const std::string &name, const std::map<std::string, std::string> &attr, const std::string &data);

private:
	struct WriterPrivate;
	WriterPrivate *d;
};
