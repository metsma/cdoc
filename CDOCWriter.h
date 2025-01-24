#pragma once

#include "CDOCDefines.h"

#include <string>

class CDOC_EXPORT SWIFT_NONCOPYABLE CDOCWriter
{
public:
	CDOCWriter(const std::string &file, const std::string &method = "http://www.w3.org/2009/xmlenc11#aes256-gcm");
	DISABLE_COPY(CDOCWriter)
	ENABLE_MOVE_D(CDOCWriter)
	~CDOCWriter() noexcept;

	void addFile(const std::string &filename, const std::string &mime, const CDOCData &data);
	void addFile(const std::string &filename, const std::string &mime, const std::string &path);
	void addRecipient(const CDOCData &recipient);
	bool encrypt();
	std::string lastError() const;

private:
	class Private;
	Private *d{};
};
