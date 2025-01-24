#pragma once

#include "CDOCDefines.h"

#include <string>

class Token;
class CDOC_EXPORT SWIFT_NONCOPYABLE CDOCReader
{
public:
	CDOCReader(const std::string &file);
	DISABLE_COPY(CDOCReader)
	ENABLE_MOVE_D(CDOCReader)
	~CDOCReader() noexcept;

	std::string mimeType() const;
	std::string fileName() const;
	CDOCData decryptData(const CDOCData &key) const;
	CDOCData decryptData(Token *token) const;

private:
	class Private;
	Private *d{};
};
