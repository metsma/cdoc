#pragma once

#include "CDOCDefines.h"

#include <string>
#include <vector>

class CDOC_EXPORT SWIFT_NONCOPYABLE Token
{
public:
	DISABLE_COPY(Token)
	ENABLE_MOVE(Token)
	virtual ~Token() noexcept;
	virtual CDOCData cert() const = 0;
	virtual CDOCData decrypt(const CDOCData &data) const = 0;
	virtual CDOCData derive(const CDOCData &publicKey) const;
	virtual CDOCData deriveConcatKDF(const CDOCData &publicKey, const std::string &digest, unsigned int keySize,
		const CDOCData &algorithmID, const CDOCData &partyUInfo, const CDOCData &partyVInfo) const;
protected:
	Token();
};

class CDOC_EXPORT SWIFT_NONCOPYABLE PKCS11Token: public Token
{
public:
	PKCS11Token(const std::string &path, const std::string &password);
	DISABLE_COPY(PKCS11Token)
	ENABLE_MOVE_D(PKCS11Token)
	~PKCS11Token() noexcept;
	virtual CDOCData cert() const override;
	CDOCData decrypt(const CDOCData &data) const override;
	CDOCData derive(const CDOCData &publicKey) const override;
private:
	class Private;
	Private *d{};
};

class CDOC_EXPORT SWIFT_NONCOPYABLE PKCS12Token: public Token
{
public:
	PKCS12Token(const std::string &path, const std::string &password);
	DISABLE_COPY(PKCS12Token)
	ENABLE_MOVE_D(PKCS12Token)
	~PKCS12Token() noexcept;
	virtual CDOCData cert() const override;
	CDOCData decrypt(const CDOCData &data) const override;
	CDOCData derive(const CDOCData &publicKey) const override;
private:
	class Private;
	Private *d{};
};

#ifdef _WIN32
class CDOC_EXPORT SWIFT_NONCOPYABLE WinToken: public Token
{
public:
	WinToken(bool ui, const std::string &pass);
	DISABLE_COPY(WinToken)
	ENABLE_MOVE_D(WinToken)
	~WinToken() noexcept;
	virtual CDOCData cert() const override;
	CDOCData decrypt(const CDOCData &data) const override;
	CDOCData deriveConcatKDF(const CDOCData &publicKey, const std::string &digest, unsigned int keySize,
		const CDOCData &algorithmID, const CDOCData &partyUInfo, const CDOCData &partyVInfo) const override;
private:
	class Private;
	Private *d{};
};
#endif
