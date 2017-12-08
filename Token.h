#pragma once

#include <CDOCExport.h>

#include <string>
#include <vector>

typedef unsigned char uchar;

class CDOC_EXPORT Token
{
public:
	virtual ~Token();
	virtual std::vector<uchar> cert() const = 0;
	virtual std::vector<uchar> decrypt(const std::vector<uchar> &data) const = 0;
	virtual std::vector<uchar> derive(const std::vector<uchar> &publicKey) const = 0;
protected:
	Token();
};

class CDOC_EXPORT PKCS11Token: public Token
{
public:
	PKCS11Token(const std::string &path, const std::string &pass);
	~PKCS11Token();
	virtual std::vector<uchar> cert() const override;
	std::vector<uchar> decrypt(const std::vector<uchar> &data) const override;
	std::vector<uchar> derive(const std::vector<uchar> &publicKey) const override;
private:
	class PKCS11TokenPrivate;
	PKCS11TokenPrivate *d;
};

class CDOC_EXPORT PKCS12Token: public Token
{
public:
	PKCS12Token(const std::string &path, const std::string &pass);
	~PKCS12Token();
	virtual std::vector<uchar> cert() const override;
	std::vector<uchar> decrypt(const std::vector<uchar> &data) const override;
	std::vector<uchar> derive(const std::vector<uchar> &publicKey) const override;
private:
	class PKCS12TokenPrivate;
	PKCS12TokenPrivate *d;
};

#ifdef _WIN32
class WinToken: public Token
{
public:
	WinToken(const std::string &pass) {}
};
#endif
