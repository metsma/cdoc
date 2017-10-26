#pragma once

#include <string>
#include <vector>

typedef unsigned char uchar;

class Token
{
public:
	virtual ~Token();
	virtual std::vector<uchar> decrypt(const std::vector<uchar> &cert, const std::string &pass, const std::vector<uchar> &data) = 0;
	virtual std::vector<uchar> derive(const std::vector<uchar> &cert, const std::string &pass, const std::vector<uchar> &publicKey) = 0;
protected:
	Token();
};

class PKCS11Token: public Token
{
public:
	PKCS11Token(const std::string &path);
	~PKCS11Token();
	std::vector<uchar> decrypt(const std::vector<uchar> &cert, const std::string &pass, const std::vector<uchar> &data) override;
	std::vector<uchar> derive(const std::vector<uchar> &cert, const std::string &pass, const std::vector<uchar> &publicKey) override;
private:
	bool login(const std::vector<uchar> &cert, const std::string &pass);
	class PKCS11TokenPrivate;
	PKCS11TokenPrivate *d;
};

class PKCS12Token: public Token
{
public:
	PKCS12Token(const std::string &path);
	~PKCS12Token();
	std::vector<uchar> decrypt(const std::vector<uchar> &cert, const std::string &pass, const std::vector<uchar> &data) override;
	std::vector<uchar> derive(const std::vector<uchar> &cert, const std::string &pass, const std::vector<uchar> &publicKey) override;
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
