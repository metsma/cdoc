#include "Token.h"

#include "Crypto.h"

#include "pkcs11.h"

#include <openssl/pkcs12.h>
#include <openssl/ssl.h>

#ifdef _WIN32
#else
#include <dlfcn.h>
#endif

Token::Token() = default;
Token::~Token() = default;


class PKCS11Token::PKCS11TokenPrivate
{
public:
	std::vector<CK_OBJECT_HANDLE> findObject(CK_OBJECT_CLASS cls, const std::vector<uchar> &id = std::vector<uchar>())
	{
		std::vector<CK_OBJECT_HANDLE> result;
		CK_BBOOL _true = CK_TRUE;
		std::vector<CK_ATTRIBUTE> attr{
			{ CKA_CLASS, &cls, sizeof(cls) },
			{ CKA_TOKEN, &_true, sizeof(_true) },
		};
		if(!id.empty())
			attr.push_back({ CKA_ID, CK_VOID_PTR(id.data()), CK_ULONG(id.size()) });
		if(f->C_FindObjectsInit(session, attr.data(), attr.size()) != CKR_OK)
			return result;

		CK_ULONG count = 32;
		result.resize(count);
		if(f->C_FindObjects(session, result.data(), result.size(), &count) == CKR_OK)
			result.resize(count);
		else
			result.clear();
		f->C_FindObjectsFinal(session);
		return result;
	}
	std::vector<uchar> attribute(CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_TYPE type)
	{
		std::vector<uchar> data;
		CK_ATTRIBUTE attr = { type, 0, 0 };
		if(f->C_GetAttributeValue(session, obj, &attr, 1) != CKR_OK)
			return data;
		data.resize(attr.ulValueLen, 0);
		attr.pValue = data.data();
		if(f->C_GetAttributeValue(session, obj, &attr, 1) != CKR_OK)
			data.clear();
		return data;
	}

	void *h = nullptr;
	CK_FUNCTION_LIST_PTR f = nullptr;
	CK_SESSION_HANDLE session = 0;
	std::vector<uchar> id;
};

PKCS11Token::PKCS11Token(const std::string &path)
	: d(new PKCS11TokenPrivate)
{
	CK_C_GetFunctionList l = nullptr;
#ifdef _WIN32
#else
	d->h = dlopen(path.c_str(), RTLD_LAZY);
	if(d->h)
		l = CK_C_GetFunctionList(dlsym(d->h, "C_GetFunctionList"));
#endif
	if(l && l(&d->f) == CKR_OK && d->f)
	{
		CK_C_INITIALIZE_ARGS init_args = { 0, 0, 0, 0, CKF_OS_LOCKING_OK, 0 };
		d->f->C_Initialize(&init_args);
	}
}

PKCS11Token::~PKCS11Token()
{
	if(d->f)
	{
		if(d->session)
			d->f->C_CloseSession(d->session);
		d->f->C_Finalize(nullptr);
		d->f = nullptr;
	}
#ifdef _WIN32
#else
	if(d->h)
		dlclose(d->h);
#endif
	delete d;
}

std::vector<uchar> PKCS11Token::decrypt(const std::vector<uchar> &cert, const std::string &pass, const std::vector<uchar> &data)
{
	std::vector<uchar> result;
	if(!login(cert, pass))
		return result;

	std::vector<CK_OBJECT_HANDLE> key = d->findObject(CKO_PRIVATE_KEY, d->id);
	if(key.size() != 1)
		return result;

	CK_MECHANISM mech = { CKM_RSA_PKCS, 0, 0 };
	if(d->f->C_DecryptInit(d->session, &mech, key[0]) != CKR_OK)
		return result;

	CK_ULONG size = 0;
	if(d->f->C_Decrypt(d->session, CK_CHAR_PTR(data.data()), data.size(), 0, &size) != CKR_OK)
		return result;

	result.resize(size);
	if(d->f->C_Decrypt(d->session, CK_CHAR_PTR(data.data()), data.size(), result.data(), &size) != CKR_OK)
		result.clear();
	return result;
}

std::vector<uchar> PKCS11Token::derive(const std::vector<uchar> &cert, const std::string &pass, const std::vector<uchar> &publicKey)
{
	std::vector<uchar> sharedSecret;
	if(!login(cert, pass))
		return sharedSecret;

	std::vector<CK_OBJECT_HANDLE> key = d->findObject(CKO_PRIVATE_KEY, d->id);
	if(key.size() != 1)
		return sharedSecret;

	CK_ECDH1_DERIVE_PARAMS ecdh_parms = { CKD_NULL, 0, nullptr, CK_ULONG(publicKey.size()), CK_BYTE_PTR(publicKey.data()) };
	CK_MECHANISM mech = { CKM_ECDH1_DERIVE, &ecdh_parms, sizeof(CK_ECDH1_DERIVE_PARAMS) };
	CK_BBOOL _true = CK_TRUE;
	CK_BBOOL _false = CK_FALSE;
	CK_OBJECT_CLASS newkey_class = CKO_SECRET_KEY;
	CK_KEY_TYPE newkey_type = CKK_GENERIC_SECRET;
	CK_ULONG key_len = CK_ULONG((publicKey.size() - 1) / 2);
	std::vector<CK_ATTRIBUTE> newkey_template{
		{CKA_TOKEN, &_false, sizeof(_false)},
		{CKA_CLASS, &newkey_class, sizeof(newkey_class)},
		{CKA_KEY_TYPE, &newkey_type, sizeof(newkey_type)},
		{CKA_ENCRYPT, &_true, sizeof(_true)},
		{CKA_DECRYPT, &_true, sizeof(_true)},
		{CKA_VALUE_LEN, &key_len, sizeof(key_len)}
	};
	CK_OBJECT_HANDLE newkey = CK_INVALID_HANDLE;
	if(d->f->C_DeriveKey(d->session, &mech, key[0], newkey_template.data(), CK_ULONG(newkey_template.size()), &newkey) != CKR_OK)
		return sharedSecret;

	return d->attribute(newkey, CKA_VALUE);
}

bool PKCS11Token::login(const std::vector<uchar> &cert, const std::string &pass)
{
	CK_ULONG size = 0;
	if(d->f->C_GetSlotList(true, 0, &size) != CKR_OK)
		return false;
	std::vector<CK_SLOT_ID> slots(size, 0);
	if(size && d->f->C_GetSlotList(true, slots.data(), &size) != CKR_OK)
		return false;
	d->id = [&] {
		for(const CK_SLOT_ID &slot: slots)
		{
			if(d->session)
				d->f->C_CloseSession(d->session);
			if(d->f->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &d->session) != CKR_OK)
				continue;
			for(CK_OBJECT_HANDLE obj: d->findObject(CKO_CERTIFICATE))
			{
				if(d->attribute(obj, CKA_VALUE) == cert)
					return d->attribute(obj, CKA_ID);
			}
		}
		return std::vector<uchar>();
	}();
	if(d->id.empty())
	{
		if(d->session)
			d->f->C_CloseSession(d->session);
		return false;
	}

	switch(d->f->C_Login(d->session, CKU_USER, CK_BYTE_PTR(pass.c_str()), CK_ULONG(pass.size())))
	{
	case CKR_OK:
	case CKR_USER_ALREADY_LOGGED_IN: return true;
	case CKR_CANCEL:
	case CKR_FUNCTION_CANCELED:
	default:
		return false;
	}
}



class PKCS12Token::PKCS12TokenPrivate
{
public:
	std::unique_ptr<PKCS12, decltype(&PKCS12_free)> p12 = std::unique_ptr<PKCS12, decltype(&PKCS12_free)>(nullptr, PKCS12_free);
};

PKCS12Token::PKCS12Token(const std::string &path)
	: d(new PKCS12TokenPrivate)
{
	SSL_load_error_strings();
	SSL_library_init();
	SCOPE(BIO, bio, BIO_new_file(path.c_str(), "rb"));
	d->p12.reset(d2i_PKCS12_bio(bio.get(), 0));
}

PKCS12Token::~PKCS12Token()
{
	delete d;
}

std::vector<uchar> PKCS12Token::decrypt(const std::vector<uchar> &/*cert*/, const std::string &pass, const std::vector<uchar> &data)
{
	std::vector<uchar> result;
	if(!d->p12)
		return result;

	EVP_PKEY *_pkey = nullptr;
	PKCS12_parse(d->p12.get(), pass.c_str(), &_pkey, nullptr, nullptr);
	SCOPE(EVP_PKEY, pkey, _pkey);
	SCOPE(RSA, rsa, EVP_PKEY_get1_RSA(pkey.get()));

	result.resize(size_t(RSA_size(rsa.get())));
	if(RSA_private_decrypt(int(data.size()), data.data(), result.data(), rsa.get(), RSA_PKCS1_PADDING) == 1)
		result.clear();
	return result;
}

std::vector<uchar> PKCS12Token::derive(const std::vector<uchar> &, const std::string &pass, const std::vector<uchar> &publicKey)
{
	std::vector<uchar> result;
	if(!d->p12)
		return result;

	EVP_PKEY *_pkey = nullptr;
	PKCS12_parse(d->p12.get(), pass.c_str(), &_pkey, nullptr, nullptr);
	SCOPE(EVP_PKEY, pkey, _pkey);
	SCOPE(EC_KEY, pECKey, EVP_PKEY_get1_EC_KEY(pkey.get()));

	size_t size = (publicKey.size() - 1) / 2;
	SCOPE(EC_KEY, peerECKey, EC_KEY_new());
	EC_KEY_set_group(peerECKey.get(), EC_KEY_get0_group(pECKey.get()));
	EC_KEY_set_public_key_affine_coordinates(peerECKey.get(),
		BN_bin2bn(&publicKey[1], int(size), nullptr),
		BN_bin2bn(&publicKey[1 + size], int(size), nullptr));

	SCOPE(EVP_PKEY, peerPKey, EVP_PKEY_new());
	EVP_PKEY_set1_EC_KEY(peerPKey.get(), peerECKey.get());

	return Crypto::deriveSharedSecret(pkey.get(), peerPKey.get());
}
