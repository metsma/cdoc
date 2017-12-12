#include "Token.h"

#include "Crypto.h"

#include "pkcs11.h"

#include <openssl/pkcs12.h>
#include <openssl/ssl.h>

#ifdef _WIN32
#include <Windows.h>
#include <wincrypt.h>
#include <cryptuiapi.h>
#else
#include <dlfcn.h>
#endif

/**
 * @class Token
 * @brief Abstract Token interface to subclass different implementations.
 */

Token::Token() = default;
Token::~Token() = default;

/**
 * @fn Token::cert
 *
 * Returns Token certificate
 */


/**
 * @fn Token::decrypt
 *
 * Returns decrypted RSA data
 * @param data Data to decrypted
 */

/**
 * @fn Token::derive
 *
 * Returns derived shared key
 * @param publicKey ECDH public Key used to derive shared secret
 */
std::vector<uchar> Token::derive(const std::vector<uchar> &) const
{
	return std::vector<uchar>();
}

/**
 * The ConcatKDF key derivation algorithm, defined in Section 5.8.1 of NIST SP 800-56A.
 * Returns derived key by using Token::derive shared secret
 * @param publicKey ECDH public Key used to derive shared secret
 * @param digest Digest method to use for ConcatKDF algorithm
 * @param keySize Key size to output
 * @param algorithmID OtherInfo info parameters to input
 * @param partyUInfo OtherInfo info parameters to input
 * @param partyVInfo OtherInfo info parameters to input
 */
std::vector<uchar> Token::deriveConcatKDF(const std::vector<uchar> &publicKey, const std::string &digest, uint32_t keySize,
	const std::vector<uchar> &algorithmID, const std::vector<uchar> &partyUInfo, const std::vector<uchar> &partyVInfo) const
{
	return Crypto::concatKDF(digest, keySize,  derive(publicKey), algorithmID, partyUInfo, partyVInfo);
}



/**
 * @class PKCS11Token
 * @brief Implements <code>Token</code> interface for ID-Cards, which support PKCS#11 protocol.
 */

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
		if(f->C_FindObjectsInit(session, attr.data(), CK_ULONG(attr.size())) != CKR_OK)
			return result;

		CK_ULONG count = 32;
		result.resize(count);
		if(f->C_FindObjects(session, result.data(), CK_ULONG(result.size()), &count) == CKR_OK)
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

#ifdef _WIN32
	HMODULE h = nullptr;
#else
	void *h = nullptr;
#endif
	CK_FUNCTION_LIST_PTR f = nullptr;
	CK_SESSION_HANDLE session = 0;
	std::vector<uchar> id, cert;
};

/**
 * Loads PKCS#11 token.
 *
 * @param path full path to the PKCS#11 driver (e.g. /usr/lib/opensc-pkcs11.so)
 * @param password token password
 */
PKCS11Token::PKCS11Token(const std::string &path, const std::string &password)
	: d(new PKCS11TokenPrivate)
{
	CK_C_GetFunctionList l = nullptr;
#ifdef _WIN32
	int len = MultiByteToWideChar(CP_UTF8, 0, path.data(), int(path.size()), 0, 0);
	std::wstring out(size_t(len), 0);
	MultiByteToWideChar(CP_UTF8, 0, path.data(), int(path.size()), &out[0], len);
	if((d->h = LoadLibrary(out.c_str())))
		l = CK_C_GetFunctionList(GetProcAddress(d->h, "C_GetFunctionList"));
#else
	if((d->h = dlopen(path.c_str(), RTLD_LAZY)))
		l = CK_C_GetFunctionList(dlsym(d->h, "C_GetFunctionList"));
#endif
	if(!l || l(&d->f) != CKR_OK || !d->f)
		return;

	CK_C_INITIALIZE_ARGS init_args = { 0, 0, 0, 0, CKF_OS_LOCKING_OK, 0 };
	d->f->C_Initialize(&init_args);

	CK_ULONG size = 0;
	if(d->f->C_GetSlotList(true, 0, &size) != CKR_OK)
		return;
	std::vector<CK_SLOT_ID> slots(size, 0);
	if(size && d->f->C_GetSlotList(true, slots.data(), &size) != CKR_OK)
		return;
	for(const CK_SLOT_ID &slot: slots)
	{
		if(d->f->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &d->session) != CKR_OK)
			continue;
		for(CK_OBJECT_HANDLE obj: d->findObject(CKO_CERTIFICATE))
		{
			d->cert = d->attribute(obj, CKA_VALUE);
			d->id = d->attribute(obj, CKA_ID);
			if(d->cert.empty() || d->id.empty())
			{
				d->f->C_CloseSession(d->session);
				d->session = 0;
				continue;
			}

			switch(d->f->C_Login(d->session, CKU_USER, CK_BYTE_PTR(password.c_str()), CK_ULONG(password.size())))
			{
			case CKR_OK:
			case CKR_USER_ALREADY_LOGGED_IN: return;
			case CKR_CANCEL:
			case CKR_FUNCTION_CANCELED:
			default:
				d->f->C_CloseSession(d->session);
				d->session = 0;
				return;
			}
		}
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
	if(d->h)
		FreeLibrary(d->h);
#else
	if(d->h)
		dlclose(d->h);
#endif
	delete d;
}

std::vector<uchar> PKCS11Token::cert() const
{
	return d->cert;
}

std::vector<uchar> PKCS11Token::decrypt(const std::vector<uchar> &data) const
{
	std::vector<uchar> result;
	if(!d->session)
		return result;
	std::vector<CK_OBJECT_HANDLE> key = d->findObject(CKO_PRIVATE_KEY, d->id);
	if(key.size() != 1)
		return result;

	CK_MECHANISM mech = { CKM_RSA_PKCS, 0, 0 };
	if(d->f->C_DecryptInit(d->session, &mech, key[0]) != CKR_OK)
		return result;

	CK_ULONG size = 0;
	if(d->f->C_Decrypt(d->session, CK_CHAR_PTR(data.data()), CK_ULONG(data.size()), 0, &size) != CKR_OK)
		return result;

	result.resize(size);
	if(d->f->C_Decrypt(d->session, CK_CHAR_PTR(data.data()), CK_ULONG(data.size()), result.data(), &size) != CKR_OK)
		result.clear();
	return result;
}

std::vector<uchar> PKCS11Token::derive(const std::vector<uchar> &publicKey) const
{
	std::vector<uchar> sharedSecret;
	if(!d->session)
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


/**
 * @class PKCS12Token
 * @brief Implements <code>Token</code> interface for PKCS#12 files.
 */

class PKCS12Token::PKCS12TokenPrivate
{
public:
	std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(nullptr, EVP_PKEY_free);
	std::unique_ptr<X509, decltype(&X509_free)> cert = std::unique_ptr<X509, decltype(&X509_free)>(nullptr, X509_free);
	std::string pass;
};

/**
 * Initializes the PKCS12 token with PKCS#12 file and password.
 *
 * @param path PKCS#12 file path
 * @param password PKCS#12 file password
 */
PKCS12Token::PKCS12Token(const std::string &path, const std::string &password)
	: d(new PKCS12TokenPrivate)
{
	SSL_load_error_strings();
	SSL_library_init();
	SCOPE(BIO, bio, BIO_new_file(path.c_str(), "rb"));
	SCOPE(PKCS12, p12, d2i_PKCS12_bio(bio.get(), 0));
	d->pass = password;

	EVP_PKEY *pkey = nullptr;
	X509 *cert = nullptr;
	PKCS12_parse(p12.get(), d->pass.c_str(), &pkey, &cert, nullptr);
	d->pkey.reset(pkey);
	d->cert.reset(cert);
}

PKCS12Token::~PKCS12Token()
{
	delete d;
}

std::vector<uchar> PKCS12Token::cert() const
{
	std::vector<uchar> result;
	if(!d->cert)
		return result;
	int size = i2d_X509(d->cert.get(), nullptr);
	if(size <= 0)
		return result;
	result.resize(size_t(size));
	uchar *p = result.data();
	if(size != i2d_X509(d->cert.get(), &p))
		result.clear();
	return result;
}

std::vector<uchar> PKCS12Token::decrypt(const std::vector<uchar> &data) const
{
	std::vector<uchar> result;
	if(!d->pkey)
		return result;
	SCOPE(EVP_PKEY, pkey, d->pkey.get());
	SCOPE(RSA, rsa, EVP_PKEY_get1_RSA(pkey.get()));
	result.resize(size_t(RSA_size(rsa.get())));
	if(RSA_private_decrypt(int(data.size()), data.data(), result.data(), rsa.get(), RSA_PKCS1_PADDING) == 1)
		result.clear();
	return result;
}

std::vector<uchar> PKCS12Token::derive(const std::vector<uchar> &publicKey) const
{
	std::vector<uchar> result;
	if(!d->pkey)
		return result;

	SCOPE(EVP_PKEY, pkey, d->pkey.get());
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

#ifdef _WIN32
extern "C" {

typedef BOOL (WINAPI * PFNCCERTDISPLAYPROC)(
  __in  PCCERT_CONTEXT pCertContext,
  __in  HWND hWndSelCertDlg,
  __in  void *pvCallbackData
);

typedef struct _CRYPTUI_SELECTCERTIFICATE_STRUCT {
  DWORD               dwSize;
  HWND                hwndParent;
  DWORD               dwFlags;
  LPCWSTR             szTitle;
  DWORD               dwDontUseColumn;
  LPCWSTR             szDisplayString;
  PFNCFILTERPROC      pFilterCallback;
  PFNCCERTDISPLAYPROC pDisplayCallback;
  void *              pvCallbackData;
  DWORD               cDisplayStores;
  HCERTSTORE *        rghDisplayStores;
  DWORD               cStores;
  HCERTSTORE *        rghStores;
  DWORD               cPropSheetPages;
  LPCPROPSHEETPAGEW   rgPropSheetPages;
  HCERTSTORE          hSelectedCertStore;
} CRYPTUI_SELECTCERTIFICATE_STRUCT, *PCRYPTUI_SELECTCERTIFICATE_STRUCT;

typedef const CRYPTUI_SELECTCERTIFICATE_STRUCT
  *PCCRYPTUI_SELECTCERTIFICATE_STRUCT;

PCCERT_CONTEXT WINAPI CryptUIDlgSelectCertificateW(
  __in  PCCRYPTUI_SELECTCERTIFICATE_STRUCT pcsc
);

#define CryptUIDlgSelectCertificate CryptUIDlgSelectCertificateW

}  // extern "C"

class WinToken::WinTokenPrivate
{
public:
	static BOOL WINAPI CertFilter(PCCERT_CONTEXT cert,
		BOOL * /*is_initial_selected_cert*/, void * /*callback_data*/)
	{
		BYTE keyUsage = 0;
		if(!CertGetIntendedKeyUsage(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, cert->pCertInfo, &keyUsage, 1))
			return false;
		if((keyUsage & (CERT_KEY_ENCIPHERMENT_KEY_USAGE|CERT_KEY_AGREEMENT_KEY_USAGE)) == 0)
			return false;

		DWORD flags = CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG|CRYPT_ACQUIRE_COMPARE_KEY_FLAG|CRYPT_ACQUIRE_SILENT_FLAG;
		HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key = 0;
		DWORD spec = 0;
		BOOL freeKey = false;
		CryptAcquireCertificatePrivateKey(cert, flags, 0, &key, &spec, &freeKey);
		if(!key)
			return false;
		switch(spec)
		{
		case CERT_NCRYPT_KEY_SPEC:
			if(freeKey)
				NCryptFreeObject(key);
			break;
		case AT_KEYEXCHANGE:
		case AT_SIGNATURE:
		default:
			if(freeKey)
				CryptReleaseContext(key, 0);
			break;
		}
		return true;
	}
	PCCERT_CONTEXT cert = nullptr;
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key = 0;
	DWORD spec = 0;
	BOOL freeKey = false;
};

WinToken::WinToken(bool ui, const std::string &pass)
	: d(new WinTokenPrivate)
{
	HCERTSTORE store = CertOpenSystemStore(0, L"MY");
	if(!store)
		return;

	PCCERT_CONTEXT cert = nullptr;
	if(ui)
	{
		CRYPTUI_SELECTCERTIFICATE_STRUCT pcsc = { sizeof(pcsc) };
		pcsc.pFilterCallback = WinTokenPrivate::CertFilter;
		pcsc.pvCallbackData = d;
		pcsc.cDisplayStores = 1;
		pcsc.rghDisplayStores = &store;
		cert = CryptUIDlgSelectCertificate(&pcsc);
		DWORD flags = CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG|CRYPT_ACQUIRE_COMPARE_KEY_FLAG|CRYPT_ACQUIRE_SILENT_FLAG;
		if(!CryptAcquireCertificatePrivateKey(cert, flags, 0, &d->key, &d->spec, &d->freeKey) || !d->key)
			return;
	}
	else
	{
		while((cert = CertFindCertificateInStore(store, X509_ASN_ENCODING|PKCS_7_ASN_ENCODING, 0, CERT_FIND_ANY, nullptr, cert)))
		{
			BYTE keyUsage = 0;
			if(!CertGetIntendedKeyUsage(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, cert->pCertInfo, &keyUsage, 1))
				continue;
			if((keyUsage & (CERT_KEY_ENCIPHERMENT_KEY_USAGE|CERT_KEY_AGREEMENT_KEY_USAGE)) == 0)
				continue;
			DWORD flags = CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG|CRYPT_ACQUIRE_COMPARE_KEY_FLAG|CRYPT_ACQUIRE_SILENT_FLAG;
			if(!CryptAcquireCertificatePrivateKey(cert, flags, 0, &d->key, &d->spec, &d->freeKey) || !d->key)
				continue;
			break;
		}
	}
	if(d->spec == CERT_NCRYPT_KEY_SPEC)
	{
		int len = MultiByteToWideChar(CP_UTF8, 0, pass.data(), int(pass.size()), 0, 0);
		std::wstring out(size_t(len), 0);
		MultiByteToWideChar(CP_UTF8, 0, pass.data(), int(pass.size()), &out[0], len);
		if(NCryptSetProperty(d->key, NCRYPT_PIN_PROPERTY, PBYTE(out.c_str()), DWORD(out.size()), 0) != ERROR_SUCCESS)
			return;
	}
	else
	{
		if(!CryptSetProvParam(d->key, d->spec == AT_SIGNATURE ? PP_SIGNATURE_PIN : PP_KEYEXCHANGE_PIN, LPBYTE(pass.c_str()), 0))
			return;
	}
	if(d->key)
		d->cert = cert;
}

WinToken::~WinToken()
{
	switch(d->spec)
	{
	case CERT_NCRYPT_KEY_SPEC:
		if(d->freeKey)
			NCryptFreeObject(d->key);
		break;
	case AT_KEYEXCHANGE:
	case AT_SIGNATURE:
	default:
		if(d->freeKey)
			CryptReleaseContext(d->key, 0);
		break;
	}
	CertFreeCertificateContext(d->cert);
	delete d;
}

std::vector<uchar> WinToken::cert() const
{
	return std::vector<uchar>(d->cert->pbCertEncoded, d->cert->pbCertEncoded + d->cert->cbCertEncoded);
}

std::vector<uchar> WinToken::decrypt(const std::vector<uchar> &data) const
{
	std::vector<uchar> result;
	if(!d->key)
		return result;

	DWORD size = DWORD(data.size());
	SECURITY_STATUS err = 0;
	switch(d->spec)
	{
	case CERT_NCRYPT_KEY_SPEC:
	{
		result.resize(size);
		err = NCryptDecrypt(d->key, PBYTE(data.data()), DWORD(data.size()), 0,
			result.data(), DWORD(result.size()), &size, NCRYPT_PAD_PKCS1_FLAG);
		break;
	}
	case AT_KEYEXCHANGE:
	case AT_SIGNATURE:
	default:
	{
		result = data;
		std::reverse(result.begin(), result.end());
		if(!CryptDecrypt(d->key, 0, true, 0, result.data(), &size))
			err = SECURITY_STATUS(GetLastError());
		break;
	}
	}

	if(err == ERROR_SUCCESS)
		result.resize(size);
	else
		result.clear();
	return result;
}

std::vector<uchar> WinToken::deriveConcatKDF(const std::vector<uchar> &publicKey, const std::string &digest, unsigned int keySize,
	const std::vector<uchar> &algorithmID, const std::vector<uchar> &partyUInfo, const std::vector<uchar> &partyVInfo) const
{
	std::vector<uchar> derived;
	if(!d->key)
		return derived;

	BCRYPT_ECCKEY_BLOB oh = { BCRYPT_ECDH_PUBLIC_P384_MAGIC, ULONG((publicKey.size() - 1) / 2) };
	switch ((publicKey.size() - 1) * 4)
	{
	case 256: oh.dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC; break;
	case 384: oh.dwMagic = BCRYPT_ECDH_PUBLIC_P384_MAGIC; break;
	case 521: oh.dwMagic = BCRYPT_ECDH_PUBLIC_P521_MAGIC; break;
	default:break;
	}
	std::vector<uchar> blob((uchar*)&oh, (uchar*)&oh + sizeof(BCRYPT_ECCKEY_BLOB));
	blob.insert(blob.cend(), publicKey.cbegin() + 1, publicKey.cend());

	NCRYPT_PROV_HANDLE prov = 0;
	DWORD size = 0;
	if(NCryptGetProperty(d->key, NCRYPT_PROVIDER_HANDLE_PROPERTY, PBYTE(&prov), sizeof(prov), &size, 0))
		return derived;

	NCRYPT_KEY_HANDLE publicKeyHandle = 0;
	NCRYPT_SECRET_HANDLE sharedSecret = 0;
	SECURITY_STATUS err = 0;
	if((err = NCryptImportKey(prov, 0, BCRYPT_ECCPUBLIC_BLOB, 0, &publicKeyHandle, PBYTE(blob.data()), DWORD(blob.size()), 0)) ||
		(err = NCryptSecretAgreement(d->key, publicKeyHandle, &sharedSecret, 0)))
	{
		if(publicKeyHandle)
			NCryptFreeObject(publicKeyHandle);
		NCryptFreeObject(prov);
		return derived;
	}

	std::vector<BCryptBuffer> paramValues{
		{ULONG(algorithmID.size()), KDF_ALGORITHMID, PBYTE(algorithmID.data())},
		{ULONG(partyUInfo.size()), KDF_PARTYUINFO, PBYTE(partyUInfo.data())},
		{ULONG(partyVInfo.size()), KDF_PARTYVINFO, PBYTE(partyVInfo.data())},
	};
	if(digest == "http://www.w3.org/2001/04/xmlenc#sha256")
		paramValues.push_back({ULONG(sizeof(BCRYPT_SHA256_ALGORITHM)), KDF_HASH_ALGORITHM, PBYTE(BCRYPT_SHA256_ALGORITHM)});
	if(digest == "http://www.w3.org/2001/04/xmlenc#sha384")
		paramValues.push_back({ULONG(sizeof(BCRYPT_SHA384_ALGORITHM)), KDF_HASH_ALGORITHM, PBYTE(BCRYPT_SHA384_ALGORITHM)});
	if(digest == "http://www.w3.org/2001/04/xmlenc#sha512")
		paramValues.push_back({ULONG(sizeof(BCRYPT_SHA512_ALGORITHM)), KDF_HASH_ALGORITHM, PBYTE(BCRYPT_SHA512_ALGORITHM)});
	BCryptBufferDesc params;
	params.ulVersion = BCRYPTBUFFER_VERSION;
	params.cBuffers = ULONG(paramValues.size());
	params.pBuffers = paramValues.data();

	size = 0;
	if((err = NCryptDeriveKey(sharedSecret, BCRYPT_KDF_SP80056A_CONCAT, &params, nullptr, 0, &size, 0)) == 0)
	{
		derived.resize(int(size));
		if((err = NCryptDeriveKey(sharedSecret, BCRYPT_KDF_SP80056A_CONCAT, &params, PBYTE(derived.data()), size, &size, 0)) == 0)
			derived.resize(keySize);
		else
			derived.clear();
	}

	NCryptFreeObject(publicKeyHandle);
	NCryptFreeObject(sharedSecret);
	NCryptFreeObject(prov);
	return derived;
}
#endif
