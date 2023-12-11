#include "global.h"

std::string Utils::BytesToString(const std::vector<BYTE>& bytes)
{
	std::string result;

	char buffer[3];
	for (BYTE byte : bytes)
	{
		sprintf_s(buffer, "%02x", byte);
		result += buffer;
	}

	return result;
}

std::vector<BYTE> Utils::GetEK()
{
	NCRYPT_PROV_HANDLE hProvider = NULL;
	if (NCryptOpenStorageProvider(&hProvider, L"Microsoft Platform Crypto Provider", 0) != ERROR_SUCCESS)
		return {};

	DWORD cbResult = 0;
	if (NCryptGetProperty(hProvider, L"PCP_EKPUB", nullptr, 0, &cbResult, 0) != ERROR_SUCCESS)
		return {};

	std::vector<BYTE> ekPub(cbResult);
	if (NCryptGetProperty(hProvider, L"PCP_EKPUB", ekPub.data(), cbResult, &cbResult, 0) != ERROR_SUCCESS)
		return {};

	DWORD cbEncoded = 0;
	if (!CryptEncodeObjectEx(X509_ASN_ENCODING, CNG_RSA_PUBLIC_KEY_BLOB, ekPub.data(), 0, nullptr, nullptr, &cbEncoded))
		return {};

	std::vector<BYTE> encodedEk(cbEncoded);
	if (!CryptEncodeObjectEx(X509_ASN_ENCODING, CNG_RSA_PUBLIC_KEY_BLOB, ekPub.data(), 0, nullptr, encodedEk.data(), &cbEncoded))
		return {};

	return encodedEk;
}

std::string Utils::GetKeyHash(const std::vector<BYTE>& input, ALG_ID algo)
{
	HCRYPTPROV provider = NULL;
	HCRYPTHASH handle = NULL;
	DWORD size = 0;
	if (!CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
		return "ERROR";

	if (!CryptCreateHash(provider, algo, 0, 0, &handle))
		return "ERROR";

	if (!CryptHashData(handle, input.data(), input.size(), 0))
		return "ERROR";

	if (!CryptGetHashParam(handle, HP_HASHVAL, nullptr, &size, 0))
		return "ERROR";

	std::vector<BYTE> hash(size);
	if (!CryptGetHashParam(handle, HP_HASHVAL, hash.data(), &size, 0))
		return "ERROR";

	if (handle)
		CryptDestroyHash(handle);

	if (provider)
		CryptReleaseContext(provider, 0);

	return BytesToString(hash);
}