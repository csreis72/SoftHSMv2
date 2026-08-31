/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 OSSLFalconPublicKey.cpp

 OpenSSL Falcon public key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_FALCON
#include "FalconParameters.h"
#include "log.h"
#include "OSSLFalconPublicKey.h"
#include "OSSLUtil.h"
#include <openssl/core_names.h>
#include <cstring>
#include <utility>

OSSLFalconPublicKey::OSSLFalconPublicKey() : pkey(NULL)
{
}

OSSLFalconPublicKey::OSSLFalconPublicKey(const EVP_PKEY* inFalconKey) : pkey(NULL)
{
	setFromOSSL(inFalconKey);
}

OSSLFalconPublicKey::~OSSLFalconPublicKey()
{
	EVP_PKEY_free(pkey);
}

OSSLFalconPublicKey::OSSLFalconPublicKey(OSSLFalconPublicKey&& other) noexcept
	: FalconPublicKey(std::move(other)), pkey(other.pkey)
{
	other.pkey = NULL;
}

OSSLFalconPublicKey& OSSLFalconPublicKey::operator=(OSSLFalconPublicKey&& other) noexcept
{
	if (this != &other)
	{
		FalconPublicKey::operator=(std::move(other));
		EVP_PKEY_free(pkey);
		pkey = other.pkey;
		other.pkey = NULL;
	}
	return *this;
}

/*static*/ const char* OSSLFalconPublicKey::type = "OpenSSL Falcon public key";

bool OSSLFalconPublicKey::setFromOSSL(const EVP_PKEY* inFalconKey)
{
	if (inFalconKey == NULL || !EVP_PKEY_is_a(inFalconKey, "falcon512")) return false;

	unsigned char publicKey[FalconParameters::FALCON_512_PUB_LENGTH];
	size_t publicKeyLength = 0;
	if (EVP_PKEY_get_octet_string_param(inFalconKey, OSSL_PKEY_PARAM_PUB_KEY,
		publicKey, sizeof(publicKey), &publicKeyLength) <= 0 ||
		publicKeyLength != sizeof(publicKey))
	{
		ERROR_MSG("Could not get Falcon-512 public key");
		return false;
	}

	setValue(ByteString(publicKey, publicKeyLength));
	return true;
}

bool OSSLFalconPublicKey::isOfType(const char* inType)
{
	return inType != NULL &&
		(strcmp(type, inType) == 0 || FalconPublicKey::isOfType(inType));
}

void OSSLFalconPublicKey::setValue(const ByteString& inValue)
{
	FalconPublicKey::setValue(inValue);
	EVP_PKEY_free(pkey);
	pkey = NULL;
}

EVP_PKEY* OSSLFalconPublicKey::getOSSLKey()
{
	if (pkey == NULL) createOSSLKey();
	return pkey;
}

void OSSLFalconPublicKey::createOSSLKey()
{
	if (pkey != NULL) return;
	if (getParameterSet() != FalconParameters::FALCON_512_PARAMETER_SET)
	{
		ERROR_MSG("Invalid Falcon-512 public key length: %zu", getValue().size());
		return;
	}

	const char* name = OSSL::falconParameterSet2Name(getParameterSet());
	if (name == NULL) return;
	ByteString localValue = getValue();

	OSSL_PARAM params[] = {
		OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
			localValue.byte_str(), localValue.size()),
		OSSL_PARAM_construct_end()
	};
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
	if (ctx == NULL || EVP_PKEY_fromdata_init(ctx) <= 0 ||
		EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
	{
		ERROR_MSG("Could not create Falcon-512 public EVP_PKEY");
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
	EVP_PKEY_CTX_free(ctx);
}

#endif
