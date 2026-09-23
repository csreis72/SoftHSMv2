/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 OSSLXWingPublicKey.cpp

 OpenSSL X-Wing public key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_X_WING
#include "OSSLXWingPublicKey.h"
#include "OSSLXWingUtil.h"
#include <string.h>
#include <utility>

OSSLXWingPublicKey::OSSLXWingPublicKey() : mlkemKey(NULL), x25519Key(NULL)
{
}

OSSLXWingPublicKey::~OSSLXWingPublicKey()
{
	invalidateOSSLKeys();
}

OSSLXWingPublicKey::OSSLXWingPublicKey(OSSLXWingPublicKey&& other) noexcept
	: XWingPublicKey(std::move(other)), mlkemKey(other.mlkemKey),
	  x25519Key(other.x25519Key)
{
	other.mlkemKey = NULL;
	other.x25519Key = NULL;
}

OSSLXWingPublicKey& OSSLXWingPublicKey::operator=(OSSLXWingPublicKey&& other) noexcept
{
	if (this != &other)
	{
		XWingPublicKey::operator=(std::move(other));
		invalidateOSSLKeys();
		mlkemKey = other.mlkemKey;
		x25519Key = other.x25519Key;
		other.mlkemKey = NULL;
		other.x25519Key = NULL;
	}
	return *this;
}

/*static*/ const char* OSSLXWingPublicKey::type = "OpenSSL X-Wing public key";

bool OSSLXWingPublicKey::isOfType(const char* inType)
{
	return inType != NULL &&
		(strcmp(type, inType) == 0 || XWingPublicKey::isOfType(inType));
}

void OSSLXWingPublicKey::invalidateOSSLKeys()
{
	EVP_PKEY_free(mlkemKey);
	EVP_PKEY_free(x25519Key);
	mlkemKey = NULL;
	x25519Key = NULL;
}

void OSSLXWingPublicKey::setValue(const ByteString& inValue)
{
	XWingPublicKey::setValue(inValue);
	invalidateOSSLKeys();
}

bool OSSLXWingPublicKey::createOSSLKeys()
{
	if (mlkemKey != NULL && x25519Key != NULL) return true;
	invalidateOSSLKeys();
	return OSSLXWing::importPublicKey(getValue(), &mlkemKey, &x25519Key);
}

EVP_PKEY* OSSLXWingPublicKey::getOSSLMLKEMKey()
{
	return createOSSLKeys() ? mlkemKey : NULL;
}

EVP_PKEY* OSSLXWingPublicKey::getOSSLX25519Key()
{
	return createOSSLKeys() ? x25519Key : NULL;
}

#endif
