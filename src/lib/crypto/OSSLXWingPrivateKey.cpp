/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 OSSLXWingPrivateKey.cpp

 OpenSSL X-Wing private key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_X_WING
#include "OSSLXWingPrivateKey.h"
#include "OSSLXWingUtil.h"
#include "XWingParameters.h"
#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <string.h>
#include <utility>

namespace
{
const char* X_WING_OID = "1.3.6.1.4.1.62253.25722";
}

OSSLXWingPrivateKey::OSSLXWingPrivateKey() : mlkemKey(NULL), x25519Key(NULL)
{
}

OSSLXWingPrivateKey::~OSSLXWingPrivateKey()
{
	invalidateExpandedKey();
}

OSSLXWingPrivateKey::OSSLXWingPrivateKey(OSSLXWingPrivateKey&& other) noexcept
	: XWingPrivateKey(std::move(other)), mlkemKey(other.mlkemKey),
	  x25519Key(other.x25519Key), publicValue(std::move(other.publicValue))
{
	other.mlkemKey = NULL;
	other.x25519Key = NULL;
}

OSSLXWingPrivateKey& OSSLXWingPrivateKey::operator=(OSSLXWingPrivateKey&& other) noexcept
{
	if (this != &other)
	{
		XWingPrivateKey::operator=(std::move(other));
		invalidateExpandedKey();
		mlkemKey = other.mlkemKey;
		x25519Key = other.x25519Key;
		publicValue = std::move(other.publicValue);
		other.mlkemKey = NULL;
		other.x25519Key = NULL;
	}
	return *this;
}

/*static*/ const char* OSSLXWingPrivateKey::type = "OpenSSL X-Wing private key";

bool OSSLXWingPrivateKey::isOfType(const char* inType)
{
	return inType != NULL &&
		(strcmp(type, inType) == 0 || XWingPrivateKey::isOfType(inType));
}

void OSSLXWingPrivateKey::invalidateExpandedKey()
{
	EVP_PKEY_free(mlkemKey);
	EVP_PKEY_free(x25519Key);
	mlkemKey = NULL;
	x25519Key = NULL;
	publicValue.wipe();
}

void OSSLXWingPrivateKey::setValue(const ByteString& inValue)
{
	XWingPrivateKey::setValue(inValue);
	invalidateExpandedKey();
}

bool OSSLXWingPrivateKey::expandKey()
{
	if (mlkemKey != NULL && x25519Key != NULL &&
		publicValue.size() == XWingParameters::PUBLIC_KEY_LENGTH)
	{
		return true;
	}
	invalidateExpandedKey();
	return OSSLXWing::expandPrivateKey(getValue(), &mlkemKey, &x25519Key,
	                                  publicValue);
}

bool OSSLXWingPrivateKey::getPublicValue(ByteString& outPublicValue)
{
	if (!expandKey()) return false;
	outPublicValue = publicValue;
	return true;
}

EVP_PKEY* OSSLXWingPrivateKey::getOSSLMLKEMKey()
{
	return expandKey() ? mlkemKey : NULL;
}

EVP_PKEY* OSSLXWingPrivateKey::getOSSLX25519Key()
{
	return expandKey() ? x25519Key : NULL;
}

ByteString OSSLXWingPrivateKey::PKCS8Encode()
{
	ByteString der;
	if (getValue().size() != XWingParameters::PRIVATE_KEY_LENGTH) return der;

	PKCS8_PRIV_KEY_INFO* p8 = PKCS8_PRIV_KEY_INFO_new();
	ASN1_OBJECT* oid = OBJ_txt2obj(X_WING_OID, 1);
	unsigned char* privateKey = static_cast<unsigned char*>(
		OPENSSL_memdup(getValue().const_byte_str(), getValue().size()));
	if (p8 == NULL || oid == NULL || privateKey == NULL ||
		PKCS8_pkey_set0(p8, oid, 0, V_ASN1_UNDEF, NULL, privateKey,
		                 XWingParameters::PRIVATE_KEY_LENGTH) <= 0)
	{
		PKCS8_PRIV_KEY_INFO_free(p8);
		ASN1_OBJECT_free(oid);
		OPENSSL_clear_free(privateKey, getValue().size());
		return der;
	}

	const int length = i2d_PKCS8_PRIV_KEY_INFO(p8, NULL);
	if (length > 0)
	{
		der.resize(length);
		unsigned char* output = der.byte_str();
		if (i2d_PKCS8_PRIV_KEY_INFO(p8, &output) != length) der.wipe();
	}
	PKCS8_PRIV_KEY_INFO_free(p8);
	return der;
}

bool OSSLXWingPrivateKey::PKCS8Decode(const ByteString& ber)
{
	if (ber.size() == 0) return false;
	const unsigned char* input = ber.const_byte_str();
	const unsigned char* end = input + ber.size();
	PKCS8_PRIV_KEY_INFO* p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &input, ber.size());
	if (p8 == NULL || input != end)
	{
		PKCS8_PRIV_KEY_INFO_free(p8);
		return false;
	}

	const ASN1_OBJECT* algorithm = NULL;
	const unsigned char* privateKey = NULL;
	const X509_ALGOR* algorithmIdentifier = NULL;
	int privateKeyLength = 0;
	int parameterType = V_ASN1_UNDEF;
	const void* parameterValue = NULL;
	const bool extracted = PKCS8_pkey_get0(&algorithm, &privateKey,
		&privateKeyLength, &algorithmIdentifier, p8) > 0;
	if (algorithmIdentifier != NULL)
		X509_ALGOR_get0(NULL, &parameterType, &parameterValue,
		                algorithmIdentifier);
	ASN1_OBJECT* expectedAlgorithm = OBJ_txt2obj(X_WING_OID, 1);
	const bool valid = extracted && expectedAlgorithm != NULL &&
		OBJ_cmp(algorithm, expectedAlgorithm) == 0 &&
		parameterType == V_ASN1_UNDEF &&
		privateKeyLength == static_cast<int>(XWingParameters::PRIVATE_KEY_LENGTH);

	if (valid) setValue(ByteString(privateKey, privateKeyLength));
	ASN1_OBJECT_free(expectedAlgorithm);
	PKCS8_PRIV_KEY_INFO_free(p8);
	return valid;
}

#endif
