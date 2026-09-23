/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 OSSLXWingUtil.cpp

 OpenSSL helpers for X-Wing keys
 *****************************************************************************/

#include "config.h"
#ifdef WITH_X_WING
#include "log.h"
#include "OSSLXWingUtil.h"
#include "XWingParameters.h"
#include <openssl/core_names.h>
#include <openssl/crypto.h>

namespace
{
bool shake256(const ByteString& input, unsigned char* output, size_t outputLength)
{
	EVP_MD* shake = EVP_MD_fetch(NULL, "SHAKE256", NULL);
	EVP_MD_CTX* context = EVP_MD_CTX_new();
	const bool result = shake != NULL && context != NULL &&
		EVP_DigestInit_ex(context, shake, NULL) > 0 &&
		EVP_DigestUpdate(context, input.const_byte_str(), input.size()) > 0 &&
		EVP_DigestFinalXOF(context, output, outputLength) > 0;
	EVP_MD_CTX_free(context);
	EVP_MD_free(shake);
	return result;
}

bool generateMLKEM(const unsigned char* seed, EVP_PKEY** key)
{
	EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
	OSSL_PARAM parameters[] = {
		OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED,
		                                  const_cast<unsigned char*>(seed), 64),
		OSSL_PARAM_construct_end()
	};
	const bool result = context != NULL && EVP_PKEY_keygen_init(context) > 0 &&
		EVP_PKEY_CTX_set_params(context, parameters) > 0 &&
		EVP_PKEY_generate(context, key) > 0;
	EVP_PKEY_CTX_free(context);
	return result;
}

bool importMLKEMPublicKey(const ByteString& value, EVP_PKEY** key)
{
	EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
	OSSL_PARAM parameters[] = {
		OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
		                                  const_cast<unsigned char*>(value.const_byte_str()),
		                                  value.size()),
		OSSL_PARAM_construct_end()
	};
	const bool result = context != NULL && EVP_PKEY_fromdata_init(context) > 0 &&
		EVP_PKEY_fromdata(context, key, EVP_PKEY_PUBLIC_KEY, parameters) > 0;
	EVP_PKEY_CTX_free(context);
	return result;
}
}

bool OSSLXWing::expandPrivateKey(const ByteString& seed, EVP_PKEY** mlkemKey,
	EVP_PKEY** x25519Key, ByteString& publicKey)
{
	if (mlkemKey == NULL || x25519Key == NULL ||
		seed.size() != XWingParameters::PRIVATE_KEY_LENGTH)
	{
		return false;
	}

	*mlkemKey = NULL;
	*x25519Key = NULL;
	unsigned char expanded[96];
	unsigned char mlkemPublic[XWingParameters::ML_KEM_768_PUBLIC_KEY_LENGTH];
	unsigned char x25519Public[XWingParameters::X25519_PUBLIC_KEY_LENGTH];
	size_t mlkemPublicLength = sizeof(mlkemPublic);
	size_t x25519PublicLength = sizeof(x25519Public);

	bool result = shake256(seed, expanded, sizeof(expanded)) &&
		generateMLKEM(expanded, mlkemKey);
	if (result)
	{
		*x25519Key = EVP_PKEY_new_raw_private_key_ex(NULL, "X25519", NULL,
		                                             expanded + 64, 32);
		result = *x25519Key != NULL &&
			EVP_PKEY_get_octet_string_param(*mlkemKey, OSSL_PKEY_PARAM_PUB_KEY,
			                                mlkemPublic, sizeof(mlkemPublic),
			                                &mlkemPublicLength) > 0 &&
			mlkemPublicLength == sizeof(mlkemPublic) &&
			EVP_PKEY_get_raw_public_key(*x25519Key, x25519Public,
			                            &x25519PublicLength) > 0 &&
			x25519PublicLength == sizeof(x25519Public);
	}

	if (result)
	{
		publicKey = ByteString(mlkemPublic, mlkemPublicLength) +
		            ByteString(x25519Public, x25519PublicLength);
	}
	else
	{
		ERROR_MSG("Could not expand X-Wing private key");
		EVP_PKEY_free(*mlkemKey);
		EVP_PKEY_free(*x25519Key);
		*mlkemKey = NULL;
		*x25519Key = NULL;
		publicKey.wipe();
	}

	OPENSSL_cleanse(expanded, sizeof(expanded));
	OPENSSL_cleanse(mlkemPublic, sizeof(mlkemPublic));
	OPENSSL_cleanse(x25519Public, sizeof(x25519Public));
	return result;
}

bool OSSLXWing::importPublicKey(const ByteString& publicKey, EVP_PKEY** mlkemKey,
	EVP_PKEY** x25519Key)
{
	if (mlkemKey == NULL || x25519Key == NULL ||
		publicKey.size() != XWingParameters::PUBLIC_KEY_LENGTH)
	{
		return false;
	}

	*mlkemKey = NULL;
	*x25519Key = NULL;
	const ByteString mlkem = publicKey.substr(
		0, XWingParameters::ML_KEM_768_PUBLIC_KEY_LENGTH);
	const ByteString x25519 = publicKey.substr(
		XWingParameters::ML_KEM_768_PUBLIC_KEY_LENGTH,
		XWingParameters::X25519_PUBLIC_KEY_LENGTH);

	bool result = importMLKEMPublicKey(mlkem, mlkemKey);
	if (result)
	{
		*x25519Key = EVP_PKEY_new_raw_public_key_ex(NULL, "X25519", NULL,
		                                            x25519.const_byte_str(),
		                                            x25519.size());
		result = *x25519Key != NULL;
	}
	if (!result)
	{
		ERROR_MSG("Could not import X-Wing public key components");
		EVP_PKEY_free(*mlkemKey);
		EVP_PKEY_free(*x25519Key);
		*mlkemKey = NULL;
		*x25519Key = NULL;
	}
	return result;
}

#endif
