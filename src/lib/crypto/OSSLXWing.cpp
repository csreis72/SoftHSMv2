/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 OSSLXWing.cpp

 OpenSSL X-Wing asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#ifdef WITH_X_WING
#include "CryptoFactory.h"
#include "log.h"
#include "OSSLXWing.h"
#include "OSSLXWingKeyPair.h"
#include "XWingParameters.h"
#include <openssl/crypto.h>
#include <openssl/err.h>

bool OSSLXWing::encapsulateMLKEM(EVP_PKEY* mlkemPkey,
	ByteString& cipherText, ByteString& sharedSecret)
{
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(NULL, mlkemPkey, NULL);
	size_t cipherTextLen = 0;
	size_t sharedSecretLen = 0;
	bool rv = ctx != NULL && EVP_PKEY_encapsulate_init(ctx, NULL) > 0 &&
		EVP_PKEY_encapsulate(ctx, NULL, &cipherTextLen, NULL,
		                     &sharedSecretLen) > 0 &&
		cipherTextLen == XWingParameters::ML_KEM_768_CIPHERTEXT_LENGTH &&
		sharedSecretLen == XWingParameters::X_WING_SHARED_SECRET_LENGTH;

	if (rv)
	{
		cipherText.resize(cipherTextLen);
		sharedSecret.resize(sharedSecretLen);
		rv = EVP_PKEY_encapsulate(ctx, cipherText.byte_str(), &cipherTextLen,
		                          sharedSecret.byte_str(), &sharedSecretLen) > 0 &&
			cipherTextLen == XWingParameters::ML_KEM_768_CIPHERTEXT_LENGTH &&
			sharedSecretLen == XWingParameters::X_WING_SHARED_SECRET_LENGTH;
	}

	EVP_PKEY_CTX_free(ctx);
	if (!rv)
	{
		ERROR_MSG("Could not encapsulate the X-Wing ML-KEM-768 component "
		          "(0x%08lX)", ERR_get_error());
		cipherText.wipe();
		sharedSecret.wipe();
	}
	return rv;
}

bool OSSLXWing::encapsulateX25519(EVP_PKEY* x25519Pkey,
	ByteString& cipherText, ByteString& sharedSecret, RNG* rng)
{
	ByteString ephemeralPrivateKey;
	EVP_PKEY* ephemeralPkey = NULL;
	EVP_PKEY_CTX* ctx = NULL;
	size_t cipherTextLen = XWingParameters::X25519_PUB_LENGTH;
	size_t sharedSecretLen = 0;
	static const unsigned char zero[
		XWingParameters::X_WING_SHARED_SECRET_LENGTH] = { 0 };

	bool rv = rng != NULL &&
		rng->generateRandom(ephemeralPrivateKey,
		                    XWingParameters::X25519_PRIV_LENGTH);
	if (rv)
	{
		ephemeralPkey = EVP_PKEY_new_raw_private_key_ex(
			NULL, "X25519", NULL, ephemeralPrivateKey.const_byte_str(),
			ephemeralPrivateKey.size());
		rv = ephemeralPkey != NULL;
	}
	if (rv)
	{
		cipherText.resize(cipherTextLen);
		rv = EVP_PKEY_get_raw_public_key(ephemeralPkey, cipherText.byte_str(),
		                                 &cipherTextLen) > 0 &&
			cipherTextLen == XWingParameters::X25519_PUB_LENGTH;
	}
	if (rv)
	{
		ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ephemeralPkey, NULL);
		rv = ctx != NULL && EVP_PKEY_derive_init(ctx) > 0 &&
			EVP_PKEY_derive_set_peer(ctx, x25519Pkey) > 0 &&
			EVP_PKEY_derive(ctx, NULL, &sharedSecretLen) > 0 &&
			sharedSecretLen == XWingParameters::X_WING_SHARED_SECRET_LENGTH;
	}
	if (rv)
	{
		sharedSecret.resize(sharedSecretLen);
		rv = EVP_PKEY_derive(ctx, sharedSecret.byte_str(),
		                     &sharedSecretLen) > 0 &&
			sharedSecretLen == XWingParameters::X_WING_SHARED_SECRET_LENGTH &&
			CRYPTO_memcmp(sharedSecret.const_byte_str(), zero,
			              sizeof(zero)) != 0;
	}

	ephemeralPrivateKey.wipe();
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(ephemeralPkey);
	if (!rv)
	{
		ERROR_MSG("Could not encapsulate the X-Wing X25519 component "
		          "(0x%08lX)", ERR_get_error());
		cipherText.wipe();
		sharedSecret.wipe();
	}
	return rv;
}

bool OSSLXWing::encapsulateComponents(EVP_PKEY* mlkemPkey,
	EVP_PKEY* x25519Pkey, ByteString& mlkemCipherText,
	ByteString& mlkemSharedSecret, ByteString& x25519CipherText,
	ByteString& x25519SharedSecret, RNG* rng)
{
	mlkemCipherText.wipe();
	mlkemSharedSecret.wipe();
	x25519CipherText.wipe();
	x25519SharedSecret.wipe();
	if (mlkemPkey == NULL || x25519Pkey == NULL) return false;
	if (rng == NULL) rng = CryptoFactory::i()->getRNG();

	if (encapsulateMLKEM(mlkemPkey, mlkemCipherText,
	                    mlkemSharedSecret) &&
		encapsulateX25519(x25519Pkey, x25519CipherText,
		                   x25519SharedSecret, rng))
	{
		return true;
	}

	mlkemCipherText.wipe();
	mlkemSharedSecret.wipe();
	x25519CipherText.wipe();
	x25519SharedSecret.wipe();
	return false;
}

bool OSSLXWing::encrypt(PublicKey* /*publicKey*/, const ByteString& /*data*/,
	ByteString& /*encryptedData*/, const AsymMech::Type /*padding*/,
	const MechanismParam* /*mechanismParam*/)
{
	ERROR_MSG("X-Wing does not support encryption");
	return false;
}

bool OSSLXWing::decrypt(PrivateKey* /*privateKey*/,
	const ByteString& /*encryptedData*/, ByteString& /*data*/,
	const AsymMech::Type /*padding*/, const MechanismParam* /*mechanismParam*/)
{
	ERROR_MSG("X-Wing does not support decryption");
	return false;
}

bool OSSLXWing::generateKeyPair(AsymmetricKeyPair** ppKeyPair,
	AsymmetricParameters* parameters, RNG* rng)
{
	if (ppKeyPair == NULL || parameters == NULL ||
		!parameters->areOfType(XWingParameters::type))
	{
		return false;
	}
	if (rng == NULL) rng = CryptoFactory::i()->getRNG();
	if (rng == NULL) return false;

	ByteString seed;
	if (!rng->generateRandom(seed, XWingParameters::X_WING_PRIV_LENGTH))
		return false;

	OSSLXWingPrivateKey privateKey;
	privateKey.setValue(seed);
	OSSLXWingKeyPair* kp = new OSSLXWingKeyPair();
	const bool rv = kp->setPrivateKey(privateKey);
	seed.wipe();
	if (!rv)
	{
		delete kp;
		return false;
	}

	*ppKeyPair = kp;
	return true;
}

unsigned long OSSLXWing::getMinKeySize()
{
	return XWingParameters::X_WING_PRIV_LENGTH;
}

unsigned long OSSLXWing::getMaxKeySize()
{
	return XWingParameters::X_WING_PRIV_LENGTH;
}

bool OSSLXWing::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair,
	ByteString& serialisedData)
{
	if (ppKeyPair == NULL || serialisedData.size() == 0) return false;

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);
	OSSLXWingPublicKey pubKey;
	OSSLXWingPrivateKey privKey;
	if (serialisedData.size() != 0 ||
		!pubKey.deserialise(dPub) || dPub.size() != 0 ||
		!privKey.deserialise(dPriv) || dPriv.size() != 0)
	{
		return false;
	}

	OSSLXWingKeyPair* kp = new OSSLXWingKeyPair();
	if (!kp->setPrivateKey(privKey) ||
		kp->getConstPublicKey()->serialise() != pubKey.serialise())
	{
		delete kp;
		return false;
	}

	*ppKeyPair = kp;
	return true;
}

bool OSSLXWing::reconstructPublicKey(PublicKey** ppPublicKey,
	ByteString& serialisedData)
{
	if (ppPublicKey == NULL || serialisedData.size() == 0) return false;
	OSSLXWingPublicKey* publicKey = new OSSLXWingPublicKey();
	if (!publicKey->deserialise(serialisedData) || serialisedData.size() != 0)
	{
		delete publicKey;
		return false;
	}
	*ppPublicKey = publicKey;
	return true;
}

bool OSSLXWing::reconstructPrivateKey(PrivateKey** ppPrivateKey,
	ByteString& serialisedData)
{
	if (ppPrivateKey == NULL || serialisedData.size() == 0) return false;
	OSSLXWingPrivateKey* privateKey = new OSSLXWingPrivateKey();
	if (!privateKey->deserialise(serialisedData) || serialisedData.size() != 0)
	{
		delete privateKey;
		return false;
	}
	*ppPrivateKey = privateKey;
	return true;
}

bool OSSLXWing::reconstructParameters(AsymmetricParameters** ppParams,
	ByteString& serialisedData)
{
	if (ppParams == NULL) return false;
	XWingParameters* parameters = new XWingParameters();
	if (!parameters->deserialise(serialisedData))
	{
		delete parameters;
		return false;
	}
	*ppParams = parameters;
	return true;
}

PublicKey* OSSLXWing::newPublicKey()
{
	return new OSSLXWingPublicKey();
}

PrivateKey* OSSLXWing::newPrivateKey()
{
	return new OSSLXWingPrivateKey();
}

AsymmetricParameters* OSSLXWing::newParameters()
{
	return new XWingParameters();
}

#endif
