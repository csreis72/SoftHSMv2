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
	if (!rng->generateRandom(seed, XWingParameters::PRIVATE_KEY_LENGTH))
		return false;

	OSSLXWingKeyPair* keyPair = new OSSLXWingKeyPair();
	const bool result = keyPair->setPrivateKeyValue(seed);
	seed.wipe();
	if (!result)
	{
		delete keyPair;
		return false;
	}

	*ppKeyPair = keyPair;
	return true;
}

unsigned long OSSLXWing::getMinKeySize()
{
	return XWingParameters::PRIVATE_KEY_LENGTH;
}

unsigned long OSSLXWing::getMaxKeySize()
{
	return XWingParameters::PRIVATE_KEY_LENGTH;
}

bool OSSLXWing::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair,
	ByteString& serialisedData)
{
	if (ppKeyPair == NULL || serialisedData.size() == 0) return false;

	ByteString serialisedPublic = ByteString::chainDeserialise(serialisedData);
	ByteString serialisedPrivate = ByteString::chainDeserialise(serialisedData);
	OSSLXWingPublicKey publicKey;
	OSSLXWingPrivateKey privateKey;
	if (serialisedData.size() != 0 ||
		!publicKey.deserialise(serialisedPublic) || serialisedPublic.size() != 0 ||
		!privateKey.deserialise(serialisedPrivate) || serialisedPrivate.size() != 0)
	{
		return false;
	}

	OSSLXWingKeyPair* keyPair = new OSSLXWingKeyPair();
	if (!keyPair->setPrivateKeyValue(privateKey.getValue()) ||
		keyPair->getConstPublicKey()->serialise() != publicKey.serialise())
	{
		delete keyPair;
		return false;
	}

	*ppKeyPair = keyPair;
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
