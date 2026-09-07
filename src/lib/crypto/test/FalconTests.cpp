/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 FalconTests.cpp

 Contains test cases to test the Falcon class
 *****************************************************************************/

#include <cstdio>
#include <cppunit/extensions/HelperMacros.h>
#include "FalconTests.h"
#include "AsymmetricKeyPair.h"
#include "CryptoFactory.h"

#ifdef WITH_FALCON
#include "FalconParameters.h"
#include "FalconPrivateKey.h"
#include "FalconPublicKey.h"

CPPUNIT_TEST_SUITE_REGISTRATION(FalconTests);

void FalconTests::setUp()
{
	falcon = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::FALCON);
	CPPUNIT_ASSERT(falcon != NULL);
}

void FalconTests::tearDown()
{
	if (falcon != NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(falcon);
		falcon = NULL;
	}

	fflush(stdout);
}

void FalconTests::testKeyGeneration()
{
	FalconParameters* parameters = new FalconParameters();
	parameters->setParameterSet(FalconParameters::FALCON_512_PARAMETER_SET);

	AsymmetricKeyPair* keyPair = NULL;
	CPPUNIT_ASSERT(falcon->generateKeyPair(&keyPair, parameters));
	CPPUNIT_ASSERT(keyPair != NULL);

	FalconPublicKey* publicKey =
		static_cast<FalconPublicKey*>(keyPair->getPublicKey());
	FalconPrivateKey* privateKey =
		static_cast<FalconPrivateKey*>(keyPair->getPrivateKey());
	CPPUNIT_ASSERT(publicKey != NULL);
	CPPUNIT_ASSERT(privateKey != NULL);
	CPPUNIT_ASSERT(publicKey->isOfType(FalconPublicKey::type));
	CPPUNIT_ASSERT(privateKey->isOfType(FalconPrivateKey::type));
	CPPUNIT_ASSERT(publicKey->getParameterSet() ==
		FalconParameters::FALCON_512_PARAMETER_SET);
	CPPUNIT_ASSERT(privateKey->getParameterSet() ==
		FalconParameters::FALCON_512_PARAMETER_SET);
	CPPUNIT_ASSERT(publicKey->getValue().size() ==
		FalconParameters::FALCON_512_PUB_LENGTH);
	CPPUNIT_ASSERT(privateKey->getValue().size() ==
		FalconParameters::FALCON_512_PRIV_LENGTH);
	CPPUNIT_ASSERT(publicKey->getOutputLength() ==
		FalconParameters::FALCON_512_SIGNATURE_LENGTH);
	CPPUNIT_ASSERT(privateKey->getOutputLength() ==
		FalconParameters::FALCON_512_SIGNATURE_LENGTH);
	CPPUNIT_ASSERT(falcon->getMinKeySize() ==
		FalconParameters::FALCON_512_PUB_LENGTH);
	CPPUNIT_ASSERT(falcon->getMaxKeySize() ==
		FalconParameters::FALCON_512_PUB_LENGTH);

	falcon->recycleKeyPair(keyPair);
	falcon->recycleParameters(parameters);
}

void FalconTests::testSerialisation()
{
	FalconParameters* parameters = new FalconParameters();
	parameters->setParameterSet(FalconParameters::FALCON_512_PARAMETER_SET);
	ByteString serialisedParameters = parameters->serialise();

	AsymmetricParameters* reconstructedParameters = NULL;
	CPPUNIT_ASSERT(falcon->reconstructParameters(&reconstructedParameters,
		serialisedParameters));
	CPPUNIT_ASSERT(reconstructedParameters != NULL);
	CPPUNIT_ASSERT(reconstructedParameters->areOfType(FalconParameters::type));
	CPPUNIT_ASSERT(static_cast<FalconParameters*>(reconstructedParameters)->
		getParameterSet() == FalconParameters::FALCON_512_PARAMETER_SET);

	AsymmetricKeyPair* keyPair = NULL;
	CPPUNIT_ASSERT(falcon->generateKeyPair(&keyPair, reconstructedParameters));
	CPPUNIT_ASSERT(keyPair != NULL);

	FalconPublicKey* publicKey =
		static_cast<FalconPublicKey*>(keyPair->getPublicKey());
	FalconPrivateKey* privateKey =
		static_cast<FalconPrivateKey*>(keyPair->getPrivateKey());
	ByteString serialisedKeyPair = keyPair->serialise();

	AsymmetricKeyPair* reconstructedKeyPair = NULL;
	CPPUNIT_ASSERT(falcon->reconstructKeyPair(&reconstructedKeyPair,
		serialisedKeyPair));
	CPPUNIT_ASSERT(reconstructedKeyPair != NULL);
	CPPUNIT_ASSERT(serialisedKeyPair.size() == 0);

	FalconPublicKey* reconstructedPublicKey =
		static_cast<FalconPublicKey*>(reconstructedKeyPair->getPublicKey());
	FalconPrivateKey* reconstructedPrivateKey =
		static_cast<FalconPrivateKey*>(reconstructedKeyPair->getPrivateKey());
	CPPUNIT_ASSERT(publicKey->getValue() == reconstructedPublicKey->getValue());
	CPPUNIT_ASSERT(privateKey->getValue() == reconstructedPrivateKey->getValue());
	CPPUNIT_ASSERT(reconstructedPrivateKey->PKCS8Encode().size() != 0);

	ByteString serialisedPublicKey = publicKey->serialise();
	PublicKey* reconstructedPublic = NULL;
	CPPUNIT_ASSERT(falcon->reconstructPublicKey(&reconstructedPublic,
		serialisedPublicKey));
	CPPUNIT_ASSERT(serialisedPublicKey.size() == 0);
	CPPUNIT_ASSERT(publicKey->getValue() ==
		static_cast<FalconPublicKey*>(reconstructedPublic)->getValue());

	ByteString serialisedPrivateKey = privateKey->serialise();
	PrivateKey* reconstructedPrivate = NULL;
	CPPUNIT_ASSERT(falcon->reconstructPrivateKey(&reconstructedPrivate,
		serialisedPrivateKey));
	CPPUNIT_ASSERT(serialisedPrivateKey.size() == 0);
	CPPUNIT_ASSERT(privateKey->getValue() ==
		static_cast<FalconPrivateKey*>(reconstructedPrivate)->getValue());

	falcon->recyclePublicKey(reconstructedPublic);
	falcon->recyclePrivateKey(reconstructedPrivate);
	falcon->recycleKeyPair(reconstructedKeyPair);
	falcon->recycleKeyPair(keyPair);
	falcon->recycleParameters(reconstructedParameters);
	falcon->recycleParameters(parameters);
}

void FalconTests::testPKCS8()
{
	FalconParameters* parameters = new FalconParameters();
	parameters->setParameterSet(FalconParameters::FALCON_512_PARAMETER_SET);

	AsymmetricKeyPair* keyPair = NULL;
	CPPUNIT_ASSERT(falcon->generateKeyPair(&keyPair, parameters));
	CPPUNIT_ASSERT(keyPair != NULL);

	FalconPrivateKey* privateKey =
		static_cast<FalconPrivateKey*>(keyPair->getPrivateKey());
	ByteString pkcs8 = privateKey->PKCS8Encode();
	CPPUNIT_ASSERT(pkcs8.size() != 0);

	FalconPrivateKey* decodedPrivateKey =
		static_cast<FalconPrivateKey*>(falcon->newPrivateKey());
	CPPUNIT_ASSERT(decodedPrivateKey != NULL);
	CPPUNIT_ASSERT(decodedPrivateKey->PKCS8Decode(pkcs8));
	CPPUNIT_ASSERT_EQUAL(privateKey->getParameterSet(),
		decodedPrivateKey->getParameterSet());
	CPPUNIT_ASSERT(privateKey->getValue() == decodedPrivateKey->getValue());
	CPPUNIT_ASSERT(decodedPrivateKey->PKCS8Encode().size() != 0);

	ByteString pkcs8WithTrailingData = pkcs8 + static_cast<unsigned char>(0);
	CPPUNIT_ASSERT(!decodedPrivateKey->PKCS8Decode(pkcs8WithTrailingData));

	falcon->recyclePrivateKey(decodedPrivateKey);
	falcon->recycleKeyPair(keyPair);
	falcon->recycleParameters(parameters);
}

void FalconTests::testInvalidInputs()
{
	FalconParameters* parameters = new FalconParameters();
	parameters->setParameterSet(FalconParameters::FALCON_512_PARAMETER_SET);
	AsymmetricKeyPair* keyPair = NULL;

	CPPUNIT_ASSERT(!falcon->generateKeyPair(NULL, parameters));
	CPPUNIT_ASSERT(!falcon->generateKeyPair(&keyPair, NULL));

	FalconParameters* unsupportedParameters = new FalconParameters();
	unsupportedParameters->setParameterSet(2UL);
	CPPUNIT_ASSERT(!falcon->generateKeyPair(&keyPair, unsupportedParameters));
	CPPUNIT_ASSERT(keyPair == NULL);

	AsymmetricParameters* reconstructedParameters = NULL;
	ByteString malformedParameters("00");
	CPPUNIT_ASSERT(!falcon->reconstructParameters(&reconstructedParameters,
		malformedParameters));
	CPPUNIT_ASSERT(reconstructedParameters == NULL);
	ByteString unsupportedSerialisedParameters(2UL);
	CPPUNIT_ASSERT(!falcon->reconstructParameters(&reconstructedParameters,
		unsupportedSerialisedParameters));
	CPPUNIT_ASSERT(reconstructedParameters == NULL);

	ByteString shortPublicKey;
	shortPublicKey.resize(FalconParameters::FALCON_512_PUB_LENGTH - 1);
	ByteString serialisedShortPublicKey = shortPublicKey.serialise();
	PublicKey* publicKey = NULL;
	CPPUNIT_ASSERT(!falcon->reconstructPublicKey(&publicKey,
		serialisedShortPublicKey));
	CPPUNIT_ASSERT(publicKey == NULL);

	ByteString shortPrivateKey;
	shortPrivateKey.resize(FalconParameters::FALCON_512_PRIV_LENGTH - 1);
	ByteString serialisedShortPrivateKey = shortPrivateKey.serialise();
	PrivateKey* privateKey = NULL;
	CPPUNIT_ASSERT(!falcon->reconstructPrivateKey(&privateKey,
		serialisedShortPrivateKey));
	CPPUNIT_ASSERT(privateKey == NULL);

	ByteString emptyPublicKey = ByteString().serialise();
	ByteString emptyPrivateKey = ByteString().serialise();
	ByteString emptyKeyPair = emptyPublicKey.serialise() +
		emptyPrivateKey.serialise();
	CPPUNIT_ASSERT(!falcon->reconstructKeyPair(NULL, emptyKeyPair));
	CPPUNIT_ASSERT(!falcon->reconstructPublicKey(NULL, emptyPublicKey));
	CPPUNIT_ASSERT(!falcon->reconstructPrivateKey(NULL, emptyPrivateKey));

	FalconPrivateKey* invalidPKCS8Key =
		static_cast<FalconPrivateKey*>(falcon->newPrivateKey());
	CPPUNIT_ASSERT(invalidPKCS8Key != NULL);
	ByteString invalidPKCS8("00");
	CPPUNIT_ASSERT(!invalidPKCS8Key->PKCS8Decode(invalidPKCS8));

	falcon->recyclePrivateKey(invalidPKCS8Key);
	falcon->recycleParameters(unsupportedParameters);
	falcon->recycleParameters(parameters);
}

#endif // WITH_FALCON
