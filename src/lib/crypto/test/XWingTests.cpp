/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 XWingTests.cpp

 Contains test cases to test the X-Wing class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_X_WING
#include "AsymmetricKeyPair.h"
#include "CryptoFactory.h"
#include "SymmetricKey.h"
#include "XWingParameters.h"
#include "XWingTests.h"

CPPUNIT_TEST_SUITE_REGISTRATION(XWingTests);

void XWingTests::setUp()
{
	xWing = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::XWING);
	CPPUNIT_ASSERT(xWing != NULL);
}

void XWingTests::tearDown()
{
	if (xWing != NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(xWing);
	}
}

void XWingTests::testEncapsulation()
{
	XWingParameters* parameters = new XWingParameters();
	AsymmetricKeyPair* keyPair = NULL;
	CPPUNIT_ASSERT(xWing->generateKeyPair(&keyPair, parameters));

	ByteString cipherText;
	SymmetricKey* secretKey = NULL;
	CPPUNIT_ASSERT(xWing->encapsulate(keyPair->getPublicKey(), cipherText,
	                                  &secretKey, CKK_AES,
	                                  AsymMech::XWING));
	CPPUNIT_ASSERT(secretKey != NULL);
	CPPUNIT_ASSERT_EQUAL(
		static_cast<size_t>(XWingParameters::X_WING_CIPHERTEXT_LENGTH),
		cipherText.size());
	CPPUNIT_ASSERT_EQUAL(
		static_cast<size_t>(XWingParameters::X_WING_SHARED_SECRET_LENGTH),
		secretKey->getKeyBits().size());
	CPPUNIT_ASSERT_EQUAL(
		static_cast<size_t>(XWingParameters::X_WING_SHARED_SECRET_LENGTH * 8),
		secretKey->getBitLen());

	xWing->recycleSymmetricKey(secretKey);
	xWing->recycleKeyPair(keyPair);
	xWing->recycleParameters(parameters);
}

#endif // WITH_X_WING
