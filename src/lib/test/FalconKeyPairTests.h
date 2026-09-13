/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _SOFTHSM_V2_FALCONKEYPAIRTESTS_H
#define _SOFTHSM_V2_FALCONKEYPAIRTESTS_H

#include "config.h"
#include "TestsBase.h"
#include <cppunit/extensions/HelperMacros.h>

class FalconKeyPairTests : public TestsBase
{
	CPPUNIT_TEST_SUITE(FalconKeyPairTests);
#ifdef WITH_FALCON
	CPPUNIT_TEST(testMechanism);
	CPPUNIT_TEST(testGenerateKeyPair);
	CPPUNIT_TEST(testTokenKeyPairPersistence);
	CPPUNIT_TEST(testSign);
	CPPUNIT_TEST(testSignErrors);
	CPPUNIT_TEST(testInvalidTemplates);
	CPPUNIT_TEST(testRollback);
#endif
	CPPUNIT_TEST_SUITE_END();

public:
#ifdef WITH_FALCON
	void testMechanism();
	void testGenerateKeyPair();
	void testTokenKeyPairPersistence();
	void testSign();
	void testSignErrors();
	void testInvalidTemplates();
	void testRollback();
#endif

protected:
#ifdef WITH_FALCON
	void openUserSession(CK_SESSION_HANDLE& hSession);
	CK_RV generateFalconKeyPair(CK_SESSION_HANDLE hSession,
		CK_BBOOL token, const char* label, CK_BYTE id,
		CK_OBJECT_HANDLE& hPublicKey, CK_OBJECT_HANDLE& hPrivateKey,
		CK_BBOOL canSign = CK_TRUE);
	CK_OBJECT_HANDLE findObject(CK_SESSION_HANDLE hSession,
		CK_OBJECT_CLASS objectClass, const char* label);
#endif
};

#endif // !_SOFTHSM_V2_FALCONKEYPAIRTESTS_H
