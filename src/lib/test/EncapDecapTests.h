/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 EncapDecapTests.h

 Contains test cases to C_EncapsulateKey and C_DecapsulateKey
 *****************************************************************************/

#ifndef _SOFTHSM_V2_ENCAPDECAPTESTS_H
#define _SOFTHSM_V2_ENCAPDECAPTESTS_H

#include "config.h"
#include "TestsBase.h"
#include <cppunit/extensions/HelperMacros.h>

class EncapDecapTests : public TestsBase
{
	CPPUNIT_TEST_SUITE(EncapDecapTests);
#ifdef WITH_ML_KEM
	CPPUNIT_TEST_PARAMETERIZED(testMLKEMEncapsulationDecapsulation, {CKP_ML_KEM_512, CKP_ML_KEM_768, CKP_ML_KEM_1024});
	CPPUNIT_TEST_PARAMETERIZED(testMLKEMEncapsulationDecapsulationWithValueLen, {16, 24, 32});
	CPPUNIT_TEST(testMLKEMEncapsulationDecapsulationWithValueLenWrong);
	CPPUNIT_TEST(testMLKEMEncapsulationCiphertextIsNull);
	CPPUNIT_TEST(testMLKEMDecapsulationCiphertextIsNull);
	CPPUNIT_TEST(testMLKEMDecapsulationCiphertextLengthIsZero);
#endif
#ifdef WITH_X_WING
	CPPUNIT_TEST(testXWingEncapsulation);
	CPPUNIT_TEST(testXWingEncapsulationDecapsulation);
	CPPUNIT_TEST(testXWingEncapsulationBufferTooSmall);
	CPPUNIT_TEST(testXWingEncapsulationInvalidInputs);
#endif
	CPPUNIT_TEST_SUITE_END();

public:
#ifdef WITH_ML_KEM
	void testMLKEMEncapsulationDecapsulation(CK_ULONG parameterSet);
	void testMLKEMEncapsulationDecapsulationWithValueLen(CK_ULONG ulValueLen);
	void testMLKEMEncapsulationDecapsulationWithValueLenWrong();
	void testMLKEMEncapsulationCiphertextIsNull();
	void testMLKEMDecapsulationCiphertextIsNull();
	void testMLKEMDecapsulationCiphertextLengthIsZero();
#endif
#ifdef WITH_X_WING
	void testXWingEncapsulation();
	void testXWingEncapsulationDecapsulation();
	void testXWingEncapsulationBufferTooSmall();
	void testXWingEncapsulationInvalidInputs();
#endif

protected:
#ifdef WITH_ML_KEM
	CK_RV generateMLKEM(CK_ULONG parameterSet, CK_SESSION_HANDLE hSession, CK_BBOOL bTokenPuk, CK_BBOOL bPrivatePuk, CK_BBOOL bTokenPrk, CK_BBOOL bPrivatePrk, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk);
#endif
#ifdef WITH_X_WING
	CK_RV generateXWing(CK_SESSION_HANDLE hSession, CK_BBOOL bTokenPuk, CK_BBOOL bPrivatePuk, CK_BBOOL bTokenPrk, CK_BBOOL bPrivatePrk, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk);
	void encapsulateXWing(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey);
#endif

};

#endif // !_SOFTHSM_V2_ENCAPDECAPTESTS_H
