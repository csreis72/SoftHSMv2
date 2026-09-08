/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <config.h>
#include <string.h>
#include <vector>
#include "FalconKeyPairTests.h"

CPPUNIT_TEST_SUITE_REGISTRATION(FalconKeyPairTests);

#ifdef WITH_FALCON
namespace
{
	const CK_ULONG FALCON_512_PARAMETER_SET = 1UL;
	const CK_ULONG FALCON_512_PUBLIC_KEY_LENGTH = 897UL;
}

void FalconKeyPairTests::openUserSession(CK_SESSION_HANDLE& hSession)
{
	CRYPTOKI_F_PTR(C_Finalize(NULL_PTR));

	CK_RV rv = CRYPTOKI_F_PTR(C_Initialize(NULL_PTR));
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR(C_OpenSession(m_initializedTokenSlotID,
		CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession));
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR(C_Login(hSession, CKU_USER,
		m_userPin1, m_userPin1Length));
	CPPUNIT_ASSERT(rv == CKR_OK);
}

CK_RV FalconKeyPairTests::generateFalconKeyPair(CK_SESSION_HANDLE hSession,
	CK_BBOOL token, const char* label, CK_BYTE id,
	CK_OBJECT_HANDLE& hPublicKey, CK_OBJECT_HANDLE& hPrivateKey)
{
	CK_MECHANISM mechanism = { CKM_FALCON_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_KEY_TYPE keyType = CKK_FALCON;
	CK_BBOOL bTrue = CK_TRUE;
	CK_BBOOL bFalse = CK_FALSE;
	CK_ULONG parameterSet = FALCON_512_PARAMETER_SET;
	CK_ULONG labelLength = (CK_ULONG)strlen(label);

	CK_ATTRIBUTE publicKeyTemplate[] = {
		{ CKA_PARAMETER_SET, &parameterSet, sizeof(parameterSet) },
		{ CKA_LABEL, (CK_VOID_PTR)label, labelLength },
		{ CKA_ID, &id, sizeof(id) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_VERIFY, &bTrue, sizeof(bTrue) },
		{ CKA_TOKEN, &token, sizeof(token) },
		{ CKA_PRIVATE, &bFalse, sizeof(bFalse) }
	};
	CK_ATTRIBUTE privateKeyTemplate[] = {
		{ CKA_LABEL, (CK_VOID_PTR)label, labelLength },
		{ CKA_ID, &id, sizeof(id) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_SIGN, &bTrue, sizeof(bTrue) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_TOKEN, &token, sizeof(token) },
		{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
		{ CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) }
	};

	hPublicKey = CK_INVALID_HANDLE;
	hPrivateKey = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR(C_GenerateKeyPair(hSession, &mechanism,
		publicKeyTemplate, sizeof(publicKeyTemplate) / sizeof(CK_ATTRIBUTE),
		privateKeyTemplate, sizeof(privateKeyTemplate) / sizeof(CK_ATTRIBUTE),
		&hPublicKey, &hPrivateKey));
}

CK_OBJECT_HANDLE FalconKeyPairTests::findObject(CK_SESSION_HANDLE hSession,
	CK_OBJECT_CLASS objectClass, const char* label)
{
	CK_KEY_TYPE keyType = CKK_FALCON;
	CK_ATTRIBUTE searchTemplate[] = {
		{ CKA_CLASS, &objectClass, sizeof(objectClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_LABEL, (CK_VOID_PTR)label, (CK_ULONG)strlen(label) }
	};

	CK_RV rv = CRYPTOKI_F_PTR(C_FindObjectsInit(hSession, searchTemplate,
		sizeof(searchTemplate) / sizeof(CK_ATTRIBUTE)));
	CPPUNIT_ASSERT(rv == CKR_OK);

	CK_OBJECT_HANDLE objects[2] = { CK_INVALID_HANDLE, CK_INVALID_HANDLE };
	CK_ULONG objectCount = 0;
	rv = CRYPTOKI_F_PTR(C_FindObjects(hSession, objects, 2, &objectCount));
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR(C_FindObjectsFinal(hSession));
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(objectCount <= 1);

	return objectCount == 1 ? objects[0] : CK_INVALID_HANDLE;
}

void FalconKeyPairTests::testMechanism()
{
	CK_ULONG mechanismCount = 0;
	CK_RV rv = CRYPTOKI_F_PTR(C_GetMechanismList(
		m_initializedTokenSlotID, NULL_PTR, &mechanismCount));
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(mechanismCount > 0);

	std::vector<CK_MECHANISM_TYPE> mechanisms(mechanismCount);
	rv = CRYPTOKI_F_PTR(C_GetMechanismList(m_initializedTokenSlotID,
		&mechanisms[0], &mechanismCount));
	CPPUNIT_ASSERT(rv == CKR_OK);

	bool found = false;
	for (CK_ULONG i = 0; i < mechanismCount; ++i)
		found = found || mechanisms[i] == CKM_FALCON_KEY_PAIR_GEN;
	CPPUNIT_ASSERT(found);

	CK_MECHANISM_INFO mechanismInfo;
	rv = CRYPTOKI_F_PTR(C_GetMechanismInfo(m_initializedTokenSlotID,
		CKM_FALCON_KEY_PAIR_GEN, &mechanismInfo));
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(mechanismInfo.ulMinKeySize == FALCON_512_PUBLIC_KEY_LENGTH);
	CPPUNIT_ASSERT(mechanismInfo.ulMaxKeySize == FALCON_512_PUBLIC_KEY_LENGTH);
	CPPUNIT_ASSERT(mechanismInfo.flags == CKF_GENERATE_KEY_PAIR);
}

void FalconKeyPairTests::testGenerateKeyPair()
{
	CK_SESSION_HANDLE hSession;
	openUserSession(hSession);

	CK_OBJECT_HANDLE hPublicKey;
	CK_OBJECT_HANDLE hPrivateKey;
	CK_RV rv = generateFalconKeyPair(hSession, CK_FALSE,
		"falcon-session-key", 1, hPublicKey, hPrivateKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(hPublicKey != CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(hPrivateKey != CK_INVALID_HANDLE);

	CK_OBJECT_CLASS publicClass;
	CK_KEY_TYPE publicKeyType;
	CK_ULONG publicParameterSet;
	CK_BBOOL publicLocal;
	CK_MECHANISM_TYPE publicKeyGenMechanism;
	CK_ATTRIBUTE publicAttributes[] = {
		{ CKA_CLASS, &publicClass, sizeof(publicClass) },
		{ CKA_KEY_TYPE, &publicKeyType, sizeof(publicKeyType) },
		{ CKA_PARAMETER_SET, &publicParameterSet, sizeof(publicParameterSet) },
		{ CKA_LOCAL, &publicLocal, sizeof(publicLocal) },
		{ CKA_KEY_GEN_MECHANISM, &publicKeyGenMechanism, sizeof(publicKeyGenMechanism) },
		{ CKA_VALUE, NULL_PTR, 0 }
	};
	rv = CRYPTOKI_F_PTR(C_GetAttributeValue(hSession, hPublicKey,
		publicAttributes, sizeof(publicAttributes) / sizeof(CK_ATTRIBUTE)));
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(publicClass == CKO_PUBLIC_KEY);
	CPPUNIT_ASSERT(publicKeyType == CKK_FALCON);
	CPPUNIT_ASSERT(publicParameterSet == FALCON_512_PARAMETER_SET);
	CPPUNIT_ASSERT(publicLocal == CK_TRUE);
	CPPUNIT_ASSERT(publicKeyGenMechanism == CKM_FALCON_KEY_PAIR_GEN);
	CPPUNIT_ASSERT(publicAttributes[5].ulValueLen == FALCON_512_PUBLIC_KEY_LENGTH);

	std::vector<CK_BYTE> publicValue(publicAttributes[5].ulValueLen);
	publicAttributes[5].pValue = &publicValue[0];
	rv = CRYPTOKI_F_PTR(C_GetAttributeValue(hSession, hPublicKey,
		&publicAttributes[5], 1));
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(publicAttributes[5].ulValueLen == FALCON_512_PUBLIC_KEY_LENGTH);

	CK_OBJECT_CLASS privateClass;
	CK_KEY_TYPE privateKeyType;
	CK_ULONG privateParameterSet;
	CK_BBOOL privateLocal;
	CK_MECHANISM_TYPE privateKeyGenMechanism;
	CK_BBOOL alwaysSensitive;
	CK_BBOOL neverExtractable;
	CK_ATTRIBUTE privateAttributes[] = {
		{ CKA_CLASS, &privateClass, sizeof(privateClass) },
		{ CKA_KEY_TYPE, &privateKeyType, sizeof(privateKeyType) },
		{ CKA_PARAMETER_SET, &privateParameterSet, sizeof(privateParameterSet) },
		{ CKA_LOCAL, &privateLocal, sizeof(privateLocal) },
		{ CKA_KEY_GEN_MECHANISM, &privateKeyGenMechanism, sizeof(privateKeyGenMechanism) },
		{ CKA_ALWAYS_SENSITIVE, &alwaysSensitive, sizeof(alwaysSensitive) },
		{ CKA_NEVER_EXTRACTABLE, &neverExtractable, sizeof(neverExtractable) }
	};
	rv = CRYPTOKI_F_PTR(C_GetAttributeValue(hSession, hPrivateKey,
		privateAttributes, sizeof(privateAttributes) / sizeof(CK_ATTRIBUTE)));
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(privateClass == CKO_PRIVATE_KEY);
	CPPUNIT_ASSERT(privateKeyType == CKK_FALCON);
	CPPUNIT_ASSERT(privateParameterSet == FALCON_512_PARAMETER_SET);
	CPPUNIT_ASSERT(privateLocal == CK_TRUE);
	CPPUNIT_ASSERT(privateKeyGenMechanism == CKM_FALCON_KEY_PAIR_GEN);
	CPPUNIT_ASSERT(alwaysSensitive == CK_TRUE);
	CPPUNIT_ASSERT(neverExtractable == CK_TRUE);

	CK_ATTRIBUTE privateValue = { CKA_VALUE, NULL_PTR, 0 };
	rv = CRYPTOKI_F_PTR(C_GetAttributeValue(hSession, hPrivateKey,
		&privateValue, 1));
	CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_SENSITIVE);
	CPPUNIT_ASSERT(privateValue.ulValueLen == CK_UNAVAILABLE_INFORMATION);

	rv = CRYPTOKI_F_PTR(C_DestroyObject(hSession, hPublicKey));
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR(C_DestroyObject(hSession, hPrivateKey));
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR(C_CloseSession(hSession));
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void FalconKeyPairTests::testTokenKeyPairPersistence()
{
	const char* label = "falcon-persistent-key";
	CK_SESSION_HANDLE hSession;
	openUserSession(hSession);

	CK_OBJECT_HANDLE hPublicKey;
	CK_OBJECT_HANDLE hPrivateKey;
	CK_RV rv = generateFalconKeyPair(hSession, CK_TRUE, label, 2,
		hPublicKey, hPrivateKey);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR(C_CloseSession(hSession));
	CPPUNIT_ASSERT(rv == CKR_OK);
	openUserSession(hSession);

	hPublicKey = findObject(hSession, CKO_PUBLIC_KEY, label);
	hPrivateKey = findObject(hSession, CKO_PRIVATE_KEY, label);
	CPPUNIT_ASSERT(hPublicKey != CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(hPrivateKey != CK_INVALID_HANDLE);

	CK_ULONG parameterSet;
	CK_ATTRIBUTE publicAttributes[] = {
		{ CKA_PARAMETER_SET, &parameterSet, sizeof(parameterSet) },
		{ CKA_VALUE, NULL_PTR, 0 }
	};
	rv = CRYPTOKI_F_PTR(C_GetAttributeValue(hSession, hPublicKey,
		publicAttributes, sizeof(publicAttributes) / sizeof(CK_ATTRIBUTE)));
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(parameterSet == FALCON_512_PARAMETER_SET);
	CPPUNIT_ASSERT(publicAttributes[1].ulValueLen == FALCON_512_PUBLIC_KEY_LENGTH);

	CK_ATTRIBUTE privateValue = { CKA_VALUE, NULL_PTR, 0 };
	rv = CRYPTOKI_F_PTR(C_GetAttributeValue(hSession, hPrivateKey,
		&privateValue, 1));
	CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_SENSITIVE);
	CPPUNIT_ASSERT(privateValue.ulValueLen == CK_UNAVAILABLE_INFORMATION);

	rv = CRYPTOKI_F_PTR(C_DestroyObject(hSession, hPublicKey));
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR(C_DestroyObject(hSession, hPrivateKey));
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR(C_CloseSession(hSession));
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void FalconKeyPairTests::testInvalidTemplates()
{
	CK_SESSION_HANDLE hSession;
	openUserSession(hSession);

	CK_MECHANISM mechanism = { CKM_FALCON_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_KEY_TYPE falconKeyType = CKK_FALCON;
	CK_KEY_TYPE rsaKeyType = CKK_RSA;
	CK_ULONG parameterSet = FALCON_512_PARAMETER_SET;
	CK_ULONG unsupportedParameterSet = 2UL;
	CK_OBJECT_HANDLE hPublicKey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrivateKey = CK_INVALID_HANDLE;
	CK_ATTRIBUTE privateTemplate[] = {
		{ CKA_KEY_TYPE, &falconKeyType, sizeof(falconKeyType) }
	};

	CK_ATTRIBUTE missingParameterSet[] = {
		{ CKA_KEY_TYPE, &falconKeyType, sizeof(falconKeyType) }
	};
	CK_RV rv = CRYPTOKI_F_PTR(C_GenerateKeyPair(hSession, &mechanism,
		missingParameterSet, 1, privateTemplate, 1,
		&hPublicKey, &hPrivateKey));
	CPPUNIT_ASSERT(rv == CKR_TEMPLATE_INCOMPLETE);
	CPPUNIT_ASSERT(hPublicKey == CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(hPrivateKey == CK_INVALID_HANDLE);

	CK_ATTRIBUTE nullParameterSet[] = {
		{ CKA_PARAMETER_SET, NULL_PTR, sizeof(parameterSet) }
	};
	rv = CRYPTOKI_F_PTR(C_GenerateKeyPair(hSession, &mechanism,
		nullParameterSet, 1, privateTemplate, 1,
		&hPublicKey, &hPrivateKey));
	CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_VALUE_INVALID);

	CK_ATTRIBUTE invalidParameterSetLength[] = {
		{ CKA_PARAMETER_SET, &parameterSet, sizeof(CK_BYTE) }
	};
	rv = CRYPTOKI_F_PTR(C_GenerateKeyPair(hSession, &mechanism,
		invalidParameterSetLength, 1, privateTemplate, 1,
		&hPublicKey, &hPrivateKey));
	CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_VALUE_INVALID);

	CK_ATTRIBUTE unsupportedParameter[] = {
		{ CKA_PARAMETER_SET, &unsupportedParameterSet, sizeof(unsupportedParameterSet) }
	};
	rv = CRYPTOKI_F_PTR(C_GenerateKeyPair(hSession, &mechanism,
		unsupportedParameter, 1, privateTemplate, 1,
		&hPublicKey, &hPrivateKey));
	CPPUNIT_ASSERT(rv == CKR_PARAMETER_SET_NOT_SUPPORTED);

	CK_ATTRIBUTE wrongKeyType[] = {
		{ CKA_PARAMETER_SET, &parameterSet, sizeof(parameterSet) },
		{ CKA_KEY_TYPE, &rsaKeyType, sizeof(rsaKeyType) }
	};
	rv = CRYPTOKI_F_PTR(C_GenerateKeyPair(hSession, &mechanism,
		wrongKeyType, 2, privateTemplate, 1,
		&hPublicKey, &hPrivateKey));
	CPPUNIT_ASSERT(rv == CKR_TEMPLATE_INCONSISTENT);

	rv = CRYPTOKI_F_PTR(C_CloseSession(hSession));
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void FalconKeyPairTests::testRollback()
{
	const char* label = "falcon-rollback-key";
	CK_SESSION_HANDLE hSession;
	openUserSession(hSession);

	CK_MECHANISM mechanism = { CKM_FALCON_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_ULONG parameterSet = FALCON_512_PARAMETER_SET;
	CK_ATTRIBUTE publicTemplate[] = {
		{ CKA_PARAMETER_SET, &parameterSet, sizeof(parameterSet) },
		{ CKA_LABEL, (CK_VOID_PTR)label, (CK_ULONG)strlen(label) }
	};
	CK_ATTRIBUTE privateTemplate[29];
	for (CK_ULONG i = 0; i < 29; ++i)
	{
		privateTemplate[i].type = CKA_LABEL;
		privateTemplate[i].pValue = (CK_VOID_PTR)label;
		privateTemplate[i].ulValueLen = (CK_ULONG)strlen(label);
	}

	CK_OBJECT_HANDLE hPublicKey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrivateKey = CK_INVALID_HANDLE;
	CK_RV rv = CRYPTOKI_F_PTR(C_GenerateKeyPair(hSession, &mechanism,
		publicTemplate, 2, privateTemplate, 29,
		&hPublicKey, &hPrivateKey));
	CPPUNIT_ASSERT(rv == CKR_TEMPLATE_INCONSISTENT);
	CPPUNIT_ASSERT(hPublicKey == CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(hPrivateKey == CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(findObject(hSession, CKO_PUBLIC_KEY, label) == CK_INVALID_HANDLE);

	rv = CRYPTOKI_F_PTR(C_CloseSession(hSession));
	CPPUNIT_ASSERT(rv == CKR_OK);
}
#endif
