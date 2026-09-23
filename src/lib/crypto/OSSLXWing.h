/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 OSSLXWing.h

 OpenSSL X-Wing asymmetric algorithm implementation
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLXWING_H
#define _SOFTHSM_V2_OSSLXWING_H

#include "config.h"
#include "AsymmetricAlgorithm.h"

class OSSLXWing : public AsymmetricAlgorithm
{
public:
	virtual bool encrypt(PublicKey* publicKey, const ByteString& data,
	                     ByteString& encryptedData, const AsymMech::Type padding,
	                     const MechanismParam* mechanismParam = NULL);
	virtual bool decrypt(PrivateKey* privateKey, const ByteString& encryptedData,
	                     ByteString& data, const AsymMech::Type padding,
	                     const MechanismParam* mechanismParam = NULL);

	virtual bool generateKeyPair(AsymmetricKeyPair** ppKeyPair,
	                             AsymmetricParameters* parameters,
	                             RNG* rng = NULL);
	virtual unsigned long getMinKeySize();
	virtual unsigned long getMaxKeySize();
	virtual bool reconstructKeyPair(AsymmetricKeyPair** ppKeyPair,
	                                ByteString& serialisedData);
	virtual bool reconstructPublicKey(PublicKey** ppPublicKey,
	                                  ByteString& serialisedData);
	virtual bool reconstructPrivateKey(PrivateKey** ppPrivateKey,
	                                   ByteString& serialisedData);
	virtual bool reconstructParameters(AsymmetricParameters** ppParams,
	                                   ByteString& serialisedData);
	virtual PublicKey* newPublicKey();
	virtual PrivateKey* newPrivateKey();
	virtual AsymmetricParameters* newParameters();
};

#endif // !_SOFTHSM_V2_OSSLXWING_H
