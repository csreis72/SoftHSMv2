/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 OSSLXWingKeyPair.h

 OpenSSL X-Wing key-pair class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLXWINGKEYPAIR_H
#define _SOFTHSM_V2_OSSLXWINGKEYPAIR_H

#include "config.h"
#ifdef WITH_X_WING
#include "AsymmetricKeyPair.h"
#include "OSSLXWingPrivateKey.h"
#include "OSSLXWingPublicKey.h"

class OSSLXWingKeyPair : public AsymmetricKeyPair
{
public:
	bool setPrivateKeyValue(const ByteString& privateKey);
	void setPublicKey(const OSSLXWingPublicKey& publicKey);

	virtual PublicKey* getPublicKey();
	virtual const PublicKey* getConstPublicKey() const;
	virtual PrivateKey* getPrivateKey();
	virtual const PrivateKey* getConstPrivateKey() const;

private:
	OSSLXWingPublicKey pubKey;
	OSSLXWingPrivateKey privKey;
};

#endif // WITH_X_WING
#endif // !_SOFTHSM_V2_OSSLXWINGKEYPAIR_H
