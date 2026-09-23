/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 OSSLXWingKeyPair.cpp

 OpenSSL X-Wing key-pair class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_X_WING
#include "OSSLXWingKeyPair.h"

bool OSSLXWingKeyPair::setPrivateKeyValue(const ByteString& privateKey)
{
	privKey.setValue(privateKey);
	ByteString publicKey;
	if (!privKey.getPublicValue(publicKey))
	{
		privKey.setValue(ByteString());
		return false;
	}
	pubKey.setValue(publicKey);
	return true;
}

void OSSLXWingKeyPair::setPublicKey(const OSSLXWingPublicKey& publicKey)
{
	pubKey.setValue(publicKey.getValue());
}

PublicKey* OSSLXWingKeyPair::getPublicKey()
{
	return &pubKey;
}

const PublicKey* OSSLXWingKeyPair::getConstPublicKey() const
{
	return &pubKey;
}

PrivateKey* OSSLXWingKeyPair::getPrivateKey()
{
	return &privKey;
}

const PrivateKey* OSSLXWingKeyPair::getConstPrivateKey() const
{
	return &privKey;
}

#endif
