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

// Set the public key
void OSSLXWingKeyPair::setPublicKey(OSSLXWingPublicKey& publicKey)
{
	pubKey.setValue(publicKey.getValue());
}

// Set the private key and derive the public key
bool OSSLXWingKeyPair::setPrivateKey(OSSLXWingPrivateKey& privateKey)
{
	privKey.setValue(privateKey.getValue());
	ByteString publicValue;
	if (!privKey.getPublicValue(publicValue))
	{
		privKey.setValue(ByteString());
		return false;
	}
	pubKey.setValue(publicValue);
	return true;
}

// Return the public key
PublicKey* OSSLXWingKeyPair::getPublicKey()
{
	return &pubKey;
}

const PublicKey* OSSLXWingKeyPair::getConstPublicKey() const
{
	return &pubKey;
}

// Return the private key
PrivateKey* OSSLXWingKeyPair::getPrivateKey()
{
	return &privKey;
}

const PrivateKey* OSSLXWingKeyPair::getConstPrivateKey() const
{
	return &privKey;
}

#endif
