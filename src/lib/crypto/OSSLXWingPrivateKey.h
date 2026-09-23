/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 OSSLXWingPrivateKey.h

 OpenSSL X-Wing private key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLXWINGPRIVATEKEY_H
#define _SOFTHSM_V2_OSSLXWINGPRIVATEKEY_H

#include "config.h"
#ifdef WITH_X_WING
#include "XWingPrivateKey.h"
#include <openssl/evp.h>

class OSSLXWingPrivateKey : public XWingPrivateKey
{
public:
	OSSLXWingPrivateKey();
	virtual ~OSSLXWingPrivateKey();

	OSSLXWingPrivateKey(const OSSLXWingPrivateKey&) = delete;
	OSSLXWingPrivateKey& operator=(const OSSLXWingPrivateKey&) = delete;
	OSSLXWingPrivateKey(OSSLXWingPrivateKey&& other) noexcept;
	OSSLXWingPrivateKey& operator=(OSSLXWingPrivateKey&& other) noexcept;

	static const char* type;
	virtual bool isOfType(const char* inType);
	virtual void setValue(const ByteString& value);

	virtual ByteString PKCS8Encode();
	virtual bool PKCS8Decode(const ByteString& ber);

	bool getPublicValue(ByteString& publicValue);
	EVP_PKEY* getOSSLMLKEMKey();
	EVP_PKEY* getOSSLX25519Key();

private:
	EVP_PKEY* mlkemKey;
	EVP_PKEY* x25519Key;
	ByteString publicValue;

	bool expandKey();
	void invalidateExpandedKey();
};

#endif // WITH_X_WING
#endif // !_SOFTHSM_V2_OSSLXWINGPRIVATEKEY_H
