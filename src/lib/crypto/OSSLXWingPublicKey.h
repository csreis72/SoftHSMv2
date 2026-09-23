/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 OSSLXWingPublicKey.h

 OpenSSL X-Wing public key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLXWINGPUBLICKEY_H
#define _SOFTHSM_V2_OSSLXWINGPUBLICKEY_H

#include "config.h"
#ifdef WITH_X_WING
#include "XWingPublicKey.h"
#include <openssl/evp.h>

class OSSLXWingPublicKey : public XWingPublicKey
{
public:
	OSSLXWingPublicKey();
	virtual ~OSSLXWingPublicKey();

	OSSLXWingPublicKey(const OSSLXWingPublicKey&) = delete;
	OSSLXWingPublicKey& operator=(const OSSLXWingPublicKey&) = delete;
	OSSLXWingPublicKey(OSSLXWingPublicKey&& other) noexcept;
	OSSLXWingPublicKey& operator=(OSSLXWingPublicKey&& other) noexcept;

	static const char* type;
	virtual bool isOfType(const char* inType);
	virtual void setValue(const ByteString& value);

	EVP_PKEY* getOSSLMLKEMKey();
	EVP_PKEY* getOSSLX25519Key();

private:
	EVP_PKEY* mlkemKey;
	EVP_PKEY* x25519Key;

	bool createOSSLKeys();
	void invalidateOSSLKeys();
};

#endif // WITH_X_WING
#endif // !_SOFTHSM_V2_OSSLXWINGPUBLICKEY_H
