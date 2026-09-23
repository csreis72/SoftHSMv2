/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 OSSLXWingUtil.h

 OpenSSL helpers for X-Wing keys
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLXWINGUTIL_H
#define _SOFTHSM_V2_OSSLXWINGUTIL_H

#include "config.h"
#ifdef WITH_X_WING
#include "ByteString.h"
#include <openssl/evp.h>

namespace OSSLXWing
{
	bool expandPrivateKey(const ByteString& seed, EVP_PKEY** mlkemKey,
	                      EVP_PKEY** x25519Key, ByteString& publicKey);
	bool importPublicKey(const ByteString& publicKey, EVP_PKEY** mlkemKey,
	                    EVP_PKEY** x25519Key);
}

#endif // WITH_X_WING
#endif // !_SOFTHSM_V2_OSSLXWINGUTIL_H
