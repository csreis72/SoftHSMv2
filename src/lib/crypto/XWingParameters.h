/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 XWingParameters.h

 X-Wing parameters (only used for key generation)
 *****************************************************************************/

#ifndef _SOFTHSM_V2_XWINGPARAMETERS_H
#define _SOFTHSM_V2_XWINGPARAMETERS_H

#include "config.h"
#include "AsymmetricParameters.h"

class XWingParameters : public AsymmetricParameters
{
public:
	// The type
	static const char* type;

	// Are the parameters of the given type?
	virtual bool areOfType(const char* inType);

	// Serialisation
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

	static const unsigned long PRIVATE_KEY_LENGTH = 32;
	static const unsigned long PUBLIC_KEY_LENGTH = 1216;
	static const unsigned long CIPHERTEXT_LENGTH = 1120;
	static const unsigned long SHARED_SECRET_LENGTH = 32;
	static const unsigned long ML_KEM_768_PUBLIC_KEY_LENGTH = 1184;
	static const unsigned long X25519_PUBLIC_KEY_LENGTH = 32;
};

#endif // !_SOFTHSM_V2_XWINGPARAMETERS_H
