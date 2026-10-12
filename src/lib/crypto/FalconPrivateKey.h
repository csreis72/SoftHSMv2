/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 FalconPrivateKey.h

 Falcon private key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_FALCONPRIVATEKEY_H
#define _SOFTHSM_V2_FALCONPRIVATEKEY_H

#include "config.h"
#include "PrivateKey.h"

class FalconPrivateKey : public PrivateKey
{
public:
	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* inType);

	// Get the parameter set
	virtual unsigned long getParameterSet() const;

	// Get the maximum signature length
	virtual unsigned long getOutputLength() const;

	// Get the bit length
	virtual unsigned long getBitLength() const;

	// Set the Falcon private key component
	virtual void setValue(const ByteString& value);

	// Get the Falcon private key component
	virtual const ByteString& getValue() const;

	// SubjectPublicKeyInfo needed by providers that encode the public key in PKCS#8.
	virtual ByteString getPublicKeyInfo() = 0;
	virtual bool setPublicKeyInfo(const ByteString& publicKeyInfo) = 0;

	// Serialisation
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

protected:
	ByteString value;
};

#endif // !_SOFTHSM_V2_FALCONPRIVATEKEY_H
