/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 XWingPrivateKey.h

 X-Wing private key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_XWINGPRIVATEKEY_H
#define _SOFTHSM_V2_XWINGPRIVATEKEY_H

#include "config.h"
#include "PrivateKey.h"

class XWingPrivateKey : public PrivateKey
{
public:
	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* inType);

	// Get the ciphertext length
	virtual unsigned long getOutputLength() const;

	// Get the bit length
	virtual unsigned long getBitLength() const;

	// Set the X-Wing private seed
	virtual void setValue(const ByteString& value);

	// Get the X-Wing private seed
	virtual const ByteString& getValue() const;

	// Serialisation
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

protected:
	ByteString value;
};

#endif // !_SOFTHSM_V2_XWINGPRIVATEKEY_H
