/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 XWingPrivateKey.cpp

 X-Wing private key class
 *****************************************************************************/

#include "config.h"
#include "XWingParameters.h"
#include "XWingPrivateKey.h"
#include <string.h>

// The type
/*static*/ const char* XWingPrivateKey::type = "Abstract X-Wing private key";

// Check if the key is of the given type
bool XWingPrivateKey::isOfType(const char* inType)
{
	return inType != NULL && strcmp(type, inType) == 0;
}

// Get the bit length
unsigned long XWingPrivateKey::getBitLength() const
{
	return getValue().bits();
}

// Get the ciphertext length
unsigned long XWingPrivateKey::getOutputLength() const
{
	if (value.size() == XWingParameters::PRIVATE_KEY_LENGTH)
	{
		return XWingParameters::CIPHERTEXT_LENGTH;
	}
	return 0UL;
}

void XWingPrivateKey::setValue(const ByteString& inValue)
{
	value = inValue;
}

const ByteString& XWingPrivateKey::getValue() const
{
	return value;
}

// Serialisation
ByteString XWingPrivateKey::serialise() const
{
	return value.serialise();
}

bool XWingPrivateKey::deserialise(ByteString& serialised)
{
	ByteString deserialisedValue = ByteString::chainDeserialise(serialised);
	if (deserialisedValue.size() != XWingParameters::PRIVATE_KEY_LENGTH)
	{
		return false;
	}

	setValue(deserialisedValue);
	return true;
}
