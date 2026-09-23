/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 XWingPublicKey.cpp

 X-Wing public key class
 *****************************************************************************/

#include "config.h"
#include "XWingParameters.h"
#include "XWingPublicKey.h"
#include <string.h>

// The type
/*static*/ const char* XWingPublicKey::type = "Abstract X-Wing public key";

// Check if the key is of the given type
bool XWingPublicKey::isOfType(const char* inType)
{
	return inType != NULL && strcmp(type, inType) == 0;
}

// Get the bit length
unsigned long XWingPublicKey::getBitLength() const
{
	return getValue().bits();
}

// Get the ciphertext length
unsigned long XWingPublicKey::getOutputLength() const
{
	if (value.size() == XWingParameters::PUBLIC_KEY_LENGTH)
	{
		return XWingParameters::CIPHERTEXT_LENGTH;
	}
	return 0UL;
}

void XWingPublicKey::setValue(const ByteString& inValue)
{
	value = inValue;
}

const ByteString& XWingPublicKey::getValue() const
{
	return value;
}

ByteString XWingPublicKey::getMLKEMPublicKey() const
{
	if (value.size() != XWingParameters::PUBLIC_KEY_LENGTH)
	{
		return ByteString();
	}
	return value.substr(0, XWingParameters::ML_KEM_768_PUBLIC_KEY_LENGTH);
}

ByteString XWingPublicKey::getX25519PublicKey() const
{
	if (value.size() != XWingParameters::PUBLIC_KEY_LENGTH)
	{
		return ByteString();
	}
	return value.substr(XWingParameters::ML_KEM_768_PUBLIC_KEY_LENGTH,
	                    XWingParameters::X25519_PUBLIC_KEY_LENGTH);
}

// Serialisation
ByteString XWingPublicKey::serialise() const
{
	return value.serialise();
}

bool XWingPublicKey::deserialise(ByteString& serialised)
{
	ByteString deserialisedValue = ByteString::chainDeserialise(serialised);
	if (deserialisedValue.size() != XWingParameters::PUBLIC_KEY_LENGTH)
	{
		return false;
	}

	setValue(deserialisedValue);
	return true;
}
