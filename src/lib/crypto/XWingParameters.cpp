/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 XWingParameters.cpp

 X-Wing parameters
 *****************************************************************************/

#include "config.h"
#include "XWingParameters.h"
#include <string.h>

// The type
/*static*/ const char* XWingParameters::type = "X-Wing parameters";

// Are the parameters of the given type?
bool XWingParameters::areOfType(const char* inType)
{
	if (inType == NULL)
	{
		return false;
	}
	return !strcmp(type, inType);
}

// Serialisation
ByteString XWingParameters::serialise() const
{
	return ByteString();
}

bool XWingParameters::deserialise(ByteString& serialised)
{
	return serialised.size() == 0;
}
