#pragma once

#include <iostream>
#include <Windows.h>

struct RelocBlock
{
	DWORD PageRVA;
	DWORD BlockSize;

	struct
	{
		WORD Offset : 12;
		WORD Type : 4;
	}Item[1];
};