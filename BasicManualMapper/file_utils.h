#pragma once

#include <Windows.h>
#include <string>

namespace file_utils
{
	BOOL DoesFileExistW(std::wstring filepath);
	BOOL DoesFileExistA(std::string filepath);
};

