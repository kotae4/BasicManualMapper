#pragma once

#include <Windows.h>
#include <string>
#include <vector>

namespace string_utils
{
	void PrintErrorMessage(HRESULT error);
	std::string GetErrorMessage(HRESULT error);
	VOID PrintLastError();

	BOOL TryConvertUtf8ToUtf16(const std::string& utf8, OUT std::wstring& outWStr);
	BOOL TryConvertUtf16ToUtf8(const std::wstring& utf16, OUT std::string& outStr);
	// credit: https://stackoverflow.com/a/57346888
	std::vector<std::string> SplitA(const std::string& input, const std::string& delim);
	std::vector<std::wstring> SplitW(const std::wstring& input, const std::wstring& delim);
};

