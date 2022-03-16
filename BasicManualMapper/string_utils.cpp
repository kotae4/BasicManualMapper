#include "string_utils.h"
#include "logger.h"
#include <tchar.h>
#include <sstream>

// credit: someone on stackoverflow, probably (sorry didn't bookmark)
void string_utils::PrintErrorMessage(HRESULT error)
{
	LPTSTR errorText = NULL;

	FormatMessage(
		// use system message tables to retrieve error text
		FORMAT_MESSAGE_FROM_SYSTEM
		// allocate buffer on local heap for error text
		| FORMAT_MESSAGE_ALLOCATE_BUFFER
		// Important! will fail otherwise, since we're not 
		// (and CANNOT) pass insertion parameters
		| FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,    // unused with FORMAT_MESSAGE_FROM_SYSTEM
		error,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&errorText,  // output 
		0, // minimum size for output buffer
		NULL);   // arguments - see note 

	if (errorText != NULL)
	{
		// ... do something with the string `errorText` - log it, display it to the user, etc.
		_tprintf(TEXT("Error code (0x%lx): %s"), error, errorText);
		// release memory allocated by FormatMessage()
		// < win10
		//LocalFree(errorText);
		// win10
		HeapFree(::GetProcessHeap(), NULL, errorText);
		errorText = NULL;
	}
}

std::string string_utils::GetErrorMessage(HRESULT error)
{
	LPTSTR errorText = NULL;
	std::string retErrorStr = std::string();

	DWORD result = FormatMessage(
		// use system message tables to retrieve error text
		FORMAT_MESSAGE_FROM_SYSTEM
		// allocate buffer on local heap for error text
		| FORMAT_MESSAGE_ALLOCATE_BUFFER
		// Important! will fail otherwise, since we're not 
		// (and CANNOT) pass insertion parameters
		| FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,    // unused with FORMAT_MESSAGE_FROM_SYSTEM
		error,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&errorText,  // output 
		0, // minimum size for output buffer
		NULL);   // arguments - see note 


	if (result == 0)
	{
		HRESULT formatMessageErr = GetLastError();
		LOG_ERROR("Could not format error message ({}) (original error: {})", formatMessageErr, error);
	}

	if (errorText != NULL)
	{
		// convert to std::string
		std::wstring errorWStr(errorText);
		if (TryConvertUtf16ToUtf8(errorWStr, retErrorStr) == FALSE)
		{
			LOG_ERROR("Could not convert error message to utf8 string");
		}

		// release memory allocated by FormatMessage()
		// < win10
		//LocalFree(errorText);
		// win10
		HeapFree(::GetProcessHeap(), NULL, errorText);
		errorText = NULL;
	}
	return retErrorStr;
}

VOID string_utils::PrintLastError()
{
	DWORD errCode = GetLastError();
	LPTSTR errorText = NULL;

	FormatMessage(
		// use system message tables to retrieve error text
		FORMAT_MESSAGE_FROM_SYSTEM
		// allocate buffer on local heap for error text
		| FORMAT_MESSAGE_ALLOCATE_BUFFER
		// Important! will fail otherwise, since we're not 
		// (and CANNOT) pass insertion parameters
		| FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,    // unused with FORMAT_MESSAGE_FROM_SYSTEM
		errCode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&errorText,  // output 
		0, // minimum size for output buffer
		NULL);   // arguments - see note 

	if (errorText != NULL)
	{
		// ... do something with the string `errorText` - log it, display it to the user, etc.
		_tprintf(TEXT("Error code (0x%lx): %s"), errCode, errorText);
		// release memory allocated by FormatMessage()
		// < win10
		//LocalFree(errorText);
		// win10
		HeapFree(::GetProcessHeap(), NULL, errorText);
		errorText = NULL;
	}
}

// credit: https://docs.microsoft.com/en-us/archive/msdn-magazine/2016/september/c-unicode-encoding-conversions-with-stl-strings-and-win32-apis
BOOL string_utils::TryConvertUtf8ToUtf16(const std::string& utf8, OUT std::wstring& outWStr)
{
	if (utf8.empty())
	{
		return FALSE;
	}
	const int utf8Length = static_cast<int>(utf8.length());
	const int utf16Length = ::MultiByteToWideChar(
		CP_UTF8,       // Source string is in UTF-8
		MB_ERR_INVALID_CHARS,        // Conversion flags
		utf8.data(),   // Source UTF-8 string pointer
		utf8Length,    // Length of the source UTF-8 string, in chars
		nullptr,       // Unused - no conversion done in this step
		0              // Request size of destination buffer, in wchar_ts
	);

	if (utf16Length == 0)
	{
		PrintErrorMessage(::GetLastError());
		return FALSE;
	}
	outWStr.resize(utf16Length);

	int result = ::MultiByteToWideChar(
		CP_UTF8,       // Source string is in UTF-8
		MB_ERR_INVALID_CHARS,        // Conversion flags
		utf8.data(),   // Source UTF-8 string pointer
		utf8Length,    // Length of source UTF-8 string, in chars
		&outWStr[0],     // Pointer to destination buffer
		utf16Length    // Size of destination buffer, in wchar_ts          
	);
	if (result == 0)
	{
		PrintErrorMessage(::GetLastError());
		return FALSE;
	}
	return TRUE;
}

BOOL string_utils::TryConvertUtf16ToUtf8(const std::wstring& utf16, OUT std::string& outStr)
{
	if (utf16.empty())
	{
		return FALSE;
	}
	const int utf16Length = static_cast<int>(utf16.length());
	const int utf8Length = ::WideCharToMultiByte(
		CP_UTF8,       // Source string is in UTF-16
		WC_ERR_INVALID_CHARS,        // Conversion flags
		utf16.data(),   // Source UTF-16 string pointer
		utf16Length,    // Length of the source UTF-16 string, in chars
		nullptr,       // Unused - no conversion done in this step
		0,              // Request size of destination buffer, in wchar_ts
		NULL,
		NULL
	);

	if (utf8Length == 0)
	{
		PrintErrorMessage(::GetLastError());
		return FALSE;
	}
	outStr.resize(utf8Length);

	int result = ::WideCharToMultiByte(
		CP_UTF8,       // Source string is in UTF-16
		WC_ERR_INVALID_CHARS,        // Conversion flags
		utf16.data(),   // Source UTF-16 string pointer
		utf16Length,    // Length of source UTF-16 string, in chars
		&outStr[0],     // Pointer to destination buffer
		utf8Length,    // Size of destination buffer, in wchar_ts
		NULL,
		NULL
	);
	if (result == 0)
	{
		PrintErrorMessage(::GetLastError());
		return FALSE;
	}
	return TRUE;
}

// credit: https://stackoverflow.com/a/57346888
std::vector<std::string> string_utils::SplitA(const std::string& input, const std::string& delim)
{
	std::vector<std::string> result;

	size_t found = input.find(delim);
	size_t startIndex = 0;

	while (found != std::string::npos)
	{
		result.push_back(std::string(input.begin() + startIndex, input.begin() + found));
		startIndex = found + delim.size();
		found = input.find(delim, startIndex);
	}
	if (startIndex != input.size())
		result.push_back(std::string(input.begin() + startIndex, input.end()));
	return result;
}

std::vector<std::wstring> string_utils::SplitW(const std::wstring& input, const std::wstring& delim)
{
	std::vector<std::wstring> result;

	size_t found = input.find(delim);
	size_t startIndex = 0;

	while (found != std::wstring::npos)
	{
		result.push_back(std::wstring(input.begin() + startIndex, input.begin() + found));
		startIndex = found + delim.size();
		found = input.find(delim, startIndex);
	}
	if (startIndex != input.size())
		result.push_back(std::wstring(input.begin() + startIndex, input.end()));
	return result;
}
