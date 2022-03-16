#include "file_utils.h"

BOOL file_utils::DoesFileExistW(std::wstring filepath)
{
	// credit: https://stackoverflow.com/questions/4403986/c-which-is-the-best-method-of-checking-for-file-existence-on-windows-platform
	DWORD attribs = GetFileAttributesW(filepath.c_str());
	if (attribs == INVALID_FILE_ATTRIBUTES)
		return FALSE;

	// TO-DO:
	// handle other cases

	return TRUE;
}

BOOL file_utils::DoesFileExistA(std::string filepath)
{
	// credit: https://stackoverflow.com/questions/4403986/c-which-is-the-best-method-of-checking-for-file-existence-on-windows-platform
	DWORD attribs = GetFileAttributesA(filepath.c_str());
	if (attribs == INVALID_FILE_ATTRIBUTES)
		return FALSE;

	// TO-DO:
	// handle other cases

	return TRUE;
}