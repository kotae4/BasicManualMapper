#pragma once

#include <Windows.h>
#include <string>

namespace process_utils
{
	BOOL GetProcessByPID(DWORD pid, HANDLE* outHandle);
	BOOL GetProcessByExeName(const std::string& exePath, HANDLE* outHandle, DWORD* outPID, int sleepTimerMillis = 500, int numRetries = 10);
	BOOL GetProcessMainModuleName(HANDLE hProc, std::string* outName, std::wstring* outNameW);
	BOOL GetRemoteModuleFilePath(DWORD pid, uintptr_t modBaseAddr, bool Is64Bit, std::string* outFullPath, std::wstring* outFullPathW);
	BOOL IsProcess64bit(HANDLE hProc, bool* outIs64bit);
};

