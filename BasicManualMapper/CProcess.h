#pragma once

#include <Windows.h>
#include <memory>
#include <vector>
#include <string>
#include "CModule.h"

class CModule;

class CProcess
{
public:
	DWORD pid;
	std::string Name;
	std::wstring NameW;
	std::string FullPath;
	std::wstring FullPathW;
	HANDLE hProc;
	bool Is64Bit;


	std::unique_ptr<CModule> MainModule;

	/// <summary>
	/// Modules properly mapped into the process and linked w/ the PEB loader list
	/// </summary>
	std::vector<std::unique_ptr<CModule>> Modules;
	/// <summary>
	/// Modules that are in the process of being injected
	/// </summary>
	std::vector<const CModule*> PendingModules;
	/// <summary>
	/// Modules that have been injected and may or may not be linked w/ the PEB loader list
	/// </summary>
	std::vector<std::unique_ptr<CModule>> InjectedModules;


	void RegisterPendingModule(const CModule* injectedModule);
	void NotifyFinalizedModule(std::unique_ptr<CModule>& injectedModule);
	BOOL GetModules();
	BOOL GetPEB();
	BOOL TryGetModuleByNameA(std::string name, CModule** outModule);
	BOOL TryGetModuleByNameW(std::wstring name, CModule** outModule);
	BOOL TryReadMemory(uintptr_t lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, bool isContiguous = true);


	static BOOL TryGetProcessByPID(DWORD _pid, CProcess** outProcess);
	static BOOL TryGetProcessByName(std::string& mainModuleName, CProcess** outProcess);

private:
	static std::vector<std::unique_ptr<CProcess>> _Processes;
};