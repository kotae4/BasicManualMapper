#include "CProcess.h"
#include "process_utils.h"
#include "string_utils.h"
#include "logger.h"
#include <iostream>
#include <tlhelp32.h>
#include <algorithm>

std::vector<std::unique_ptr<CProcess>> CProcess::_Processes;

void CProcess::RegisterPendingModule(const CModule* injectedModule)
{
	// check that it's not already registered. we don't want duplicates.
	for (const auto& mod : this->PendingModules)
	{
		if (mod->NameA == injectedModule->NameA)
			return;
	}

	this->PendingModules.push_back(injectedModule);
}

void CProcess::NotifyFinalizedModule(std::unique_ptr<CModule>& injectedModule)
{
	// erase it from PendingModules if present
	CModule* tmp = injectedModule.get();
	this->PendingModules.erase(std::remove_if(this->PendingModules.begin(), this->PendingModules.end(), [tmp](const CModule*& mod)
		{ return tmp->NameA == mod->NameA; }));

	// now add it to the final InjectedModules list
	this->InjectedModules.push_back(std::move(injectedModule));
}

BOOL CProcess::GetModules()
{
	// TO-DO:
	// manually iterate PEB module list instead of calling CreateToolhelp32Snapshot
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32{};

	DWORD snapshotFlags = TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32;
	//  Take a snapshot of all modules in the specified process. 
	hModuleSnap = CreateToolhelp32Snapshot(snapshotFlags, pid);
	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		// TO-DO:
		// read docs and make sure this actually sets a last error
		string_utils::PrintLastError();
		LOG_ERROR("Could not get module snapshot for process");
		return FALSE;
	}

	me32.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(hModuleSnap, &me32))
	{
		// TO-DO:
		// read docs and make sure this actually sets a last error
		string_utils::PrintLastError();
		LOG_ERROR("Module snapshot was invalid");
		CloseHandle(hModuleSnap);
		return FALSE;
	}

	do
	{
		// process the module here
		BOOL success = FALSE;
#ifdef _UNICODE
		if (_wcsicmp(me32.szModule, NameW.c_str()) == 0)
#else
		if (_stricmp(me32.szModule, Name.c_str()) == 0)
#endif
		{
			// this is the main module, so we process it into this->MainModule instead of the Modules vector.
			success = CModule::TryParseRemoteModuleByAddress(this, reinterpret_cast<uintptr_t>(me32.modBaseAddr), me32.modBaseSize, &this->MainModule);
		}
		else
		{
			std::unique_ptr<CModule> newMod;
			success = CModule::TryParseRemoteModuleByAddress(this, reinterpret_cast<uintptr_t>(me32.modBaseAddr), me32.modBaseSize, &newMod);
			if (success)
				this->Modules.push_back(std::move(newMod));
			else
				LOG_ERRORW(L"Could not parse remote module '{}'", me32.szModule);
		}
	} while (Module32Next(hModuleSnap, &me32));
	CloseHandle(hModuleSnap);

	return TRUE;
}

BOOL CProcess::GetPEB()
{
	// TO-DO:
	// do this, would allow us to write our own module iteration w/out going through winapi (and a bunch of other cool stuff)
	return FALSE;
}

BOOL CProcess::TryGetModuleByNameA(std::string name, CModule** outModule)
{
	// start with PendingModules first, then InjectedModules, and finally plain ol' Modules
	for (const auto& modPtr : this->PendingModules)
	{
		if (modPtr->NameA == name)
		{
			*outModule = const_cast<CModule*>(modPtr);
			return TRUE;
		}
	}

	for (const auto& modPtr : this->InjectedModules)
	{
		if (modPtr->NameA == name)
		{
			*outModule = modPtr.get();
			return TRUE;
		}
	}

	for (auto& modPtr : this->Modules)
	{
		// NOTE:
		// if the process is 32bit we don't want to return the 64bit version of ntdll.dll, for example. so we check the bitness here too.
		if ((modPtr->NameA == name) && (modPtr->Is64bit == this->Is64Bit))
		{
			*outModule = modPtr.get();
			return TRUE;
		}
	}
	return FALSE;
}

BOOL CProcess::TryGetModuleByNameW(std::wstring name, CModule** outModule)
{
	for (const auto& modPtr : this->PendingModules)
	{
		if (modPtr->NameW == name)
		{
			*outModule = const_cast<CModule*>(modPtr);
			return TRUE;
		}
	}

	for (const auto& modPtr : this->InjectedModules)
	{
		if (modPtr->NameW == name)
		{
			*outModule = modPtr.get();
			return TRUE;
		}
	}

	for (auto& modPtr : this->Modules)
	{
		if (modPtr->NameW == name)
		{
			*outModule = modPtr.get();
			return TRUE;
		}
	}
	return FALSE;
}

BOOL CProcess::TryReadMemory(uintptr_t lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, bool isContiguous /* = true */)
{
	BOOL success = FALSE;
	SIZE_T numBytesRead = 0;
	if (isContiguous == true)
	{
		success = ReadProcessMemory(this->hProc, reinterpret_cast<LPCVOID>(lpBaseAddress), lpBuffer, nSize, &numBytesRead);
		if (success == FALSE)
		{
			string_utils::PrintLastError();
			LOG_ERROR("Could not read remote memory into local buffer");
			return FALSE;
		}
	}
	else
	{
		// have to call VirtualQueryEx on each page and only call ReadProcessMemory on pages that are committed
		// this all started with trying to read syswow64\\kernel32.dll btw. it's mapped with reserved but uncommitted pages mixed in.
		MEMORY_BASIC_INFORMATION64 mbi{ 0 };
		for (uintptr_t addr = lpBaseAddress; addr < lpBaseAddress + nSize; addr = mbi.BaseAddress + mbi.RegionSize)
		{
			success = VirtualQueryEx(this->hProc, reinterpret_cast<LPCVOID>(addr), reinterpret_cast<PMEMORY_BASIC_INFORMATION>(&mbi), sizeof(MEMORY_BASIC_INFORMATION64));
			if (success == FALSE)
			{
				string_utils::PrintLastError();
				LOG_ERROR("Could not query {:#x}", addr);
			}

			if ((mbi.State != MEM_COMMIT) || (mbi.Protect <= PAGE_NOACCESS))
				continue;

			// TO-DO:
			// make sure this works when lpBaseAddress isn't the start of a page
			// also make sure lpBuffer is sized appropriately. nSize should be a multiple of page size (4096).
			uintptr_t bufferOffset = addr - lpBaseAddress;
			success = ReadProcessMemory(this->hProc, reinterpret_cast<LPCVOID>(mbi.BaseAddress), (reinterpret_cast<BYTE*>(lpBuffer) + bufferOffset), mbi.RegionSize, &numBytesRead);
			if (success == FALSE)
			{
				string_utils::PrintLastError();
				LOG_ERROR("Could not read page @ {:#x} despite being queried beforehand...", mbi.BaseAddress);
				return FALSE;
			}
		}
	}

	return success;
}

/* static */ BOOL CProcess::TryGetProcessByPID(DWORD _pid, CProcess** outProcess)
{
	std::unique_ptr<CProcess> proc = std::make_unique<CProcess>();
	proc->pid = _pid;

	BOOL success = process_utils::GetProcessByPID(_pid, &proc->hProc);
	if (success == FALSE)
	{
		LOG_ERROR("Could not locate target process");
		return FALSE;
	}

	success = process_utils::GetProcessMainModuleName(proc->hProc, &proc->FullPath, &proc->FullPathW);
	if (success == FALSE)
	{
		LOG_ERROR("Could not get target process name");
		return FALSE;
	}

	proc->Name = proc->FullPath.substr(proc->FullPath.find_last_of("/\\") + 1);
	proc->NameW = proc->FullPathW.substr(proc->FullPathW.find_last_of(L"/\\") + 1);

	success = process_utils::IsProcess64bit(proc->hProc, &proc->Is64Bit);
	if (success == FALSE)
	{
		LOG_ERROR("Could not determine target process bitness");
		return FALSE;
	}

	success = proc->GetModules();
	if (success == FALSE)
	{
		LOG_ERROR("Could not enumerate target process modules");
		return FALSE;
	}

	_Processes.push_back(std::move(proc));
	*outProcess = _Processes.back().get();
	return TRUE;
}

/* static */ BOOL CProcess::TryGetProcessByName(std::string& mainModuleName, CProcess** outProcess)
{
	std::unique_ptr<CProcess> proc = std::make_unique<CProcess>();

	BOOL success = process_utils::GetProcessByExeName(mainModuleName.c_str(), &proc->hProc, &proc->pid);
	if (success == FALSE)
	{
		LOG_ERROR("Could not locate target process");
		return FALSE;
	}

	success = process_utils::GetProcessMainModuleName(proc->hProc, &proc->FullPath, &proc->FullPathW);
	if (success == FALSE)
	{
		LOG_ERROR("Could not get target process name");
		return FALSE;
	}

	proc->Name = proc->FullPath.substr(proc->FullPath.find_last_of("/\\") + 1);
	proc->NameW = proc->FullPathW.substr(proc->FullPathW.find_last_of(L"/\\") + 1);

	success = process_utils::IsProcess64bit(proc->hProc, &proc->Is64Bit);
	if (success == FALSE)
	{
		LOG_ERROR("Could not determine target process bitness");
		return FALSE;
	}

	success = proc->GetModules();
	if (success == FALSE)
	{
		LOG_ERROR("Could not enumerate target process modules");
		return FALSE;
	}

	_Processes.push_back(std::move(proc));
	*outProcess = _Processes.back().get();
	return TRUE;
}