#include "CModule.h"
#include "ApiSet.h"
#include "NativeStructures.h"
#include "string_utils.h"
#include "process_utils.h"
#include "logger.h"
#include <iostream>
#include <algorithm>
#include <cwctype>

bool CModule::IsAPISetInitialized = false;
std::map<std::wstring, std::vector<std::wstring>> CModule::_ApiSetW{};
std::map<std::string, std::vector<std::string>> CModule::_ApiSetA{};
int CModule::_NumAllocated = 0;
int CModule::_NumDeallocated = 0;

BOOL CModule::ParseImports(BYTE* moduleBytes /* = NULL */)
{
	BOOL success = FALSE;
	if (moduleBytes == NULL)
	{
		success = GetModuleBytes(&moduleBytes);
		if (success == FALSE)
		{
			LOG_ERROR("Could not get module bytes into local buffer for imports parsing");
			return FALSE;
		}
	}

	// TO-DO:
	// when working with RVAs, always make sure resulting address is within range of moduleBytes

	IMAGE_DATA_DIRECTORY importDir = (Is64bit ? pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] : pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
	if (importDir.Size == 0)
	{
		LOG_WARN("{} has no import directory, nothing to parse.", this->NameA);
		return TRUE;
	}
	uintptr_t importStart = reinterpret_cast<uintptr_t>(moduleBytes) + importDir.VirtualAddress;
	IMAGE_IMPORT_DESCRIPTOR* pImportEntry = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(importStart);
	while (pImportEntry->Name != NULL)
	{
		// NOTE:
		// Name is an RVA to the module name (name+ext, but no path)
		// OriginalFirstThunk is table of all imported functions w/ name or ordinal
		// FirstThunk is the IAT, which should be filled with the actual addresses of the imported functions once that import is loaded
		// IMAGE_THUNK_DATA struct is used to represent entries in the OriginalFirstThunk table or the unbound FirstThunk table

		// 1. get the module name and save it
		char* pModuleName = reinterpret_cast<char*>(reinterpret_cast<uintptr_t>(moduleBytes) + pImportEntry->Name);
		std::string moduleName = std::string(pModuleName);
		std::transform(moduleName.begin(), moduleName.end(), moduleName.begin(), ::tolower);

		auto match = Imports.find(moduleName);
		if (match != Imports.end())
		{
			LOG_WARN("Module '{}' has already processed imports for dependency '{}'. Clearing its entries and reprocessing anyway.", this->NameA, moduleName);
			match->second.clear();
		}
		// 2. iterate the OriginalFirstThunk table and process each import, whether it be by function name or by ordinal
		BYTE* pOrigThunkEntry = reinterpret_cast<BYTE*>(reinterpret_cast<uintptr_t>(moduleBytes) + pImportEntry->OriginalFirstThunk);
		BYTE* pBoundThunkEntry = reinterpret_cast<BYTE*>(reinterpret_cast<uintptr_t>(moduleBytes) + pImportEntry->FirstThunk);
		while (*pOrigThunkEntry != 0)
		{
			// each thunk entry is a 32 bit or 64 bit integer depending on architecture
			// the entry is packed, the data is either a 16 bit ordinal or a 31 bit name RVA (for x64, the space in between is unused)
			ImportData data{};
			data.IsImportByOrdinal = (bool)(Is64bit ? reinterpret_cast<ImportThunkEntry64*>(pOrigThunkEntry)->isOrdinal : reinterpret_cast<ImportThunkEntry32*>(pOrigThunkEntry)->isOrdinal);
			if (data.IsImportByOrdinal == true)
			{
				// thunk->Data is a 16 bit ordinal
				data.Ordinal = (Is64bit ? reinterpret_cast<ImportThunkEntry64*>(pOrigThunkEntry)->Data : reinterpret_cast<ImportThunkEntry32*>(pOrigThunkEntry)->Data) & 0xFFFF;
				data.Name = "";
				data.HasName = false;
			}
			else
			{
				// thunk->Data is a 31 bit name RVA relative to image base
				DWORD nameRVA = (Is64bit ? reinterpret_cast<ImportThunkEntry64*>(pOrigThunkEntry)->Data : reinterpret_cast<ImportThunkEntry32*>(pOrigThunkEntry)->Data) & 0x7FFFFFFF;
				data.Name = std::string((reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(reinterpret_cast<uintptr_t>(moduleBytes) + nameRVA))->Name);
				std::transform(data.Name.begin(), data.Name.end(), data.Name.begin(), ::tolower);
				data.Ordinal = 0;
				data.IsImportByOrdinal = false;
				data.HasName = true;
			}

			// save RVA to its IT and IAT entry
			// TO-DO:
			// i'm thinking subtracting the image base will be enough, but my brain is smooth right now so definitely double check
			data.OrigThunkEntryRVA = (reinterpret_cast<uintptr_t>(pOrigThunkEntry) - reinterpret_cast<uintptr_t>(moduleBytes));
			data.BoundThunkEntryRVA = (reinterpret_cast<uintptr_t>(pBoundThunkEntry) - reinterpret_cast<uintptr_t>(moduleBytes));

			Imports[moduleName].push_back(data);

			// move to next entry
			pOrigThunkEntry += (Is64bit ? sizeof(IMAGE_THUNK_DATA64) : sizeof(IMAGE_THUNK_DATA32));
			pBoundThunkEntry += (Is64bit ? sizeof(IMAGE_THUNK_DATA64) : sizeof(IMAGE_THUNK_DATA32));
		}
		pImportEntry++;
	}
	return TRUE;
}

BOOL CModule::ParseExports(BYTE* moduleBytes /* = NULL */)
{
	BOOL success = FALSE;
	if (moduleBytes == NULL)
	{
		success = GetModuleBytes(&moduleBytes);
		if (success == FALSE)
		{
			LOG_ERROR("Could not get module bytes into local buffer for exports parsing");
			return FALSE;
		}
	}

	// TO-DO:
	// when working with RVAs, always make sure resulting address is within range of moduleBytes
	// also look over this entire function, my brain was broken when writing all this.

	IMAGE_DATA_DIRECTORY exportDataDir = (Is64bit ? pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] : pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	if (exportDataDir.Size == 0)
	{
		LOG_WARN("{} has no export directory, nothing to parse.", this->NameA);
		return TRUE;
	}
	IMAGE_EXPORT_DIRECTORY* exportTable = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>((moduleBytes + exportDataDir.VirtualAddress));
	DWORD* namePtrTable = reinterpret_cast<DWORD*>((moduleBytes + exportTable->AddressOfNames));
	WORD* ordinalTable = reinterpret_cast<WORD*>((moduleBytes + exportTable->AddressOfNameOrdinals));
	this->ExportAddressTableRVA = exportTable->AddressOfFunctions;

	uintptr_t ExportAddressTable = reinterpret_cast<uintptr_t>(moduleBytes + exportTable->AddressOfFunctions);

	// curious to see how often this happens. i wonder if only ancient DLLs have exported symbols by ordinal only.
	if (exportTable->NumberOfNames != exportTable->NumberOfFunctions)
		LOG_WARN("Not all exported functions of module '{}' have an associated name (named: {}, total: {})", this->NameA, exportTable->NumberOfNames, exportTable->NumberOfFunctions);

	for (int symbolIndex = 0; symbolIndex < exportTable->NumberOfFunctions; symbolIndex++)
	{
		ExportData data{};
		data.HasName = false;
		data.UnbiasedOrdinal = symbolIndex;
		data.BiasedOrdinal = symbolIndex + exportTable->Base;
		// we can read the value from the EAT too, since it's baked into the image unlike the IAT which relies on the loader to fill it out
		// TO-DO:
		// make parantheses better. currently adding index + sizeof(value) DWORDs, not bytes. so it's way off.
		if (Is64bit)
			data.FunctionRVA = static_cast<uintptr_t>(*reinterpret_cast<DWORD64*>(reinterpret_cast<BYTE*>(ExportAddressTable) + (data.UnbiasedOrdinal * sizeof(DWORD64))));
		else
			data.FunctionRVA = static_cast<uintptr_t>(*reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(ExportAddressTable) + (data.UnbiasedOrdinal * sizeof(DWORD))));


		// now search for the matching name, if present.
		// this extra loop kills performance but i don't think it's wise to assume exports are ordered by named followed by un-named
		// it could be the case that symbols 0-10 have corresponding names, but 11-13 don't, then 14-20 do, then 21-25 don't, etc..
		// and so name[11] might actually match symbol[14], hence the need for this extra loop starting from 0.
		for (int nameIndex = 0; nameIndex < exportTable->NumberOfNames; nameIndex++)
		{
			if (ordinalTable[nameIndex] == symbolIndex)
			{
				// match found, so add its name
				data.Name = std::string(reinterpret_cast<const char*>((moduleBytes + namePtrTable[nameIndex])));
				std::transform(data.Name.begin(), data.Name.end(), data.Name.begin(), ::tolower);
				data.HasName = true;
			}
		}

		// and we also have to check if it's a forwarded export...
		// if the value in the EAT is within the range given by the IMAGE_DATA_DIRECTORY then we know it's a forwarder RVA.
		// TO-DO:
		// check if forwarder module is already loaded, if so then get that and try to resolve the symbol here
		if ((data.FunctionRVA > exportDataDir.VirtualAddress) &&
			(data.FunctionRVA < (exportDataDir.VirtualAddress + exportDataDir.Size)))
		{
			data.IsForwarder = true;
			std::string forwarderStr = std::string(reinterpret_cast<const char*>((moduleBytes + data.FunctionRVA)));
			std::string forwarderSymbolName = forwarderStr.substr(forwarderStr.find('.') + 1, std::string::npos);

			data.ForwarderModule = forwarderStr.substr(0, forwarderStr.find('.')) + ".dll";
			std::transform(data.ForwarderModule.begin(), data.ForwarderModule.end(), data.ForwarderModule.begin(), ::tolower);
			size_t indexOfOrdinal = forwarderStr.find('#');
			if (indexOfOrdinal != std::string::npos)
			{
				data.IsForwardByOrdinal = true;
				data.ForwarderSymbolOrdinal = static_cast<WORD>(atoi(forwarderSymbolName.c_str() + 1));
			}
			else
			{
				data.IsForwardByOrdinal = false;
				data.ForwarderSymbolName = forwarderSymbolName;
				std::transform(data.ForwarderSymbolName.begin(), data.ForwarderSymbolName.end(), data.ForwarderSymbolName.begin(), ::tolower);
			}
		}

		// finally, add it to the Exports vector
		this->Exports.push_back(data);
	}

	return TRUE;
}

BOOL CModule::Parse()
{
	BYTE* buf = nullptr;
	BOOL success = GetModuleBytes(&buf);
	if (success == FALSE)
	{
		LOG_ERROR("Could not get module bytes into local buffer for parsing");
		return FALSE;
	}

	IMAGE_DOS_HEADER* pDosHdr = reinterpret_cast<IMAGE_DOS_HEADER*>(buf);
	this->pNtHdr32 = reinterpret_cast<IMAGE_NT_HEADERS32*>(reinterpret_cast<BYTE*>(pDosHdr) + pDosHdr->e_lfanew);
	this->pNtHdr64 = reinterpret_cast<IMAGE_NT_HEADERS64*>(reinterpret_cast<BYTE*>(pDosHdr) + pDosHdr->e_lfanew);
	bool isValid = (this->pNtHdr32->Signature == 0x4550);
	if (isValid == false)
	{
		LOG_ERROR("Image '{}' file header had invalid signature", this->NameA);
		return FALSE;
	}

	this->Is64bit = (this->pNtHdr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
	this->EntryPointRVA = (this->Is64bit ? this->pNtHdr64->OptionalHeader.AddressOfEntryPoint : this->pNtHdr32->OptionalHeader.AddressOfEntryPoint);
	this->ImgSize = (this->Is64bit ? this->pNtHdr64->OptionalHeader.SizeOfImage : this->pNtHdr32->OptionalHeader.SizeOfImage);
	this->ImgReqBase = (uint64_t)(this->Is64bit ? this->pNtHdr64->OptionalHeader.ImageBase : this->pNtHdr32->OptionalHeader.ImageBase);
	this->ImgHdrSize = (this->Is64bit ? this->pNtHdr64->OptionalHeader.SizeOfHeaders : this->pNtHdr32->OptionalHeader.SizeOfHeaders);

	success = ParseImports(buf);
	if (success == FALSE)
	{
		LOG_ERROR("Could not parse imports for module '{}'", this->NameA);
		return FALSE;
	}

	success = ParseExports(buf);
	if (success == FALSE)
	{
		LOG_ERROR("Could not parse exports for module '{}'", this->NameA);
		return FALSE;
	}

	// parse sections table
	// sections table begins immediately after the optional header.
	// so adding size of optional header doesn't work because some i
	IMAGE_SECTION_HEADER* section = reinterpret_cast<IMAGE_SECTION_HEADER*>((this->Is64bit ? reinterpret_cast<BYTE*>(&this->pNtHdr64->OptionalHeader) + this->pNtHdr64->FileHeader.SizeOfOptionalHeader : reinterpret_cast<BYTE*>(&this->pNtHdr32->OptionalHeader) + this->pNtHdr32->FileHeader.SizeOfOptionalHeader));
	for (int sectionIndex = 0; sectionIndex < this->pNtHdr32->FileHeader.NumberOfSections; sectionIndex++, section++)
	{
		this->Sections.push_back(section);
	}

	return TRUE;
}

BOOL CModule::GetModuleBytes(BYTE** outBuffer, int numBytes /* = -1 */, bool fromRemoteOnly /* = false */)
{
	*outBuffer = reinterpret_cast<BYTE*>(this->FileBase);
	if ((this->HasFileMapping == false) || (fromRemoteOnly == true))
	{
		if (this->HasOwningProcess == false)
		{
			LOG_ERROR("Could not read remote image because there is no remote process");
			return FALSE;
		}

		if (this->LocalBuffer == nullptr)
			this->LocalBuffer = std::make_unique<BYTE[]>(this->ImgSize);

		*outBuffer = this->LocalBuffer.get();
		BOOL success = FALSE;
		SIZE_T numBytesRead = 0;
		if (numBytes > 0)
			success = OwningProcess->TryReadMemory(this->RemoteBase, *outBuffer, numBytes);
		else
			success = OwningProcess->TryReadMemory(this->RemoteBase, *outBuffer, this->ImgSize);

		if (success == FALSE)
		{
			string_utils::PrintLastError();
			LOG_ERROR("Could not read remote image into local buffer, trying again but accounting for holes this time...");
			if (numBytes > 0)
				success = OwningProcess->TryReadMemory(this->RemoteBase, *outBuffer, numBytes, false);
			else
				success = OwningProcess->TryReadMemory(this->RemoteBase, *outBuffer, this->ImgSize, false);

			if (success == FALSE)
			{
				string_utils::PrintLastError();
				LOG_ERROR("Could not read remote image even after accounting for holes");
			}

			return success;
		}
	}
	return TRUE;
}

BOOL CModule::TryGetExportByName(std::string name, const ExportData*& outExport)
{
	for (const auto& exportedSymbol : this->Exports)
	{
		if ((exportedSymbol.HasName) && (exportedSymbol.Name == name))
		{
			// we'll let the caller handle forwarded exports,
			// since the forwarder module may not be loaded and loading it here is beyond the scope of this function / class
			outExport = &exportedSymbol;
			return TRUE;
		}
	}
	return FALSE;
}

BOOL CModule::TryGetExportByOrdinal(WORD ordinal, const ExportData*& outExport)
{
	for (const auto& exportedSymbol : this->Exports)
	{
		if (exportedSymbol.UnbiasedOrdinal == ordinal)
		{
			// we'll let the caller handle forwarded exports,
			// since the forwarder module may not be loaded and loading it here is beyond the scope of this function / class
			outExport = &exportedSymbol;
			return TRUE;
		}
	}
	return FALSE;
}

void CModule::ReleaseFile()
{
	if (HasFileMapping)
	{
		UnmapViewOfFile(FileMapping.modFileBase);
		CloseHandle(FileMapping.hMappedModFile);
		CloseHandle(FileMapping.hModFile);
		HasFileMapping = false;
	}
}

/* static */ BOOL CModule::TryParseRemoteModuleByAddress(CProcess* _owningProcess, uintptr_t baseAddr, DWORD size, std::unique_ptr<CModule>* outModule)
{
	*outModule = std::make_unique<CModule>();
	CModule* tmpView = (*outModule).get();
	tmpView->HasOwningProcess = true;
	tmpView->OwningProcess = _owningProcess;
	tmpView->RemoteBase = baseAddr;
	tmpView->FileBase = NULL;
	tmpView->HasFileMapping = false;
	tmpView->ImgSize = size;

	BOOL success = process_utils::GetRemoteModuleFilePath(_owningProcess->pid, baseAddr, _owningProcess->Is64Bit, &tmpView->FullPathA, &tmpView->FullPathW);
	if (success == FALSE)
	{
		LOG_ERROR("Could not get remote module filepath from base address {:#x}", baseAddr);
		return FALSE;
	}

	tmpView->NameA = tmpView->FullPathA.substr(tmpView->FullPathA.find_last_of("/\\") + 1);
	std::transform(tmpView->NameA.begin(), tmpView->NameA.end(), tmpView->NameA.begin(), ::tolower);

	tmpView->NameW = tmpView->FullPathW.substr(tmpView->FullPathW.find_last_of(L"/\\") + 1);
	std::transform(tmpView->NameW.begin(), tmpView->NameW.end(), tmpView->NameW.begin(), ::towlower);

	return tmpView->Parse();
}

/* static */ BOOL CModule::TryParseModuleByFilePath(std::string& modulePath, std::unique_ptr<CModule>* outModule)
{
	*outModule = std::make_unique<CModule>();
	CModule* tmpView = (*outModule).get();
	tmpView->HasOwningProcess = false;
	tmpView->HasFileMapping = true;

	tmpView->FullPathA = modulePath;
	BOOL success = string_utils::TryConvertUtf8ToUtf16(tmpView->FullPathA, tmpView->FullPathW);
	if (success == FALSE)
	{
		LOG_ERROR("Could not convert module filepath to wide string '{}'", modulePath);
		return FALSE;
	}

	tmpView->NameA = tmpView->FullPathA.substr(tmpView->FullPathA.find_last_of("/\\") + 1);
	std::transform(tmpView->NameA.begin(), tmpView->NameA.end(), tmpView->NameA.begin(), ::tolower);
	tmpView->NameW = tmpView->FullPathW.substr(tmpView->FullPathW.find_last_of(L"/\\") + 1);
	std::transform(tmpView->NameW.begin(), tmpView->NameW.end(), tmpView->NameW.begin(), ::towlower);

	tmpView->FileMapping.hModFile = CreateFileA(modulePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (tmpView->FileMapping.hModFile == INVALID_HANDLE_VALUE)
	{
		string_utils::PrintLastError();
		LOG_ERROR("Could not open file '{}'", modulePath);
		return FALSE;
	}

	tmpView->FileMapping.hMappedModFile = CreateFileMappingA(tmpView->FileMapping.hModFile, 0, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	if (tmpView->FileMapping.hMappedModFile == NULL)
	{
		string_utils::PrintLastError();
		LOG_ERROR("Could not create file mapping for file '{}'", modulePath);
		CloseHandle(tmpView->FileMapping.hModFile);
		return FALSE;
	}

	tmpView->FileMapping.modFileBase = MapViewOfFile(tmpView->FileMapping.hMappedModFile, FILE_MAP_READ, 0, 0, 0);
	if (tmpView->FileMapping.modFileBase == NULL)
	{
		string_utils::PrintLastError();
		LOG_ERROR("Could not map view of file '{}'", modulePath);
		CloseHandle(tmpView->FileMapping.hMappedModFile);
		CloseHandle(tmpView->FileMapping.hModFile);
		return FALSE;
	}

	tmpView->FileBase = reinterpret_cast<uintptr_t>(tmpView->FileMapping.modFileBase);
	
	return tmpView->Parse();
}

/* static */ void CModule::InitAPISet()
{
	LOG_INFO("Initializing APISet mapping from current process PEB");
	// all of this APISet stuff is shamefully yoink'd from blackbone by darthton
	// https://github.com/DarthTon/Blackbone

	PEB_T* ppeb = reinterpret_cast<PEB_T*>(reinterpret_cast<TEB_T*>(NtCurrentTeb())->ProcessEnvironmentBlock);
	PAPI_SET_NAMESPACE_ARRAY_10 pSetMap = reinterpret_cast<PAPI_SET_NAMESPACE_ARRAY_10>(ppeb->ApiSetMap);

	for (DWORD i = 0; i < pSetMap->Count; i++)
	{
		PAPI_SET_NAMESPACE_ENTRY_10 pDescriptor = pSetMap->entry(i);

		std::vector<std::wstring> vhosts;
		wchar_t dllName[MAX_PATH] = { 0 };

		auto nameSize = pSetMap->apiName(pDescriptor, dllName);
		std::transform(dllName, dllName + nameSize / sizeof(wchar_t), dllName, ::towlower);

		PAPI_SET_VALUE_ARRAY_10 pHostData = pSetMap->valArray(pDescriptor);

		for (DWORD j = 0; j < pHostData->Count; j++)
		{
			PAPI_SET_VALUE_ENTRY_10 pHost = pHostData->entry(pSetMap, j);
			std::wstring hostName(
				reinterpret_cast<wchar_t*>(reinterpret_cast<uint8_t*>(pSetMap) + pHost->ValueOffset),
				pHost->ValueLength / sizeof(wchar_t)
			);

			if (!hostName.empty())
				vhosts.emplace_back(std::move(hostName));
		}

		_ApiSetW.emplace(dllName, std::move(vhosts));
	}

	// keep a separate copy of narrow string versions, because i suck and can't figure out whether i want everything to be wide or everything be narrow.
	BOOL success = FALSE;
	std::vector<std::string> hostsVec;
	std::string tmpNarrow;
	for (const auto& mapping : _ApiSetW)
	{
		for (const auto& host : mapping.second)
		{
			success = string_utils::TryConvertUtf16ToUtf8(host, tmpNarrow);
			if (success == FALSE)
			{
				string_utils::PrintLastError();
				LOG_ERRORW(L"Could not convert API set host '{}' to narrow string", host);
				continue;
			}
			hostsVec.push_back(tmpNarrow);
		}
		success = string_utils::TryConvertUtf16ToUtf8(mapping.first, tmpNarrow);
		if (success == FALSE)
		{
			string_utils::PrintLastError();
			LOG_ERRORW(L"Could not convert API set mapping '{}' to narrow string", mapping.first);
			continue;
		}
		_ApiSetA.emplace(tmpNarrow, std::move(hostsVec));
	}


	IsAPISetInitialized = true;
}

CModule::CModule()
{
	if (CModule::IsAPISetInitialized == false)
	{
		InitAPISet();
	}

	CModule::_NumAllocated++;
}

CModule::~CModule()
{
	if (HasFileMapping)
	{
		UnmapViewOfFile(FileMapping.modFileBase);
		CloseHandle(FileMapping.hMappedModFile);
		CloseHandle(FileMapping.hModFile);
		HasFileMapping = false;
	}
	/*
	if (HasBeenBootstrapped)
	{
		VirtualFreeEx(OwningProcess->hProc, reinterpret_cast<LPVOID>(BootstrapperBase), 0, MEM_RELEASE);
		CloseHandle(BootstrapperThread);
	}
	*/

	CModule::_NumDeallocated++;
}