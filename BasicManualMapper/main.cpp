#include "main.h"

#include "CLArgsParser.h"
#include "process_utils.h"
#include "string_utils.h"
#include "file_utils.h"
#include "CProcess.h"
#include "CModule.h"
#include "logger.h"
#include <vector>
#include <string>
#include <filesystem>

// TO-DO:
// move a lot of the pe_utils and process_utils functions into the CProcess or CModule classes
// change standard return type to a status code instead of simple BOOL so i can better handle fail cases
// go over log messages and include more relevant information where possible
// go through and fix all the points where i use an improper data-type and forgot to cast to proper one. mainly for addresses.
// go through and triple check that my casts are proper. could probably use static_cast in place of some reinterpret_casts, etc.
// figure out better wide and narrow string usages. it's very annoying converting between them.
// expand execution functionality. include different execution techniques and make working with shellcode more robust.
// go through and make sure i'm not leaking any handles, allocations, or threads.
// verify it works in all configurations: x86 with x86 target, x64 with x86 target (tested - works), and x64 with x64 target
// DelayedImports! i completely forgot these. none of the modules i've tested have delayed imports, so i'll leave it unfinished for now.

BOOL TryResolvePathToModuleA(CProcess* pTargetProcess, std::string moduleName, bool isWoW64, std::string& outPath, BOOL& outWasAPISetMapping);
BOOL TryFindOrMapModuleA(CProcess* pTargetProcess, std::string moduleName, CModule** outModule);
BOOL RelocateModule(CProcess* pTargetProcess, CModule* mappedModule);
BOOL LoadDependencies(CProcess* pTargetProcess, CModule* mappedModule);
BOOL SetImageProtections(CProcess* pTargetProcess, CModule* mappedModule);
BOOL ManualMap(std::string& modulePath, CProcess* pTargetProcess, CModule** outModule);
BOOL TryExecuteMappedModules(CProcess* pTargetProcess);

#pragma pack(8)
struct ExecData
{
    uintptr_t AddrOfDllMain;
    uintptr_t AddrOfUserArg;
    DWORD Reason;
    uintptr_t BaseAddrOfModule;
};
// execution shellcode
// we allocate enough memory to hold the args and the shellcode.
// then we fill in the address of the args portion in the shellcode (so it becomes: mov zcx, <addrOfArgs>).
// then we'll create a thread or point an existing thread to the start of the shellcode portion and let it run. this will then call our mapped module's dllmain.
// the args portion should be structured as so: [0] = AddrOfDllMain, [1] = AddrOfUserArg (or nullptr), [2] = DWORD reason for call (DLL_PROCESS_ATTACH), [3] = BaseAddrOfModule
// the ExecData struct is used for this, with 8 byte padding so it can be used for both the x86 and x64 versions.
/* x86
0:  55                      push   ebp
1:  89 e5                   mov    ebp,esp
3:  b9 0f 1f 2f 3f          mov    ecx,0x3f2f1f0f
8:  8b 01                   mov    eax,DWORD PTR [ecx]
a:  ff 71 08                push   DWORD PTR [ecx+0x8]
d:  ff 71 10                push   DWORD PTR [ecx+0x10]
10: ff 71 18                push   DWORD PTR [ecx+0x18]
13: ff d0                   call   eax
15: 89 ec                   mov    esp,ebp
17: 5d                      pop    ebp
18: c3                      ret
*/
BYTE bsExecDllMain_x86[] = { 0x55, 0x89, 0xE5, 0xB9, 0x0F, 0x1F, 0x2F, 0x3F, 0x8B, 0x01, 0xFF, 0x71, 0x08, 0xFF, 0x71, 0x10, 0xFF, 0x71, 0x18, 0xFF, 0xD0, 0x89, 0xEC, 0x5D, 0xC3 };
int offsetToAddrBytes_x86 = 4;
/* x64
0:  55                      push   rbp
1:  48 89 e5                mov    rbp,rsp
4:  48 b9 0f 1f 2f 3f 4f    movabs rcx,0x7f6f5f4f3f2f1f0f
b:  5f 6f 7f
e:  48 8b 01                mov    rax,QWORD PTR [rcx]
11: ff 71 08                push   QWORD PTR [rcx+0x8]
14: ff 71 10                push   QWORD PTR [rcx+0x10]
17: ff 71 18                push   QWORD PTR [rcx+0x18]
1a: ff d0                   call   rax
1c: 48 89 ec                mov    rsp,rbp
1f: 5d                      pop    rbp
20: c3                      ret
*/
BYTE bsExecDllMain_x64[] = { 0x55, 0x48, 0x89, 0xE5, 0x48, 0xB9, 0x0F, 0x1F, 0x2F, 0x3F, 0x4F, 0x5F, 0x6F, 0x7F, 0x48, 0x8B, 0x01, 0xFF, 0x71, 0x08, 0xFF, 0x71, 0x10, 0xFF, 0x71, 0x18, 0xFF, 0xD0, 0x48, 0x89, 0xEC, 0x5D, 0xC3 };
int offsetToAddrBytes_x64 = 6;

BOOL TryResolvePathToModuleA(CProcess* pTargetProcess, std::string moduleName, bool isWoW64, std::string& outPath, BOOL& outWasAPISetMapping)
{
    // TO-DO:
    // add support for API sets (if needed)
    // add support for winSxS manifests
    // check that paths returned from winapi funcs are actually valid and there aren't weird locale conversion issues

    char tmpBuf[MAX_PATH];
    UINT length = 0;
    if (isWoW64)
        length = GetSystemWow64DirectoryA(tmpBuf, MAX_PATH);
    else
        length = GetSystemDirectoryA(tmpBuf, MAX_PATH);
    if ((length > MAX_PATH) || (length == 0))
    {
        // TO-DO:
        // resize tmpWBuf to length and call again instead of erroring out
        LOG_ERROR("Path to system directory greater than MAX_PATH or some other error (length: {})", length);
        return FALSE;
    }
    std::string systemPathStr = std::string(tmpBuf);
    std::string testPath;

    // 1. check if it's an api set mapping first. if it is then we can return and check if that module exists.
    for (const auto& apiMapping : CModule::_ApiSetA)
    {
        // example input: "api-ms-win-crt-math-l1-1-0.dll"
        // we want to match at least: "api-ms-win-crt-math-l1-1"
        // i guess if the patch ver is 0 then it's just omitted entirely. don't know if same holds true if both minor and patch ver are 0.
        if (moduleName.find(apiMapping.first) != std::string::npos)
        {
            if (apiMapping.second.size() < 1)
            {
                LOG_ERROR("Matching API set '{}' does not have any mappings", apiMapping.first);
                return FALSE;
            }
            else if (apiMapping.second.size() >= 2)
                LOG_WARN("Matching API set '{}' has more than 1 mapping. Defaulting to first ('{}')", apiMapping.first, apiMapping.second.at(0));

            testPath = systemPathStr + "\\" + apiMapping.second.at(0);
            if (file_utils::DoesFileExistA(testPath))
            {
                outPath = testPath;
                outWasAPISetMapping = TRUE;
                LOG_INFO("Module {} was an APISet mapping to {}", moduleName, apiMapping.second.at(0));
                return TRUE;
            }
            else
            {
                LOG_INFO("Module {} was an APISet mapping to {}, but that file doesn't exist on disk", moduleName, apiMapping.second.at(0));
                outWasAPISetMapping = TRUE;
                return FALSE;
            }
        }
    }

    // standard search order (if not resolved first via API sets or winSxS)
    // 1. HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs
    HKEY hKnownDLLsReg = NULL;
    LSTATUS status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs", 0, KEY_READ, &hKnownDLLsReg);
    if (status != ERROR_SUCCESS)
    {
        string_utils::PrintLastError();
        LOG_WARN("Could not open KnownDLLs registry key. Skipping this step in the standard search order.");
    }
    else
    {
        // there's probably a way to get the number of values in a key,
        // but i'm lazy and it doesn't really matter because RegEnumValue will return ERROR_NO_MORE_ITEMS once it's reached the end anyway
        // so i'll just loop until 4096 for now. no way it'll actually reach that.
        for (int index = 0; ((index < 4096) && (status == ERROR_SUCCESS)); index++)
        {
            DWORD bufSize = MAX_PATH;
            char nameBuf[MAX_PATH];
            char valueBuf[MAX_PATH];

            status = RegEnumValueA(hKnownDLLsReg, index, nameBuf, &bufSize, NULL, NULL, reinterpret_cast<BYTE*>(valueBuf), &bufSize);
            if ((status != ERROR_SUCCESS) && (status != ERROR_NO_MORE_ITEMS))
            {
                LOG_WARN("Could not enumerate KnownDLLs registry key (status: {})", status);
                break;
            }
            std::string valueBufStr = std::string(valueBuf);
            if (valueBufStr == moduleName)
            {
                outPath = systemPathStr + "\\" + moduleName;
                RegCloseKey(hKnownDLLsReg);
                return TRUE;
            }
        }
        RegCloseKey(hKnownDLLsReg);
    }

    // 2. The directory from which the application loaded.
    testPath = pTargetProcess->FullPath.substr(0, pTargetProcess->FullPath.rfind("\\")) + "\\" + moduleName;
    if (file_utils::DoesFileExistA(testPath))
    {
        outPath = testPath;
        return TRUE;
    }

    // 3. The system directory. Use the GetSystemDirectory function to get the path of this directory.
    testPath = systemPathStr + "\\" + moduleName;
    if (file_utils::DoesFileExistA(testPath))
    {
        outPath = testPath;
        return TRUE;
    }

    // 4. The Windows directory. Use the GetWindowsDirectory function to get the path of this directory.
    length = GetWindowsDirectoryA(tmpBuf, MAX_PATH);
    if ((length > MAX_PATH) || (length == 0))
    {
        // TO-DO:
        // resize tmpWBuf to length and call again instead of erroring out
        LOG_ERROR("Path to windows directory greater than MAX_PATH or some other error (length: {})", length);
        return FALSE;
    }
    testPath = std::string(tmpBuf) + "\\" + moduleName;
    if (file_utils::DoesFileExistA(testPath))
    {
        outPath = testPath;
        return TRUE;
    }

    // 5. The current directory.
    length = GetCurrentDirectoryA(MAX_PATH, tmpBuf);
    if ((length > MAX_PATH) || (length == 0))
    {
        // TO-DO:
        // resize tmpWBuf to length and call again instead of erroring out
        LOG_ERROR("Path to current directory greater than MAX_PATH or some other error (length: {})", length);
        return FALSE;
    }
    testPath = std::string(tmpBuf) + "\\" + moduleName;
    if (file_utils::DoesFileExistA(testPath))
    {
        outPath = testPath;
        return TRUE;
    }

    // 6. The directories that are listed in the PATH environment variable. GetEnvironmentVariableW(L"PATH"...
    char envBuf[4096];
    length = GetEnvironmentVariableA("PATH", envBuf, 4096);
    if ((length > 4096) || (length == 0))
    {
        // TO-DO:
        // resize envBuf to length and call again instead of erroring out
        LOG_ERROR("PATH environment variable greater than 4096 or some other error (length: {})", length);
        return FALSE;
    }
    std::string pathStr = std::string(envBuf);
    std::vector<std::string> pathSplits = string_utils::SplitA(pathStr, ";");
    for (auto& pathVar : pathSplits)
    {
        if (pathVar.ends_with("\\") == false)
        {
            testPath = pathVar + "\\" + moduleName;
        }
        else
        {
            testPath = pathVar + moduleName;
        }
        if (file_utils::DoesFileExistA(testPath))
        {
            outPath = testPath;
            return TRUE;
        }
    }

    return FALSE;
}

BOOL TryFindOrMapModuleA(CProcess* pTargetProcess, std::string moduleName, CModule** outModule)
{
    BOOL success = pTargetProcess->TryGetModuleByNameA(moduleName, outModule);
    // if it's not found, then we have to map it
    if (success == FALSE)
    {
        LOG_INFO("Module '{}' was not already present in process, resolving path and manually mapping now...", moduleName);
        std::string modulePath;
        BOOL wasAPISetMapping = FALSE;
        success = TryResolvePathToModuleA(pTargetProcess, moduleName, (pTargetProcess->Is64Bit == false), modulePath, wasAPISetMapping);
        if (success == FALSE)
        {
            LOG_ERROR("Could not resolve path to '{}'", moduleName);
            return FALSE;
        }
        if (wasAPISetMapping == true)
        {
            std::string strippedPath = modulePath.substr(modulePath.find_last_of("/\\") + 1);
            success = pTargetProcess->TryGetModuleByNameA(strippedPath, outModule);

            if (success == TRUE)
            {
                LOG_INFO("Resolved '{}' to API Set Mapping '{}' and module was found in target", moduleName, modulePath);
                return TRUE;
            }
            else
            {
                LOG_INFO("Resolved '{}' to API Set Mapping '{}' but module still needs to be mapped.", moduleName, modulePath);
            }
        }
        LOG_INFO("Resolved '{}' to '{}'", moduleName, modulePath);
        // 3b. map the dependent module (recursive)
        success = ManualMap(modulePath, pTargetProcess, outModule);
        if (success == FALSE)
        {
            LOG_ERROR("Could not manual map dependency '{}'", modulePath);
            return FALSE;
        }
    }

    return TRUE;
}

BOOL RelocateModule(CProcess* pTargetProcess, CModule* mappedModule)
{
    LOG_INFO("Applying relocations for module '{}'", mappedModule->NameA);
    uintptr_t relocDelta = mappedModule->RemoteBase - mappedModule->ImgReqBase;
    if (relocDelta == 0)
    {
        LOG_INFO("No relocations necessary. Image was allocated at desired base ({:#x})", mappedModule->ImgReqBase);
        return TRUE;
    }

    bool canBeRelocated = (mappedModule->Is64bit ? mappedModule->pNtHdr64->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE : mappedModule->pNtHdr32->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);
    if (canBeRelocated == false)
    {
        LOG_ERROR("Module was not allocated at its desired base, but image was not compiled with a dynamic base.");
        return FALSE;
    }

    IMAGE_DATA_DIRECTORY relocDir = (mappedModule->Is64bit ? mappedModule->pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] : mappedModule->pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
    uintptr_t relocStart = (uintptr_t)mappedModule->FileBase + relocDir.VirtualAddress;
    uintptr_t relocEnd = relocStart + relocDir.Size;
    RelocBlock* curBlock = reinterpret_cast<RelocBlock*>(relocStart);
    if (curBlock == nullptr)
    {
        LOG_INFO("Module does not use relocations, no need to relocate.");
        return TRUE;
    }

    BYTE* pRemoteModuleBytes = NULL;
    BOOL success = mappedModule->GetModuleBytes(&pRemoteModuleBytes, -1, true);
    if (success == FALSE)
    {
        LOG_ERROR("Could not read remote image into local buffer for relocation fixups");
        return FALSE;
    }

    while (((uintptr_t)curBlock < relocEnd) && (curBlock->BlockSize > 8))
    {
        int numRelocsInBlock = (curBlock->BlockSize - 8) / 2;
        for (int index = 0; index < numRelocsInBlock; index++)
        {
            WORD type = curBlock->Item[index].Type;
            WORD offset = curBlock->Item[index].Offset;
            uintptr_t relocAddr = (uintptr_t)pRemoteModuleBytes + curBlock->PageRVA + offset;
            switch (type)
            {
            case IMAGE_REL_BASED_ABSOLUTE:
                // docs say this type is used for padding and should be skipped
                continue;
            case IMAGE_REL_BASED_HIGHLOW:
                // 32 bits of delta is added to the 32bit field pointed to by offset
                *reinterpret_cast<DWORD*>(relocAddr) = (int)relocDelta;
                break;
            case IMAGE_REL_BASED_DIR64:
                // full delta is added to the 64bit field pointed to by offset
                *reinterpret_cast<DWORD64*>(relocAddr) = (uintptr_t)relocDelta;
                break;
            case IMAGE_REL_BASED_LOW:
                // low 16 bits of delta is added to the 16bit field pointed to by offset
                *reinterpret_cast<WORD*>(relocAddr) = LOWORD(relocDelta);
                break;
            case IMAGE_REL_BASED_HIGH:
                // high 16 bits of delta is added to the 16bit field pointed to by offset
                *reinterpret_cast<WORD*>(relocAddr) = HIWORD(relocDelta);
                break;
            case IMAGE_REL_BASED_HIGHADJ:
                // high 16 bits of delta is added to the 16 bit field (actually 32 bits, but irrelevant) pointed to by offset
                // additionally, the next entry contains the low 16 bits of the field pointed to by offset
                // slightly confusing so i'm just going to print an error for now and see if it's actually encountered in the wild
                LOG_ERROR("Confusing relocation type encountered. Not yet supported because it's exceedingly rare and I'm exceedingly lazy (submit issue and I'll look into it)");
                return FALSE;
            default:
                LOG_ERROR("Weird relocation type encountered. Not yet supported because it's exceedingly rare and I'm exceedingly lazy (submit issue and I'll look into it)");
                return FALSE;

            }
        }
        curBlock = reinterpret_cast<RelocBlock*>(reinterpret_cast<uintptr_t>(curBlock) + curBlock->BlockSize);
    }

    // write fixed up image back over to remote process
    SIZE_T numBytesWritten = 0;
    // we set the first 0x1000 bytes to readonly when we wrote the initial image over, so skip those to avoid that access violation
    success = WriteProcessMemory(pTargetProcess->hProc, reinterpret_cast<BYTE*>(mappedModule->RemoteBase) + 0x1000, pRemoteModuleBytes + 0x1000, mappedModule->ImgSize - 0x1000, &numBytesWritten);
    if (success == FALSE)
    {
        string_utils::PrintLastError();
        LOG_ERROR("Could not write relocations back to remote process");
        return FALSE;
    }

    return TRUE;
}

BOOL LoadDependencies(CProcess* pTargetProcess, CModule* mappedModule)
{
    LOG_INFO("Resolving dependencies for module '{}'", mappedModule->NameA);
    BYTE* pRemoteModuleBytes = NULL;
    BOOL success = mappedModule->GetModuleBytes(&pRemoteModuleBytes, -1, true);
    if (success == FALSE)
    {
        string_utils::PrintLastError();
        LOG_ERROR("Could not read remote image into local buffer for dependency resolutions");
        return FALSE;
    }

    // 1. iterate the modules that mappedModule depends upon
    // 2. check if dependent module is already loaded in pTargetProcess
    // 3. if not already loaded, then:
    //      3a. resolve its path using windows path resolution
    //      3b. map the dependent module (recursion starts here)
    // 4. iterate each imported function in mappedModule
    // 5. find the imported function's entry in the dependent module's ExportAddressTable
    // 6. write the address to mappedModule's ImportAddressTable
    // 7. once iteration of modules and functions is done, write mappedModule's ImportAddressTable back over to pTargetProcess.

    // 1. iterate the modules that mappedModule depends upon
    for (const std::pair<std::string, std::vector<CModule::ImportData>>& dependency : mappedModule->Imports)
    {
        CModule* dependentModule, *forwarderModule = NULL;
        // 2 & 3a & 3b. check if dependent module is already loaded in pTargetProcess, resolve its path using windows path resolution, map the dependent module (recursion starts here).
        LOG_INFO("[{}]: resolving dependency '{}'", mappedModule->NameA, dependency.first);
        success = TryFindOrMapModuleA(pTargetProcess, dependency.first, &dependentModule);
        if (success == FALSE)
        {
            LOG_ERROR("Could not find or map dependency '{}'", dependency.first);
            return FALSE;
        }
        // 4. iterate each imported function in mappedModule
        for (const CModule::ImportData& importedSymbol : dependency.second)
        {
            // 5. find the imported function's entry in the dependent module's ExportAddressTable
            const CModule::ExportData* exportedSymbol;
            if (importedSymbol.IsImportByOrdinal)
                success = dependentModule->TryGetExportByOrdinal(importedSymbol.Ordinal, exportedSymbol);
            else
                success = dependentModule->TryGetExportByName(importedSymbol.Name, exportedSymbol);

            if (success == FALSE)
            {
                LOG_ERROR("Could not find exported symbol for dependency '{}' [{}]", importedSymbol.Name, importedSymbol.Ordinal);
                return FALSE;
            }

            // CModule::TryGetExport will return forward exports plainly, so we have to traverse the forward chain here
            forwarderModule = NULL;
            int sanity = 0;
            while ((exportedSymbol->IsForwarder) && (sanity < 50))
            {
                // get the module that hosts the forwarded symbol, mapping it if it's not present
                success = TryFindOrMapModuleA(pTargetProcess, exportedSymbol->ForwarderModule, &forwarderModule);
                if (success == FALSE)
                {
                    LOG_ERROR("Could not resolve forward export symbol for dependency");
                    return FALSE;
                }
                // now, with that module, try to get the exported symbol again, noting that it could *still* be a forwarder (hence the while loop)
                if (exportedSymbol->IsForwardByOrdinal)
                    success = forwarderModule->TryGetExportByOrdinal(exportedSymbol->ForwarderSymbolOrdinal, exportedSymbol);
                else
                    success = forwarderModule->TryGetExportByName(exportedSymbol->ForwarderSymbolName, exportedSymbol);
            }
            if (sanity >= 50)
            {
                LOG_ERROR("Could not resolve forward export symbol, max loop counter reached");
                return FALSE;
            }

            // by now, exportedSymbol should be the real export, so now copy its value over to the dependency's IAT
            // 6. write the address to mappedModule's ImportAddressTable
            uintptr_t IATEntryAddress = (reinterpret_cast<uintptr_t>(pRemoteModuleBytes) + importedSymbol.BoundThunkEntryRVA);
            uintptr_t functionAddress = (forwarderModule == NULL ? dependentModule->RemoteBase : forwarderModule->RemoteBase) + exportedSymbol->FunctionRVA;
            if (pTargetProcess->Is64Bit)
                *reinterpret_cast<DWORD64*>(IATEntryAddress) = functionAddress;
            else
                *reinterpret_cast<DWORD*>(IATEntryAddress) = static_cast<DWORD>(functionAddress);
        }
    }

    // 7. once iteration of modules and functions is done, write mappedModule's ImportAddressTable back over to pTargetProcess.
    LOG_INFO("[{}]: Writing filled-out ImportAddressTable back to remote process", mappedModule->NameA);
    SIZE_T numBytesWritten = 0;
    success = WriteProcessMemory(pTargetProcess->hProc, reinterpret_cast<BYTE*>(mappedModule->RemoteBase) + 0x1000, pRemoteModuleBytes + 0x1000, mappedModule->ImgSize - 0x1000, &numBytesWritten);
    if (success == FALSE)
    {
        string_utils::PrintLastError();
        LOG_ERROR("Could not write IAT back to remote process for module '{}'", mappedModule->NameA);
        return FALSE;
    }

    return TRUE;
}

BOOL SetImageProtections(CProcess* pTargetProcess, CModule* mappedModule)
{
    BOOL success = FALSE;
    DWORD oldProt = 0;
    for (const auto& section : mappedModule->Sections)
    {
        // yoink'd directly from blackbone
        // it's intuitive enough though
        DWORD sectionProtection = PAGE_NOACCESS;
        if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE)
        {
            if (section->Characteristics & IMAGE_SCN_MEM_WRITE)
                sectionProtection = PAGE_EXECUTE_READWRITE;
            else if (section->Characteristics & IMAGE_SCN_MEM_READ)
                sectionProtection = PAGE_EXECUTE_READ;
            else
                sectionProtection = PAGE_EXECUTE;
        }
        else
        {
            if (section->Characteristics & IMAGE_SCN_MEM_WRITE)
                sectionProtection = PAGE_READWRITE;
            else if (section->Characteristics & IMAGE_SCN_MEM_READ)
                sectionProtection = PAGE_READONLY;
            else
                sectionProtection = PAGE_NOACCESS;
        }
        if (sectionProtection != PAGE_NOACCESS)
        {
            // write the protection
            success = VirtualProtectEx(pTargetProcess->hProc, reinterpret_cast<LPVOID>(mappedModule->RemoteBase + section->VirtualAddress), section->Misc.VirtualSize, sectionProtection, &oldProt);
            if (success == FALSE)
            {
                string_utils::PrintLastError();
                LOG_ERROR("Could not set section '{}' page protection to {}", reinterpret_cast<char*>(section->Name[0]), sectionProtection);
                return FALSE;
            }
        }
        else
        {
            // decommit any sections that have PAGE_NOACCESS.
            // if nothing can access it, then why should it exist?
            success = VirtualFreeEx(pTargetProcess->hProc, reinterpret_cast<LPVOID>(mappedModule->RemoteBase + section->VirtualAddress), section->Misc.VirtualSize, MEM_FREE);
            LOG_WARN("Section '{}' has PAGE_NOACCESS protection, decommitting and freeing it", reinterpret_cast<char*>(section->Name[0]));
        }
    }
    return TRUE;
}

BOOL ManualMap(std::string& modulePath, CProcess* pTargetProcess, CModule** outModule)
{
    LOG_INFO("Mapping module '{}' to process '{}' with PID {}...", modulePath, pTargetProcess->Name, pTargetProcess->pid);
    // 1. Read user dll into memory
    // * Open file w/ CreateFile
    // * Create file mapping w/ CreateFileMapping
    // * Create mapped view of file w/ MapViewOfFile
    // * Read/Write to it as if it's memory (MapViewOfFile returns base address)
    std::unique_ptr<CModule> mappedModule;
    BOOL success = CModule::TryParseModuleByFilePath(modulePath, &mappedModule);
    if (success == FALSE)
    {
        LOG_ERROR("Could not parse module at '{}'", modulePath);
        return false;
    }

    // TO-DO:
    // support WoW64 better
    if (pTargetProcess->Is64Bit != mappedModule->Is64bit)
    {
        LOG_ERROR("Module at '{}' does not match process bitness (x86 vs x64 or vice versa)", modulePath);
        return false;
    }

    // TO-DO:
    // 2. Create activation context if image has a manifest (dependencies always skip this step)
    // * Constructs shellcode and executes in target process

    // 3. Allocate memory in target process to hold image using VirtualAllocEx
    LOG_INFO("[{}]: allocating memory in remote process and writing headers", mappedModule->NameA);
    LPVOID remoteBase = VirtualAllocEx(pTargetProcess->hProc, reinterpret_cast<LPVOID>(mappedModule->ImgReqBase), mappedModule->ImgSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remoteBase == NULL)
    {
        string_utils::PrintLastError();
        LOG_ERROR("Could not allocate memory in remote process");
        return false;
    }

    // 4. Write image using WriteProcessMemory
    // * Headers first, then set headers to readonly, then write section by section skipping discardable sections
    SIZE_T numBytesWritten = 0;
    success = WriteProcessMemory(pTargetProcess->hProc, remoteBase, reinterpret_cast<LPCVOID>(mappedModule->FileBase), 0x1000, &numBytesWritten);
    if (success == FALSE)
    {
        string_utils::PrintLastError();
        LOG_ERROR("Could not write image headers to remote process");
        return false;
    }
    DWORD oldProtect = 0;
    success = VirtualProtectEx(pTargetProcess->hProc, remoteBase, 0x1000, PAGE_READONLY, &oldProtect);
    if (success == FALSE)
    {
        string_utils::PrintLastError();
        LOG_ERROR("Could not set page protection of image headers");
        return false;
    }
    // now write sections
    LOG_INFO("[{}]: Writing sections", mappedModule->NameA);
    IMAGE_SECTION_HEADER* pSectionHdr = reinterpret_cast<IMAGE_SECTION_HEADER*>(mappedModule->pNtHdr32 + 1);
    if (mappedModule->Is64bit)
        pSectionHdr = reinterpret_cast<IMAGE_SECTION_HEADER*>(mappedModule->pNtHdr64 + 1);
    for (int i = 0; i < mappedModule->pNtHdr32->FileHeader.NumberOfSections; i++, pSectionHdr++)
    {
        std::cout << pSectionHdr->Name << std::endl;
        if (pSectionHdr->Characteristics & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE))
        {
            if (pSectionHdr->SizeOfRawData == 0)
            {
                LOG_INFO("\t-Skipping section because it contains no raw data");
                continue;
            }
            success = WriteProcessMemory(pTargetProcess->hProc, reinterpret_cast<BYTE*>(remoteBase) + pSectionHdr->VirtualAddress, reinterpret_cast<LPCVOID>((reinterpret_cast<BYTE*>(mappedModule->FileBase) + pSectionHdr->VirtualAddress)), pSectionHdr->SizeOfRawData, &numBytesWritten);
            if (success == FALSE)
            {
                string_utils::PrintLastError();
                LOG_ERROR("Could not write image section '{}' to remote process", reinterpret_cast<char*>(pSectionHdr->Name[0]));
                return false;
            }
        }
        else
        {
            LOG_INFO("\t-Skipping section because it doesn't have relevant characteristics");
        }
    }
    // now that it's written to the remote process, fill in some of its data fields.
    // this allows us to use the same CModule instance to represent both the local file and the remote.
    mappedModule->OwningProcess = pTargetProcess;
    mappedModule->RemoteBase = reinterpret_cast<uintptr_t>(remoteBase);
    mappedModule->HasOwningProcess = true;

    // 5. Apply relocations if image has them and if VirtualAllocEx didn't allocate at desired base address
    // * Blackbone reads the entire image from the remote process back into main process... need to figure out why it doesn't just use its already-existing local copy (from the MapViewOfFile call)
    LOG_INFO("[{}]: Applying relocations", mappedModule->NameA);
    success = RelocateModule(pTargetProcess, mappedModule.get());
    if (success == FALSE)
    {
        string_utils::PrintLastError();
        LOG_ERROR("Could not apply relocation fixups");
        return false;
    }

    // 6. Load all dependencies and fill out IAT using newly loaded dependency's EAT. Make sure to account for delayed imports and forwarded imports.
    // * Blackbone reads the image from the remote process again. Very strange.
    // * The loading of dependencies eventually calls the same method to load the main dll, making this a recursive function.
    // * Also have to account for Wow64 barrier if target process is 32 bit? System DLLs are always 64 bit.
    // * Path resolution should match windows' own path resolution as closely as possible. Activation context is used for this too, when name starts with "api-set"
    // * If winSxS identities don't match (?) then final path should probe *remote* winSxS w/ RtlDosApplyFileIsolationRedirection_Ustr, RtlActivateActivationContext, and RtlDeactivateActivationContext.
    // * Shellcode is generated and executed in target process for the above function calls ^
    
    // before we recursively load dependencies, we need to register this module with the process' module list
    LOG_INFO("[{}]: Resolving dependencies and filling in ImportAddressTable", mappedModule->NameA);
    pTargetProcess->RegisterPendingModule(mappedModule.get());
    success = LoadDependencies(pTargetProcess, mappedModule.get());
    if (success == FALSE)
    {
        LOG_ERROR("Could not resolve image imports");
        return false;
    }

    // 7. Apply proper memory protections for image sections based on section characteristics
    // * Decommit any section that has PAGE_NOACCESS protection w/ VirtualFree
    LOG_INFO("[{}]: Setting page protections for image sections", mappedModule->NameA);
    success = SetImageProtections(pTargetProcess, mappedModule.get());
    if (success == FALSE)
    {
        LOG_ERROR("Could not set image section page protections");
        return false;
    }

    // 8. (optional) Enable SEH and VEH exception handling
    // * Lots of shellcode, lots of strange native structs. Interesting to research when more time is available.

    // 9. (somewhat optional?) Initialize security cookie
    // * Generates security cookie based on complicated formula (x86 and x64 formulas are different)
    // * Writes cookie to IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG's SecurityCookie field
    // * Formula starts with an executing thread's ID. Not sure if it matters which thread's ID we choose. Need to research.

    // 10. (optional) Create reference for native loader functions
    // * This seems like something we definitely wouldn't want for a cheat DLL
    // * Does seem very interesting though. Need to learn about the structs it's creating and their role in all this.

    // 11. (optional?) Initialize static TLS data
    // * Allocates and writes more native structs, very interesting.
    // * Eventually writes to the TEB's TLS pointer.
    // * Also then generates some shellcode and executes it, presumably invoking each TLS callback?

    // 12. (somewhat optional?) Fill out TLS callbacks
    // * Looks like it just fixes up the addresses, converting file address to mapped in-process address
    

    // 13. Release local copy of image w/ UnmapViewOfFile
    // TO-DO:
    // having an outModule while also transferring ownership of the smart pointer to pTargetProcess is a problem.
    // need to re-think this. maybe remove the outModule and have each caller go through the CProcess class to retrieve the newly mapped module.
    LOG_INFO("[{}]: Releasing local copy and returning successfully!", mappedModule->NameA);
    *outModule = mappedModule.get();
    mappedModule->ReleaseFile();
    pTargetProcess->NotifyFinalizedModule(mappedModule);
    return true;
}

BOOL TryExecuteMappedModules(CProcess* pTargetProcess)
{
    for (const auto& modulePtr : pTargetProcess->InjectedModules)
    {

        const uint64_t sizeOfBootstrapper = sizeof(ExecData) + sizeof(bsExecDllMain_x64);
        LOG_INFO("Allocating memory in remote process for bootstrapping shellcode");
        modulePtr->BootstrapperSize = sizeOfBootstrapper;
        modulePtr->BootstrapperBase = reinterpret_cast<uintptr_t>(VirtualAllocEx(pTargetProcess->hProc, NULL, sizeOfBootstrapper, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (modulePtr->BootstrapperBase == NULL)
        {
            string_utils::PrintLastError();
            LOG_ERROR("Could not allocate memory in remote process for bootstrapper");
            return FALSE;
        }

        ExecData execData{ 0 };
        execData.AddrOfDllMain = (modulePtr->RemoteBase + modulePtr->EntryPointRVA);
        execData.AddrOfUserArg = 0;
        execData.BaseAddrOfModule = modulePtr->RemoteBase;
        execData.Reason = DLL_PROCESS_ATTACH;
        if (modulePtr->Is64bit)
        {
            *reinterpret_cast<DWORD64*>(reinterpret_cast<BYTE*>(bsExecDllMain_x64) + offsetToAddrBytes_x64) = modulePtr->BootstrapperBase;
        }
        else
        {
            *reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(bsExecDllMain_x86) + offsetToAddrBytes_x86) = static_cast<DWORD>(modulePtr->BootstrapperBase);
        }
        SIZE_T numBytesWritten = 0;
        BOOL success = WriteProcessMemory(pTargetProcess->hProc, reinterpret_cast<LPVOID>(modulePtr->BootstrapperBase), &execData, sizeof(execData), &numBytesWritten);
        if (success == FALSE)
        {
            string_utils::PrintLastError();
            LOG_ERROR("Could not write ExecData struct to remote process");
            VirtualFreeEx(pTargetProcess->hProc, reinterpret_cast<LPVOID>(modulePtr->BootstrapperBase), 0, MEM_RELEASE);
            return FALSE;
        }

        success = WriteProcessMemory(pTargetProcess->hProc, reinterpret_cast<LPVOID>(modulePtr->BootstrapperBase + sizeof(execData)), (modulePtr->Is64bit ? bsExecDllMain_x64 : bsExecDllMain_x86), (modulePtr->Is64bit ? sizeof(bsExecDllMain_x64) : sizeof(bsExecDllMain_x86)), &numBytesWritten);
        if (success == FALSE)
        {
            string_utils::PrintLastError();
            LOG_ERROR("Could not write bootstrapping code to remote process");
            VirtualFreeEx(pTargetProcess->hProc, reinterpret_cast<LPVOID>(modulePtr->BootstrapperBase), 0, MEM_RELEASE);
            return FALSE;
        }

        // now that the ExecData struct and the shellcode has been written, we can execute it
        // here is where we'd include any other execution techniques like thread hijacking or APCs
        DWORD threadID = 0;
        modulePtr->BootstrapperThread = CreateRemoteThread(pTargetProcess->hProc, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(modulePtr->BootstrapperBase + sizeof(execData)), NULL, 0, &threadID);
        if (modulePtr->BootstrapperThread == NULL)
        {
            string_utils::PrintLastError();
            LOG_ERROR("Failed to create thread to execute bootstrapping code");
            VirtualFreeEx(pTargetProcess->hProc, reinterpret_cast<LPVOID>(modulePtr->BootstrapperBase), 0, MEM_RELEASE);
            return FALSE;
        }

        // we need to know when the bootstrapper thread exits so we can free its memory via VirtualFreeEx (called from CModule's dtor)
        DWORD res = WaitForSingleObject(modulePtr->BootstrapperThread, 5000);
        if (res == WAIT_FAILED)
        {
            string_utils::PrintLastError();
            LOG_ERROR("Failed to wait on bootstrapper thread");
            // let's just assume it's running, so we shouldn't free it just yet because that'll definitely cause a crash
            //VirtualFreeEx(pTargetProcess->hProc, reinterpret_cast<LPVOID>(modulePtr->BootstrapperBase), 0, MEM_RELEASE);
            return FALSE;
        }
        else if (res == WAIT_TIMEOUT)
        {
            LOG_WARN("Bootstrapper thread is still running, is user module doing too much work in DllMain? Crash incoming.");
        }
        else if (res == WAIT_OBJECT_0)
        {
            DWORD exitCode = 0;
            success = GetExitCodeThread(modulePtr->BootstrapperThread, &exitCode);
            if (success == FALSE)
            {
                LOG_WARN("Bootstrapper thread exited, but we couldn't get the exit code.");
            }
            else
            {
                LOG_INFO("Bootstrapper thread exited with code {}", exitCode);
            }
        }
        else
        {
            LOG_ERROR("Unknown wait result: {}", res);
        }

        modulePtr->HasBeenBootstrapped = true;
    }
    return TRUE;
}

int main(int argc, char* argv[])
{
    // 1. Parse args (path to user DLL, path to target EXE)
    LOG_INFO("Parsing args...");

    if (argc != 5)
    {
        LOG_ERROR("Invalid number of args. Expected -dll <Full\\Path\\To\\DLL.dll> -target <ExeName.exe>\nPlease note: target exe should be running in a process already and should not include file path");
        return 0;
    }

    std::string dllPath;
    std::string targetExePath;
    
    CLArgsParser::RegisterArg("-dll", ArgHandler{ .m_NumArgs = 1, .m_Handler = ([&dllPath](const std::vector<std::string>& args) -> void {
        if (std::filesystem::exists(args[0]) == false)
        {
            LOG_ERROR("Could not find dll at '{}'", args[0].c_str());
            dllPath = "";
            return;
        }
        LOG_INFO("Setting dllPath to '{}'", args[0]);
        dllPath = args[0];
        })});
    CLArgsParser::RegisterArg("-target", ArgHandler{ .m_NumArgs = 1, .m_Handler = ([&targetExePath](const std::vector<std::string>& args) -> void {
        LOG_INFO("Setting targetExe to '{}'", args[0]);
        targetExePath = args[0];
        }) });

    CLArgsParser::ProcessArgs(argv, argc);

    if ((dllPath == "") || (targetExePath == ""))
    {
        LOG_ERROR("Could not parse arguments. Expected -dll <Full\\Path\\To\\DLL.dll> -target <ExeName.exe>");
        return 0;
    }

    LOG_INFO("Parsed DLL path '{}' and target EXE '{}'", dllPath, targetExePath);
    LOG_INFO("Scanning for target process...");
    // 2. Scan processes and look for main module to match target exe path
    CProcess* pTargetProcess;
    BOOL success = CProcess::TryGetProcessByName(targetExePath, &pTargetProcess);
    if (success == FALSE)
    {
        LOG_ERROR("Could not find target process that matches '{}'", targetExePath);
        return 0;
    }
    LOG_INFO("Found target process (PID: {})", pTargetProcess->pid);
    LOG_INFO("Mapping user module...");
    CModule* mappedUserModule = NULL;
    success = ManualMap(dllPath, pTargetProcess, &mappedUserModule);
    if (success == FALSE)
    {
        LOG_ERROR("Could not manual map user module");
        return 0;
    }

    // finally, execute the mapped image's entry point.
    // need to allocate memory to hold the args + shellcode to push the args onto stack and call entrypoint
    success = TryExecuteMappedModules(pTargetProcess);
    if (success == FALSE)
    {
        LOG_ERROR("Could not execute mapped modules");
        return 0;
    }

    LOG_INFO("Exiting!");
    return 0;
}