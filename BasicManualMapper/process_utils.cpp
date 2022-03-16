#include "process_utils.h"

#include <TlHelp32.h>
#include <iostream>
#include <Psapi.h>
#include "logger.h"
#include "string_utils.h"

BOOL process_utils::GetProcessByExeName(const std::string& exePath, HANDLE* outHandle, DWORD* outPID, int sleepTimerMillis /* = 500 */, int numRetries/* = 10 */)
{
    HANDLE hProc = NULL;
    DWORD pid = 0;
    int tries = 0;
    std::wstring exePathW;
    if (string_utils::TryConvertUtf8ToUtf16(exePath, exePathW) == FALSE)
    {
        LOG_ERROR("Could not convert exePath to unicode string");
        return FALSE;
    }
    while ((hProc == NULL) && (tries < numRetries))
    {
        HANDLE procSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (procSnapshot == INVALID_HANDLE_VALUE)
        {
            string_utils::PrintLastError();
            LOG_ERROR("Could not get process snapshot");
            continue;
        }
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(procSnapshot, &pe32) == FALSE)
        {
            string_utils::PrintLastError();
            LOG_ERROR("Process snapshot was invalid");
            CloseHandle(procSnapshot);
            continue;
        }
        do
        {
#ifdef _UNICODE
            if (_wcsicmp(pe32.szExeFile, exePathW.c_str()) == 0)
#else
            if (_stricmp(pe32.szExeFile, exePath.c_str()) == 0)
#endif
            {
                // found game, get handle and return
                pid = pe32.th32ProcessID;
                hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
                if (hProc == NULL)
                {
                    string_utils::PrintLastError();
                    LOG_ERROR("Could not open handle to target process");
                    break;
                }
                else
                {
                    CloseHandle(procSnapshot);
                    *outHandle = hProc;
                    *outPID = pid;
                    return TRUE;
                }
            }
        } while (Process32Next(procSnapshot, &pe32));

        CloseHandle(procSnapshot);
        tries++;
        Sleep(sleepTimerMillis);
    }
    return FALSE;
}

BOOL process_utils::GetProcessByPID(DWORD pid, HANDLE* outHandle)
{
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProc == NULL)
    {
        string_utils::PrintLastError();
        LOG_ERROR("Could not open handle to process with PID {}", pid);
        return FALSE;
    }
    *outHandle = hProc;
    return TRUE;
}

BOOL process_utils::GetProcessMainModuleName(HANDLE hProc, std::string* outName, std::wstring* outNameW)
{
    char name[MAX_PATH];
    DWORD bufSize = MAX_PATH;

    BOOL success = QueryFullProcessImageNameA(hProc, 0, name, &bufSize);
    if (success == FALSE)
    {
        string_utils::PrintLastError();
        LOG_ERROR("Could not query full process image name");
        return FALSE;
    }

    *outName = std::string(name);
    success = string_utils::TryConvertUtf8ToUtf16(*outName, *outNameW);
    if (success == FALSE)
    {
        string_utils::PrintLastError();
        LOG_ERROR("Could not convert main module name to wide");
        return FALSE;
    }

    return TRUE;
}

BOOL process_utils::GetRemoteModuleFilePath(DWORD pid, uintptr_t modBaseAddr, bool Is64Bit, std::string* outFullPath, std::wstring* outFullPathW)
{
    HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
    MODULEENTRY32 me32;

    DWORD snapshotFlags = TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32;
    //  Take a snapshot of all modules in the specified process. 
    hModuleSnap = CreateToolhelp32Snapshot(snapshotFlags, pid);
    if (hModuleSnap == INVALID_HANDLE_VALUE)
    {
        string_utils::PrintLastError();
        LOG_ERROR("Could not get module snapshot for process with PID {}", pid);
        return FALSE;
    }

    me32.dwSize = sizeof(MODULEENTRY32);
    if (!Module32First(hModuleSnap, &me32))
    {
        string_utils::PrintLastError();
        LOG_ERROR("Module snapshot was invalid for process with PID {}", pid);
        CloseHandle(hModuleSnap);
        return FALSE;
    }

    BOOL wasFound = FALSE;
    do
    {
        if (reinterpret_cast<uintptr_t>(me32.modBaseAddr) == modBaseAddr)
        {
            *outFullPathW = std::wstring(me32.szExePath);
            wasFound = TRUE;
            break;
        }
    } while (Module32Next(hModuleSnap, &me32));
    CloseHandle(hModuleSnap);

    BOOL success = string_utils::TryConvertUtf16ToUtf8(*outFullPathW, *outFullPath);
    if (success == FALSE)
    {
        string_utils::PrintLastError();
        std::wcout << "Could not convert remote module filepath '" << *outFullPathW << "' to narrow string\n";
        //LOG_ERROR("Could not convert remote module filepath '{}' to narrow string", (*outFullPathW).c_str());
        return FALSE;
    }

    return wasFound;
}

BOOL process_utils::IsProcess64bit(HANDLE hProc, bool* outIs64bit)
{
    USHORT procArch, machineArch;
    BOOL success = IsWow64Process2(hProc, &procArch, &machineArch);
    if (success == FALSE)
    {
        string_utils::PrintLastError();
        LOG_ERROR("Call to IsWow64Process2 failed");
        return FALSE;
    }
    *outIs64bit = ((machineArch == IMAGE_FILE_MACHINE_AMD64) && (procArch == IMAGE_FILE_MACHINE_UNKNOWN));
    return TRUE;
}