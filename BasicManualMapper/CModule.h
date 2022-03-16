#pragma once

#include "CProcess.h"
#include <Windows.h>
#include <memory>
#include <map>
#include <vector>
#include <string>

class CProcess;

class CModule
{
public:
    /* === POD STRUCTS === */

    struct ImportThunkEntry32
    {
        DWORD Data : 31;
        DWORD isOrdinal : 1;
    };
    struct ImportThunkEntry64
    {
        DWORD64 Data : 63;
        DWORD64 isOrdinal : 1;
    };

    struct ImportData
    {
        // whether this function is imported by ordinal or by name
        bool IsImportByOrdinal;
        // function ordinal, if imported by ordinal
        WORD Ordinal;
        /// <summary>
        /// RVA to the IAT entry. if bound, add to module base and dereference to get the address of the function.
        /// if not bound, this should be identical to origThunkEntryRVA
        /// </summary>
        uintptr_t BoundThunkEntryRVA;
        // RVA to the IT entry. add to module base and dereference to get its ImportThunkEntry(32/64).
        uintptr_t OrigThunkEntryRVA;
        
        bool HasName;
        // function name, if imported by name
        std::string Name;
    };

    struct ExportData
    {
        bool HasName;
        std::string Name;
        WORD BiasedOrdinal;
        /// <summary>
        /// The true index into the ExportAddressTable
        /// </summary>
        WORD UnbiasedOrdinal;
        /// <summary>
        /// The value of this symbol's entry in the ExportAddressTable. If it's not a forwarder, then add image base to get the address of the function.
        /// </summary>
        uintptr_t FunctionRVA;

        bool IsForwarder;
        bool IsForwardByOrdinal;
        std::string ForwarderModule;
        std::string ForwarderSymbolName;
        WORD ForwarderSymbolOrdinal;
    };

    struct FileMappingData
    {
        /// <summary>
        /// The result of CreateFile call, passing the DLL path.
        /// Must be cleaned up via CloseHandle.
        /// </summary>
        HANDLE hModFile;
        /// <summary>
        /// The result of CreateFileMapping call, passing the handle to the file opened with CreateFile.
        /// Must be cleaned up via CloseHandle.
        /// </summary>
        HANDLE hMappedModFile;
        /// <summary>
        /// The result of the MapViewOfFile call, passing the handle to the filemapping mapped with CreateFileMapping.
        /// Must be cleaned up via UnmapViewOfFile.
        /// </summary>
        LPVOID modFileBase;
    };

    /* === FIELDS === */
    std::string NameA;
    std::wstring NameW;
    std::string FullPathA;
    std::wstring FullPathW;

    bool HasFileMapping;
	/// <summary>
	/// Only valid if HasFileMapping is true.
	/// </summary>
	uintptr_t FileBase;
    FileMappingData FileMapping;

    bool HasOwningProcess;
    /// <summary>
    /// Only valid if HasOwningProcess is true.
    /// </summary>
    CProcess* OwningProcess;
    /// <summary>
    /// Only valid if HasOwningProcess is true.
    /// </summary>
	uintptr_t RemoteBase;

    bool HasBeenBootstrapped;
    uintptr_t BootstrapperBase;
    uint64_t BootstrapperSize;
    HANDLE BootstrapperThread;

	bool Is64bit;
    uintptr_t EntryPointRVA;
	DWORD ImgSize;
	DWORD ImgHdrSize;
	uintptr_t ImgReqBase;
	
    // TO-DO:
    // make sure pointers are cleared when ReleaseFile() is called
    // better control access to these fields, maybe separate them into a separate struct or something
    // basically, need better distinction between fields that come from the filemapping and fields that come from the remote,
    // even though sometimes they may be representing the same thing just in the different contexts
    // maybe move to a BeginModifications and EndModifications style for making changes in remote context

	/// <summary>
	/// Pointer to the NT header within the mapped file or LocalBuffer if it's a remote module
	/// </summary>
	IMAGE_NT_HEADERS32* pNtHdr32;
	/// <summary>
	/// Pointer to the NT header within the mapped file or LocalBuffer if it's a remote module
	/// </summary>
	IMAGE_NT_HEADERS64* pNtHdr64;

    std::vector<IMAGE_SECTION_HEADER*> Sections;

    uintptr_t ExportAddressTableRVA;

	/// <summary>
	/// Mapping of imported functions, with the name of the dependent module as the key
	/// </summary>
	std::map<std::string, std::vector<ImportData>> Imports;
    /// <summary>
    /// Mapping of exported functions, with the name of the function as the key
    /// </summary>
    std::vector<ExportData> Exports;

private:
    /// <summary>
    /// Working buffer set to the size of the image. Useful for reading the remote image back into local space.
    /// </summary>
    std::unique_ptr<BYTE[]> LocalBuffer;


    /* === METHODS === */
public:
    CModule();
    ~CModule();
    BOOL GetModuleBytes(BYTE** outBuffer, int numBytes = -1,  bool fromRemoteOnly = false);
    BOOL Parse();
    BOOL TryGetExportByName(std::string name, const ExportData*& outExport);
    BOOL TryGetExportByOrdinal(WORD ordinal, const ExportData*& outExport);
    void ReleaseFile();
private:
    BOOL ParseImports(BYTE* moduleBytes = NULL);
    BOOL ParseExports(BYTE* moduleBytes = NULL);

    /* === STATIC MEMBERS === */
public:
    static bool IsAPISetInitialized;
    static std::map<std::wstring, std::vector<std::wstring>> _ApiSetW;
    static std::map<std::string, std::vector<std::string>> _ApiSetA;
private:
    // paranoia (check that these are equal at program termination to make sure i'm using smart pointers properly)
    static int _NumAllocated;
    static int _NumDeallocated;
    // end paranoia
    static void InitAPISet();

public:
    static BOOL TryParseRemoteModuleByAddress(CProcess* _owningProcess, uintptr_t baseAddr, DWORD size, std::unique_ptr<CModule>* outModule);
    static BOOL TryParseModuleByFilePath(std::string& modulePath, std::unique_ptr<CModule>* outModule);
};