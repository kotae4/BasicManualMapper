#pragma once
// credit: DarthTon
// source: https://github.com/DarthTon/Blackbone

#include <Windows.h>

template <int n>
using const_int = std::integral_constant<int, n>;

template<typename T>
constexpr bool is32bit = std::is_same_v<T, uint32_t>;

template<typename T, typename T32, typename T64>
using type_32_64 = std::conditional_t<is32bit<T>, T32, T64>;

template<typename T, int v32, int v64>
constexpr int int_32_64 = std::conditional_t<is32bit<T>, const_int<v32>, const_int<v64>>::value;

// nonstandard extension used : nameless struct/union
#pragma warning(disable : 4201)

template <typename T>
struct _LIST_ENTRY_T
{
    T Flink;
    T Blink;
};

template <typename T>
struct _UNICODE_STRING_T
{
    using type = T;

    uint16_t Length;
    uint16_t MaximumLength;
    T Buffer;
};

template <typename T>
struct _NT_TIB_T
{
    T ExceptionList;
    T StackBase;
    T StackLimit;
    T SubSystemTib;
    T FiberData;
    T ArbitraryUserPointer;
    T Self;
};

template <typename T>
struct _CLIENT_ID_T
{
    T UniqueProcess;
    T UniqueThread;
};

template <typename T>
struct _GDI_TEB_BATCH_T
{
    uint32_t Offset;
    T HDC;
    uint32_t Buffer[310];
};

template <typename T>
struct _ACTIVATION_CONTEXT_STACK_T
{
    T ActiveFrame;
    _LIST_ENTRY_T<T> FrameListCache;
    uint32_t Flags;
    uint32_t NextCookieSequenceNumber;
    uint32_t StackId;
};

template <typename T>
struct _TEB_T
{
    struct Specific32_1
    {
        uint8_t InstrumentationCallbackDisabled;
        uint8_t SpareBytes[23];
        uint32_t TxFsContext;
    };

    struct Specific64_1
    {
        uint32_t TxFsContext;
        uint32_t InstrumentationCallbackDisabled;
    };

    struct Specific64_2
    {
        T TlsExpansionSlots;
        T DeallocationBStore;
        T BStoreLimit;
    };

    struct Specific32_2
    {
        T TlsExpansionSlots;
    };

    _NT_TIB_T<T> NtTib;
    T EnvironmentPointer;
    _CLIENT_ID_T<T> ClientId;
    T ActiveRpcHandle;
    T ThreadLocalStoragePointer;
    T ProcessEnvironmentBlock;
    uint32_t LastErrorValue;
    uint32_t CountOfOwnedCriticalSections;
    T CsrClientThread;
    T Win32ThreadInfo;
    uint32_t User32Reserved[26];
    uint32_t UserReserved[5];
    T WOW32Reserved;
    uint32_t CurrentLocale;
    uint32_t FpSoftwareStatusRegister;
    T ReservedForDebuggerInstrumentation[16];
    T SystemReserved1[int_32_64<T, 26, 30>];
    uint8_t PlaceholderCompatibilityMode;
    uint8_t PlaceholderReserved[11];
    uint32_t ProxiedProcessId;
    _ACTIVATION_CONTEXT_STACK_T<T> ActivationStack;
    uint8_t WorkingOnBehalfTicket[8];
    uint32_t ExceptionCode;
    T ActivationContextStackPointer;
    T InstrumentationCallbackSp;
    T InstrumentationCallbackPreviousPc;
    T InstrumentationCallbackPreviousSp;
    type_32_64<T, Specific32_1, Specific64_1> spec1;
    _GDI_TEB_BATCH_T<T> GdiTebBatch;
    _CLIENT_ID_T<T> RealClientId;
    T GdiCachedProcessHandle;
    uint32_t GdiClientPID;
    uint32_t GdiClientTID;
    T GdiThreadLocalInfo;
    T Win32ClientInfo[62];
    T glDispatchTable[233];
    T glReserved1[29];
    T glReserved2;
    T glSectionInfo;
    T glSection;
    T glTable;
    T glCurrentRC;
    T glContext;
    uint32_t LastStatusValue;
    _UNICODE_STRING_T<T> StaticUnicodeString;
    wchar_t StaticUnicodeBuffer[261];
    T DeallocationStack;
    T TlsSlots[64];
    _LIST_ENTRY_T<T> TlsLinks;
    T Vdm;
    T ReservedForNtRpc;
    T DbgSsReserved[2];
    uint32_t HardErrorMode;
    T Instrumentation[int_32_64<T, 9, 11>];
    GUID ActivityId;
    T SubProcessTag;
    T PerflibData;
    T EtwTraceData;
    T WinSockData;
    uint32_t GdiBatchCount;             // TEB64 pointer
    uint32_t IdealProcessorValue;
    uint32_t GuaranteedStackBytes;
    T ReservedForPerf;
    T ReservedForOle;
    uint32_t WaitingOnLoaderLock;
    T SavedPriorityState;
    T ReservedForCodeCoverage;
    T ThreadPoolData;
    type_32_64<T, Specific32_2, Specific64_2> spec2;
    uint32_t MuiGeneration;
    uint32_t IsImpersonating;
    T NlsCache;
    T pShimData;
    uint16_t HeapVirtualAffinity;
    uint16_t LowFragHeapDataSlot;
    T CurrentTransactionHandle;
    T ActiveFrame;
    T FlsData;
    T PreferredLanguages;
    T UserPrefLanguages;
    T MergedPrefLanguages;
    uint32_t MuiImpersonation;
    uint16_t CrossTebFlags;
    union
    {
        uint16_t SameTebFlags;
        struct
        {
            uint16_t SafeThunkCall : 1;
            uint16_t InDebugPrint : 1;
            uint16_t HasFiberData : 1;
            uint16_t SkipThreadAttach : 1;
            uint16_t WerInShipAssertCode : 1;
            uint16_t RanProcessInit : 1;
            uint16_t ClonedThread : 1;
            uint16_t SuppressDebugMsg : 1;
            uint16_t DisableUserStackWalk : 1;
            uint16_t RtlExceptionAttached : 1;
            uint16_t InitialThread : 1;
            uint16_t SessionAware : 1;
            uint16_t LoadOwner : 1;
            uint16_t LoaderWorker : 1;
            uint16_t SkipLoaderInit : 1;
            uint16_t SpareSameTebBits : 1;
        };
    };
    T TxnScopeEnterCallback;
    T TxnScopeExitCallback;
    T TxnScopeContext;
    uint32_t LockCount;
    uint32_t WowTebOffset;
    T ResourceRetValue;
    T ReservedForWdf;
    uint64_t ReservedForCrt;
    GUID EffectiveContainerId;
};

template<typename T>
struct _PEB_T
{
    static_assert(std::is_same_v<T, uint32_t> || std::is_same_v<T, uint64_t>, "T must be uint32_t or uint64_t");

    uint8_t InheritedAddressSpace;
    uint8_t ReadImageFileExecOptions;
    uint8_t BeingDebugged;
    union
    {
        uint8_t BitField;
        struct
        {
            uint8_t ImageUsesLargePages : 1;
            uint8_t IsProtectedProcess : 1;
            uint8_t IsImageDynamicallyRelocated : 1;
            uint8_t SkipPatchingUser32Forwarders : 1;
            uint8_t IsPackagedProcess : 1;
            uint8_t IsAppContainer : 1;
            uint8_t IsProtectedProcessLight : 1;
            uint8_t SpareBits : 1;
        };
    };
    T Mutant;
    T ImageBaseAddress;
    T Ldr;
    T ProcessParameters;
    T SubSystemData;
    T ProcessHeap;
    T FastPebLock;
    T AtlThunkSListPtr;
    T IFEOKey;
    union
    {
        T CrossProcessFlags;
        struct
        {
            uint32_t ProcessInJob : 1;
            uint32_t ProcessInitializing : 1;
            uint32_t ProcessUsingVEH : 1;
            uint32_t ProcessUsingVCH : 1;
            uint32_t ProcessUsingFTH : 1;
            uint32_t ReservedBits0 : 27;
        };
    };
    union
    {
        T KernelCallbackTable;
        T UserSharedInfoPtr;
    };
    uint32_t SystemReserved;
    uint32_t AtlThunkSListPtr32;
    T ApiSetMap;
    union
    {
        uint32_t TlsExpansionCounter;
        T Padding2;
    };
    T TlsBitmap;
    uint32_t TlsBitmapBits[2];
    T ReadOnlySharedMemoryBase;
    T SparePvoid0;
    T ReadOnlyStaticServerData;
    T AnsiCodePageData;
    T OemCodePageData;
    T UnicodeCaseTableData;
    uint32_t NumberOfProcessors;
    uint32_t NtGlobalFlag;
    LARGE_INTEGER CriticalSectionTimeout;
    T HeapSegmentReserve;
    T HeapSegmentCommit;
    T HeapDeCommitTotalFreeThreshold;
    T HeapDeCommitFreeBlockThreshold;
    uint32_t NumberOfHeaps;
    uint32_t MaximumNumberOfHeaps;
    T ProcessHeaps;
    T GdiSharedHandleTable;
    T ProcessStarterHelper;
    union
    {
        uint32_t GdiDCAttributeList;
        T Padding3;
    };
    T LoaderLock;
    uint32_t OSMajorVersion;
    uint32_t OSMinorVersion;
    uint16_t OSBuildNumber;
    uint16_t OSCSDVersion;
    uint32_t OSPlatformId;
    uint32_t ImageSubsystem;
    uint32_t ImageSubsystemMajorVersion;
    union
    {
        uint32_t ImageSubsystemMinorVersion;
        T Padding4;
    };
    T ActiveProcessAffinityMask;
    uint32_t GdiHandleBuffer[int_32_64<T, 34, 60>];
    T PostProcessInitRoutine;
    T TlsExpansionBitmap;
    uint32_t TlsExpansionBitmapBits[32];
    union
    {
        uint32_t SessionId;
        T Padding5;
    };
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    T pShimData;
    T AppCompatInfo;
    _UNICODE_STRING_T<T> CSDVersion;
    T ActivationContextData;
    T ProcessAssemblyStorageMap;
    T SystemDefaultActivationContextData;
    T SystemAssemblyStorageMap;
    T MinimumStackCommit;
    T FlsCallback;
    _LIST_ENTRY_T<T> FlsListHead;
    T FlsBitmap;
    uint32_t FlsBitmapBits[4];
    uint32_t FlsHighIndex;
    T WerRegistrationData;
    T WerShipAssertPtr;
    T pUnused;
    T pImageHeaderHash;
    union
    {
        uint64_t TracingFlags;
        struct
        {
            uint32_t HeapTracingEnabled : 1;
            uint32_t CritSecTracingEnabled : 1;
            uint32_t LibLoaderTracingEnabled : 1;
            uint32_t SpareTracingBits : 29;
        };
    };
    T CsrServerReadOnlySharedMemoryBase;
};

using _UNICODE_STRING32 = _UNICODE_STRING_T<uint32_t>;
using _UNICODE_STRING64 = _UNICODE_STRING_T<uint64_t>;
using UNICODE_STRING_T = _UNICODE_STRING_T<uintptr_t>;

using _PEB32 = _PEB_T<uint32_t>;
using _PEB64 = _PEB_T<uint64_t>;
using PEB_T = _PEB_T<uintptr_t>;

using _TEB32 = _TEB_T<uint32_t>;
using _TEB64 = _TEB_T<uint64_t>;
using TEB_T = _TEB_T<uintptr_t>;