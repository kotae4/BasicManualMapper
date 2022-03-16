#pragma once
// credit: DarthTon
// source: https://github.com/DarthTon/Blackbone

#include <Windows.h>

//
// Api schema structures
//   

//
// Win 10
//
typedef struct _API_SET_VALUE_ENTRY_10
{
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} API_SET_VALUE_ENTRY_10, * PAPI_SET_VALUE_ENTRY_10;

typedef struct _API_SET_VALUE_ARRAY_10
{
    ULONG Flags;
    ULONG NameOffset;
    ULONG Unk;
    ULONG NameLength;
    ULONG DataOffset;
    ULONG Count;

    inline PAPI_SET_VALUE_ENTRY_10 entry(void* pApiSet, DWORD i)
    {
        return (PAPI_SET_VALUE_ENTRY_10)((BYTE*)pApiSet + DataOffset + i * sizeof(API_SET_VALUE_ENTRY_10));
    }
} API_SET_VALUE_ARRAY_10, * PAPI_SET_VALUE_ARRAY_10;

typedef struct _API_SET_NAMESPACE_ENTRY_10
{
    ULONG Limit;
    ULONG Size;
} API_SET_NAMESPACE_ENTRY_10, * PAPI_SET_NAMESPACE_ENTRY_10;

typedef struct _API_SET_NAMESPACE_ARRAY_10
{
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    ULONG Start;
    ULONG End;
    ULONG Unk[2];

    inline PAPI_SET_NAMESPACE_ENTRY_10 entry(DWORD i)
    {
        return (PAPI_SET_NAMESPACE_ENTRY_10)((BYTE*)this + End + i * sizeof(API_SET_NAMESPACE_ENTRY_10));
    }

    inline PAPI_SET_VALUE_ARRAY_10 valArray(PAPI_SET_NAMESPACE_ENTRY_10 pEntry)
    {
        return (PAPI_SET_VALUE_ARRAY_10)((BYTE*)this + Start + sizeof(API_SET_VALUE_ARRAY_10) * pEntry->Size);
    }

    inline ULONG apiName(PAPI_SET_NAMESPACE_ENTRY_10 pEntry, wchar_t* output)
    {
        auto pArray = valArray(pEntry);
        memcpy(output, (char*)this + pArray->NameOffset, pArray->NameLength);
        return  pArray->NameLength;
    }
} API_SET_NAMESPACE_ARRAY_10, * PAPI_SET_NAMESPACE_ARRAY_10;