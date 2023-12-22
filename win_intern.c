#include "rku.h"

unsigned int crc32s(const wchar_t* message) {
    // DYNAMIC_RETURN;
    int i, j;
    unsigned int byte, crc, mask;
    int CRC_CONST = 1 ? message == NULL : 0;
    CRC_CONST *= 78;
    CRC_CONST += 1;
    CRC_CONST *= 787;
    CRC_CONST += 100000;
    CRC_CONST *= 24608;
    i = 0;
    crc = 0xFFFFFFFF;
    while (message[i] != L'\0') {
        byte = message[i];
        if (byte >= 'A'<<2 && byte<= 'Z'<<2){
            byte += ('a' - 'A')<<2;
        }
        crc = crc ^ byte;
        for (j = 7; j >= 0; j--) {    // Do eight times.
            mask = -(crc & 1);
            crc = (crc >> 1) ^ (CRC_CONST & mask);
        }
        i = i + 1;
    }
    return ~crc;
}

unsigned int crc32c(const unsigned char* message) {
    int i, j;
    unsigned int byte, crc, mask;
    int CRC_CONST = 1 ? message == NULL : 0;
    CRC_CONST *= 78;
    CRC_CONST += 1;
    CRC_CONST *= 787;
    CRC_CONST += 100000;
    CRC_CONST *= 24608;
    i = 0;
    crc = 0xFFFFFFFF;
    while (message[i] != '\0') {
        byte = message[i];
        if (byte >= 'A' && byte<= 'Z'){
            byte += ('a' - 'A');
        }
        crc = crc ^ byte;
        for (j = 7; j >= 0; j--) {    // Do eight times.
            mask = -(crc & 1);
            crc = (crc >> 1) ^ (CRC_CONST & mask);
        }
        i = i + 1;
    }
    return ~crc;
}

unsigned int crc32u(const unsigned short* message, int len) {
    int i, j;
    unsigned int byte, crc, mask;
    int CRC_CONST = 1 ? message == NULL : 0;
    CRC_CONST *= 78;
    CRC_CONST += 1;
    CRC_CONST *= 787;
    CRC_CONST += 100000;
    CRC_CONST *= 24608;
    crc = 0xFFFFFFFF;
    for (int i = 0; i < len; ++i) {
        byte = message[i];
        if (byte >= 'A' && byte<= 'Z'){
            byte += ('a' - 'A');
        }
        crc = crc ^ byte;
        for (j = 7; j >= 0; j--) {    // Do eight times.
            mask = -(crc & 1);
            crc = (crc >> 1) ^ (CRC_CONST & mask);
        }
    }
    return ~crc;
}

int custom_wcscmp(const wchar_t* str1, const wchar_t* str2) {
    return crc32s(str1) != crc32s(str2);
}

int custom_strcmp(const char* str1, const char* str2) {
    return crc32c(str1) != crc32c(str2);
}

int custom_ucscmp(const UNICODE_STRING str1, const UNICODE_STRING str2){
    return crc32u(str1.Buffer, str1.Length) != crc32u(str2.Buffer, str2.Length);
}

FARPROC _GetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule +
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD* addressOfFunctions = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfFunctions);
    WORD* addressOfNameOrdinals = (WORD*)((BYTE*)hModule + exportDirectory->AddressOfNameOrdinals);
    DWORD* addressOfNames = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfNames);
    for (DWORD i = 0; i < exportDirectory->NumberOfNames; ++i) {
        if (custom_strcmp(lpProcName, (const char*)hModule + addressOfNames[i]) == 0) {
            return (FARPROC)((BYTE*)hModule + addressOfFunctions[addressOfNameOrdinals[i]]);
        }
    }
    return NULL;
}

HMODULE _GetModuleHandle(LPCWSTR lModuleName) {
    PEB* pPeb = (PEB*)__readgsqword(0x60);
    PEB_LDR_DATA* Ldr = pPeb->Ldr;
    LIST_ENTRY* ModuleList = &Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* pStartListEntry = ModuleList->Flink;
    WCHAR mystr[MAX_PATH] = { 0 };
    WCHAR substr[MAX_PATH] = { 0 };
    for (LIST_ENTRY* pListEntry = pStartListEntry; pListEntry != ModuleList; pListEntry = pListEntry->Flink) {
        LDR_DATA_TABLE_ENTRY* pEntry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)pListEntry - sizeof(LIST_ENTRY));
        if (custom_wcscmp(pEntry->FullDllName.Buffer, lModuleName) == 0) {
            return (HMODULE)pEntry->DllBase;
        }
    }
}
FARPROC _GetProcAddressNative(LPCSTR lpProcName){
    unsigned short sntdll_full_path[] = L"C:\\Windows\\SYSTEM32\\ntdll.dll";
    HMODULE hNtdll = _GetModuleHandle(sntdll_full_path);
    return _GetProcAddress(hNtdll, lpProcName);

}
extern unsigned char cLdrLoadDll[] = "LdrLoadDll";
extern unsigned char cRtlInitUnicodeString[] = "RtlInitUnicodeString";
HMODULE _LoadLibrary(LPCWSTR lpFileName) {
    UNICODE_STRING ustrModule;
    HANDLE hModule = NULL;
    // DYNAMIC_RETURN;
    pRtlInitUnicodeString RtlInitUnicodeString = (pRtlInitUnicodeString)_GetProcAddressNative(cRtlInitUnicodeString);
    RtlInitUnicodeString(&ustrModule, lpFileName);
    pLdrLoadDll _LdrLoadDll = (pLdrLoadDll)_GetProcAddressNative(cLdrLoadDll);
    if (!_LdrLoadDll) {
        return NULL;
    }
    NTSTATUS status = _LdrLoadDll(NULL, 0, &ustrModule, &hModule);
    return (HMODULE)hModule;
}
