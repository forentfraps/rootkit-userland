#include "rku.h"

unsigned char hide_me[] = "CalculatorApp.exe";
unsigned short whide_me[] = L"CalculatorApp.exe";

int isCalcPresent_v1(void){
    printf("Testing CreateToolhelp32Snapshot way to enumerate processes\n");
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (!strcmp(pe32.szExeFile, hide_me)){
                printf("%d %s\n", pe32.th32ProcessID, pe32.szExeFile);
                printf("We have found the CalculatorApp.exe!\n");
                return 0;
            }
        } while (Process32Next(hSnapshot, &pe32));
        printf("We have not found the CalculatorApp.exe :(\n");
        return 1;
    }
    printf("We have failed at creating a snapshot!\n");
    return 2;

}

typedef WINBOOL (*fpProcessEnum)(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
typedef NTSTATUS (NTAPI* fpNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
);

int isCalcPresent_v2(fpNtQuerySystemInformation f){
    printf("Testing NtQuerySystemInformation way to enumerate processes\n");
    ULONG len1;
    ULONG len2;
    f(SystemProcessInformation, NULL, 0, &len1);
    PSYSTEM_PROCESS_INFORMATION SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)len1);
    LPVOID freeme =(LPVOID) SystemProcInfo;
    f(SystemProcessInformation, SystemProcInfo, len1, &len2);
    int flag = 0;
    while (TRUE) {
        if (SystemProcInfo->ImageName.Length && wcscmp(SystemProcInfo->ImageName.Buffer, whide_me) == 0) {
            flag = 1;
            break;
        }
        if (!SystemProcInfo->NextEntryOffset)
            break;
        SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
    }
    HeapFree(GetProcessHeap(), 0, freeme);
    if (flag){
        printf("We have found the CalculatorApp.exe!\n");
        return 0;
    }
    printf("We have not found the CalculatorApp.exe :(\n");
    return 1;

}

int hookProcessEnum(HANDLE hSnapshot, LPPROCESSENTRY32W lppe){
    fpProcessEnum f;
    GVA(&f);
    int res = 0;
    res = f(hSnapshot, lppe);
    if (!strcmp(lppe->szExeFile, hide_me)){
        return Process32Next(hSnapshot, lppe);
    }
    return res;
}

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

int main(){
    HookInfo hFirst;
    HookInfo hNext;
    HookInfo hNtQ;
    HANDLE k32 = GetModuleHandleA("kernel32.dll");
    HANDLE nt = GetModuleHandleA("ntdll.dll");
    fpProcessEnum P32First = (fpProcessEnum)GetProcAddress(k32, "Process32First");
    fpProcessEnum P32Next = (fpProcessEnum)GetProcAddress(k32, "Process32Next");
    fpNtQuerySystemInformation pnt = (fpNtQuerySystemInformation)GetProcAddress(nt, "NtQuerySystemInformation");
    printf("Installing the hooks\n");
    InstallHook(P32First, hookProcessEnum, &hFirst);
    InstallHook(P32Next, hookProcessEnum, &hNext);
    InstallHook(pnt, hookNt, &hNtQ);
    isCalcPresent_v1();
    isCalcPresent_v2(pnt);
    printf("Removing the hooks\n");
    RemoveHook(P32First, &hFirst);
    RemoveHook(P32Next, &hNext);
    RemoveHook(pnt, &hNtQ);
    isCalcPresent_v1();
    isCalcPresent_v2(pnt);
    return 0;
}