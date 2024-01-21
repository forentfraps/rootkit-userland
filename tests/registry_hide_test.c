#include "../rku.h"
unsigned char hide_me[] = HIDE_ME;
unsigned short shide_me[] = LHIDE_ME;

// HKEY_CURRENT_USER\SOFTWARE\Amazon\Kindle Previewer 3\ 

int test()
{
    HKEY hKey;
    LONG result;
    DWORD dataType;
    DWORD dataSize = 1024;
    unsigned char data[1024];

    // Replace with your registry key path
    const char *subKey = "SOFTWARE\\Amazon\\Kindle Previewer 3\\notepad.exe\\";

    // Replace with your registry value name
    const char *valueName = "notepad.exe";

    // Open the registry key
    result = RegOpenKeyEx(HKEY_CURRENT_USER, subKey, 0, KEY_READ, &hKey);

    if (result == ERROR_SUCCESS)
    {
        // Query the value
        result = RegQueryValueEx(hKey, valueName, NULL, &dataType, data, &dataSize);

        if (result == ERROR_SUCCESS)
        {
            printf("Value: %s\n", data);
        }
        else
        {
            printf("Failed to read the value. Error code: %ld\n", result);
        }

        // Close the registry key
        RegCloseKey(hKey);
    }
    else
    {
        printf("Failed to open the registry key. Error code: %ld\n", result);
    }

    return 0;
}

int main(){
    test();
    LoadLibraryA("../inf.dll");
    test();
}