winhook is taken from my repo -> [Repo](https://github.com/forentfraps/winhook)

Compiling with ```.\make_dll.bat```


Current Features:
 - Hook NtQuerySystemInformation to hide the process from process list
 - Hiding the dll from loaded modules via parsing PEB (Sadly VAD tree and EPROCESS could not be altered, due to ring3 limitations)

Current TODO:
 - Hide from the explorer (will not show in the directory). Apparently explorer does not use NtQueryDirectoryFileEx to view files!
	 - hook NtQueryDirectoryFileEx
 - Hide the AppInit registry key, and the fact that AppInit is enabled at all
 - Hook opening files to read (ntdll.dll), so that when the buffer is read, altered version is received, with hooks already installed
 - Hide from windows event log - unknown how to approach this currently
