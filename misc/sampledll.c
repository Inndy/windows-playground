#include <windows.h>
#include <stdio.h>

WCHAR buff[1024];

DWORD WINAPI ThreadProc(LPVOID lParam)
{
	MessageBoxW(NULL, lParam, L"Sample DLL", MB_ICONINFORMATION | MB_SETFOREGROUND);
	return 0;
}

BOOL WINAPI DllEntryPoint(HINSTANCE hinstDLL, UINT fdwReason, LPVOID lpvReserved)
{
	switch(fdwReason) {
		case DLL_PROCESS_ATTACH:
			printf("DLLEntryPoint\n");
			swprintf(buff, sizeof(buff) / 2, L"Hello, World\r\nPID = %d", GetCurrentProcessId());
			MessageBoxW(NULL, buff, L"Sample DLL", MB_ICONINFORMATION | MB_SETFOREGROUND);
			// CreateThread(NULL, 0, ThreadProc, buff, 0, NULL);
			return FALSE;
			break;
		case DLL_PROCESS_DETACH:
			break;
		case DLL_THREAD_ATTACH:
			break;
		case DLL_THREAD_DETACH:
			break;
	}

	return TRUE;
}
