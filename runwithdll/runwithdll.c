#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <wchar.h>
#include <assert.h>
#include "shellcode.h"

WCHAR wcmdline[4096];
PWCHAR wcmdlinep = wcmdline;

void wcmdlinecat(WCHAR c)
{
	if(c == '\\' || c == '"') {
		assert(wcmdlinep < wcmdline + sizeof(wcmdline) - 1);
		*wcmdlinep++ = '\\';
	}
	assert(wcmdlinep < wcmdline + sizeof(wcmdline) - 1);
	*wcmdlinep++ = c;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
	int argc;
	WCHAR **argvw = CommandLineToArgvW(GetCommandLineW(), &argc);

	if(argc < 3) {
		wprintf(L"Usage: %s hook.dll victim.exe\n", argvw[0]);
		return 1;
	}

	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));

	si.cb = sizeof(si);

	for(int i = 2; i < argc; i++) {
		if(i > 2) {
			wcmdlinecat(' ');
		}
		for(int j = 0; argvw[i][j]; j++) {
			wcmdlinecat(argvw[i][j]);
		}
	}

	if(CreateProcessW(argvw[2], wcmdline, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi) == 0) {
		printf("Can not CreateProcess\n");
		return 1;
	}

	LPVOID shellcode_ptr = VirtualAllocEx(pi.hProcess, 0, 0x4000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if(!shellcode_ptr) {
		printf("Can not VirtualAllocEx\n");
		goto failed;
	}

	if(!WriteProcessMemory(pi.hProcess, shellcode_ptr, shellcode, sizeof(shellcode), NULL)) {
		printf("Can not WriteProcessMemory\n");
		goto failed;
	}

	if(!WriteProcessMemory(pi.hProcess, ((PBYTE)shellcode_ptr) + sizeof(shellcode), argvw[1], 260 * 2 + 2, NULL)) {
		printf("Can not WriteProcessMemory (2)\n");
		goto failed;
	}

//	printf("Shellcode size = %d\n", sizeof(shellcode));
//	printf("Child pid = %d (0x%x)\n", pi.dwProcessId, pi.dwProcessId);
//	printf("Hook at %p\n", shellcode_ptr);
//	getchar();

	HANDLE shellcodeThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)shellcode_ptr, ((PBYTE)shellcode_ptr) + sizeof(shellcode), 0, NULL);
	if(shellcodeThread == NULL) {
		printf("Can not CreateRemoteThread\n");
		goto failed;
	}
	printf("Wait for shellcode...\n");
	WaitForSingleObject(shellcodeThread, INFINITE);

	DWORD threadExitCode;
	if(GetExitCodeThread(shellcodeThread, &threadExitCode) == FALSE) {
		printf("Can not get thread exit code\n");
		goto failed;
	}

	CloseHandle(shellcodeThread);

	printf("Shellcode exit code (HMODULE in 32bit) = %p\n", (LPVOID)threadExitCode);

	if(VirtualFreeEx(pi.hProcess, shellcode_ptr, 0, MEM_RELEASE) == FALSE) {
		printf("VirtualFreeEx failed\n");
		goto failed;
	}

	if(threadExitCode == 0) {
		printf("Can not load dll\n");
		goto failed;
	}

	printf("ResumeThread...\n");
	ResumeThread(pi.hThread);
	printf("Wait for process...\n");
	WaitForSingleObject(pi.hProcess, INFINITE);

	return 0;

failed:
	TerminateProcess(pi.hProcess, 0);
	return 1;
}
