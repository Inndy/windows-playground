#include <windows.h>
#include <stdio.h>
#include <string.h>

int wmain(int argc, char *argv[])
{
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	LPCWSTR proc = L"C:\\Windows\\System32\\notepad.exe";

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));

	si.cb = sizeof(si);

	if(argc > 1) {
		proc = argv[1];
	}

	BOOL created = CreateProcessW(proc, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	if(!created) {
		printf("CreateProcessW failed\n");
		return 1;
	}

	printf("PID = %d (0x%x)\n", pi.dwProcessId, pi.dwProcessId);

	CONTEXT ctx;
	GetThreadContext(pi.hThread, &ctx);

#if defined(_AMD64_)
	printf("RSP = 0x%llx\n", ctx.Rsp);
	printf("RIP = 0x%llx\n", ctx.Rip);
#elif defined(_X86_)
	printf("ESP = 0x%x\n", ctx.Esp);
	printf("EIP = 0x%x\n", ctx.Eip);
#endif

	printf("Press enter to kill process...\n");
	while(getchar() != '\n') ;

	TerminateProcess(pi.hProcess, -1);

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
}
