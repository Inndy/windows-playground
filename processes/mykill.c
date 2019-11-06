#include <windows.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
	DWORD pid;

	if(argc < 2) {
		printf("Usage: %s PID-to-kill\n", argv[0]);
		return 1;
	}
	sscanf(argv[1], "%d", &pid);

	HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
	if(hProc) {
		if(TerminateProcess(hProc, -1)) {
			printf("PID = %d Killed\n", pid);
		} else {
			printf("Can not kill process\n");
		}
		CloseHandle(hProc);
	} else {
		printf("Can not OpenProcess\n");
	}
}
