#include <stdio.h>
#include <windows.h>
#include "hexdump.h"

DWORD_PTR parse_number(const char *s)
{
	int base = 10;
	if(strncmp("0x", s, 2) == 0) {
		base = 16;
	}

	return strtoll(s, NULL, base);
}

int main(int argc, char *argv[])
{
	if(argc < 4) {
		printf("Usage: %s pid address size\n", argv[0]);
		return 0;
	}

	int exit_code = 0;
	char *buff = NULL;

	DWORD pid = parse_number(argv[1]);
	DWORD_PTR addr = parse_number(argv[2]);
	DWORD size = parse_number(argv[3]);

	printf("[*] Trying open pid %d\n", pid);
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
	if(hProcess == NULL) {
		puts("OpenProcess failed");
		return 1;
	}

	buff = malloc(size);
	if(buff == NULL) {
		puts("malloc failed");
		return 1;
	}

	SIZE_T read_size = 0;
	DWORD ret_rpm = ReadProcessMemory(hProcess, (LPCVOID)addr, buff, (SIZE_T)size, &read_size);

	if(ret_rpm == FALSE) {
		puts("ReadProcessMemory failed");
		exit_code = 1;
		goto cleanup;
	}

	printf("[*] %d bytes required, but %lld bytes actually read\n", size, (UINT64)read_size);
	hexdump((LPCBYTE)buff, read_size, addr);

cleanup:
	CloseHandle(hProcess);
	free(buff);
	return exit_code;
}
