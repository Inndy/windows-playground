#include <stdio.h>
#include <windows.h>
#include "hexdump.h"

volatile char data[1024] = "Hello, World...\0\xAB\xCD\xEF\x12\x34\x56\x78\x90";

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
	DWORD pid = GetCurrentProcessId();
	printf("My pid is %d (0x%x)\n", pid, pid);
	printf("Read data at 0x%llx\n", (UINT64)(DWORD_PTR)&data);

	while(1) {
		printf("[%10u] data -> %s\n", GetTickCount(), data);
		Sleep(1000);
	}
}
