#include <windows.h>
#include <stdio.h>

#define SIZE 0x10000

#ifdef _WIN64
#define ADDR 0x0000400000000000
#else
#define ADDR 0x40000000
#endif

int main(int argc, char *argv[])
{
	const char *filename = argv[1];
	if(filename == NULL)
		filename = "shellcode.bin";

	FARPROC sc = (FARPROC)VirtualAlloc((LPVOID)ADDR, SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if(sc == NULL) {
		printf("VirtualAlloc failed\n");
		return 1;
	}

	FILE *fp = fopen(filename, "rb");
	if(fp == NULL) {
		printf("Can not open file %s\n", filename);
		return 1;
	}
	fread(sc, 1, SIZE, fp);
	fclose(fp);

	printf("Excute shellcode now!\n");
	Sleep(1); // break on Sleep
	sc();
	printf("Shellcode returned!\n");
	if(VirtualFree(sc, 0, MEM_RELEASE) == FALSE) {
		printf("VirtualFree failed, but who cares?\n");
		return 1;
	} else {
		printf("VirtualFree succeed\n");
	}
}
