#include <windows.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
	if(argc < 2) {
		printf("Usage: %s loadme.dll [func]\n", argv[0]);
		return 0;
	}

	HMODULE hMod = LoadLibraryA(argv[1]);
	if(hMod == NULL) {
		printf("LoadLibraryA failed\n");
		return 1;
	}
	printf("Module loaded at %p\n", hMod);
	if(argv[2]) {
		printf("%s located at %p\n", argv[2], GetProcAddress(hMod, argv[2]));
	}
	printf("Press enter to exit...");
	char c;
	scanf("%c", &c);
	FreeLibrary(hMod);
}
