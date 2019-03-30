#include <windows.h>
#include <stdio.h>

BOOL DoHook(LPVOID source, LPVOID target)
{
	if(source == NULL) {
		return FALSE;
	}
    BYTE buff[5];
    buff[0] = 0xe9;
    *(DWORD*)(buff + 1) = (intptr_t)target - (intptr_t)source - 5;
    return WriteProcessMemory(GetCurrentProcess(), source, buff, 5, NULL);
}

void shexdump(BYTE *data, size_t s, char *out)
{
    for(size_t i = 0; i < s; i++) {
        sprintf(out + i * 2, "%.2x", data[i]);
    }
}

void fhexdump(BYTE *data, size_t s, FILE *fp)
{
    for(size_t i = 0; i < s; i++) {
        fprintf(fp, "%.2x", data[i]);
    }
    fprintf(fp, "\n");
}

void hexdump(BYTE *data, size_t s)
{
    for(size_t i = 0; i < s; i++) {
        printf("%.2x", data[i]);
    }
    putchar('\n');
}

void dump(int dummy)
{
    char filebuff[260];
    memset(filebuff, 0, sizeof(filebuff));
    GetModuleFileNameA(NULL, filebuff, sizeof(filebuff));

	char buff[1024];
	sprintf(buff, "Hello from %s\r\n", filebuff);

	MessageBoxA(NULL, buff, "Message", MB_ICONINFORMATION | MB_SETFOREGROUND);

    ExitProcess(0);
}

DWORD WINAPI hook(LPVOID param)
{
    HMODULE kernel32 = LoadLibraryW(L"kernel32.dll");
    if(kernel32 == NULL) {
        MessageBoxA(NULL, "Can not load kernel32.dll", "Error", MB_ICONERROR | MB_SETFOREGROUND);
        ExitProcess(1);
    }

    if(!DoHook(GetProcAddress(kernel32, "CreateProcessW"), dump)) {
        MessageBoxA(NULL, "Can not setup hook", "Error", MB_ICONERROR | MB_SETFOREGROUND);
        ExitProcess(1);
    }

    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if(fdwReason == DLL_PROCESS_ATTACH) {
        // hook(hinstDLL);
        HANDLE hThread = CreateThread(NULL, 0x2000, hook, hinstDLL, 0, NULL); Sleep(100);
		if(hThread) {
			WaitForSingleObject(hThread, 1000);
		} else {
			return FALSE;
		}
    }
    return TRUE;
}
