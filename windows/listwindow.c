#include <windows.h>
#include <stdio.h>

char buff[1024] = { 0 };

void dump_windows(HANDLE parent, int depth)
{
	HANDLE hWnd = NULL;

	goto seek_first;
	while(hWnd != NULL) {
		DWORD pid = -1;
		GetWindowThreadProcessId(hWnd, &pid);
		printf("[%d] Found a window 0x%llx under pid %d", depth, (ULONG64)(DWORD_PTR)hWnd, pid);

		if(GetWindowTextA(hWnd, buff, sizeof(buff)))
			printf(" with text: %s\n", buff);
		else
			printf(" without text\n");

		dump_windows(hWnd, depth + 1);
seek_first:
		hWnd = FindWindowExA(parent, hWnd, NULL, NULL);
	}
}

int main()
{
	dump_windows(NULL, 0);
}
