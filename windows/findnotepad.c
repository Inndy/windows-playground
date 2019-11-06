#include <windows.h>
#include <stdio.h>

int main()
{
	HANDLE hWnd = FindWindowW(L"Notepad", NULL);
	if(hWnd) {
		char buff[1024] = { 0 };
		GetWindowTextA(hWnd, buff, sizeof(buff));
		printf("Found a notepad window: %s\n", buff);
	} else {
		printf("Notepad not found\n");
		return 1;
	}

	DWORD pid = 0;
	GetWindowThreadProcessId(hWnd, &pid);
	printf("Notepad PID = %d (0x%x)\n", pid, pid);

	printf("Would you like to close it? (y/N)");
	char x = 'N';
	scanf("%c", &x);
	if(x == 'Y' || x == 'y') {
		SendMessage(hWnd, WM_CLOSE, 0, 0);
	}
}
