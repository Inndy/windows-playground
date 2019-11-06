#include <windows.h>
#include <psapi.h>
#include <stdio.h>

LPCWSTR check_integrity_level(HANDLE hProcess)
{
	HANDLE hToken;
    if(OpenProcessToken(hProcess, TOKEN_QUERY, &hToken) == FALSE)
		return L"?";

	DWORD dwIntgtyLvl, dwSizeIntgtyLvl = 0;
	if(!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, dwSizeIntgtyLvl, &dwSizeIntgtyLvl) &&
			GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		BYTE* pbIntgtyLvl = alloca(dwSizeIntgtyLvl);
		if(pbIntgtyLvl)
		{
			TOKEN_MANDATORY_LABEL* pTML = (TOKEN_MANDATORY_LABEL*)pbIntgtyLvl;
			DWORD dwSizeIntgtyLvl2;
			if(GetTokenInformation(hToken, TokenIntegrityLevel, pTML, dwSizeIntgtyLvl, &dwSizeIntgtyLvl2) &&
					dwSizeIntgtyLvl2 <= dwSizeIntgtyLvl)
			{
				dwIntgtyLvl = *GetSidSubAuthority(pTML->Label.Sid,
						(DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTML->Label.Sid) - 1));
			}
		}
	}

	CloseHandle(hToken);

	switch(dwIntgtyLvl) {
		case SECURITY_MANDATORY_UNTRUSTED_RID: return L"UNTRUSTED";
		case SECURITY_MANDATORY_LOW_RID: return L"LOW";
		case SECURITY_MANDATORY_MEDIUM_RID: return L"MEDIUM";
		case SECURITY_MANDATORY_MEDIUM_RID + 0x100 /*SECURITY_MANDATORY_MEDIUM_PLUS_RID*/: return L"MEDIUM+";
		case SECURITY_MANDATORY_HIGH_RID: return L"HIGH";
		case SECURITY_MANDATORY_SYSTEM_RID: return L"SYSTEM";
		case 0x00005000 /*SECURITY_MANDATORY_PROTECTED_RID*/: return L"PROTECTED";
	}

	static WCHAR buff[64];
	snwprintf(buff, sizeof(buff), L"%.8xh", dwIntgtyLvl);
	return buff;
}

void check_pid(DWORD pid)
{
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if(hProcess == NULL) return;

	LPCWSTR integrity_level = check_integrity_level(hProcess);

	WCHAR path[MAX_PATH];
	if(GetModuleFileNameExW(hProcess, NULL, path, MAX_PATH) == 0) goto failed;

	wprintf(L" 0x%.4x (%-5d) | %-9s | %s\n", pid, pid, integrity_level, path);

failed:
	CloseHandle(hProcess);
}

int main()
{
	DWORD pid_list[4096], pid_count = 0;

	wprintf(L" Process ID       IL          Process Image Path\n");
	wprintf(L"---------------- ----------- --------------------------------------\n");

	if(EnumProcesses(pid_list, sizeof(pid_list), &pid_count) == FALSE) {
		printf("Can not list processes id, use bruteforce method\n");
		for(DWORD pid = 0; pid < 65536; pid += 4) {
			check_pid(pid);
		}
	} else {
		for(DWORD i = 0; i < pid_count / sizeof(DWORD); i++) {
			check_pid(pid_list[i]);
		}
	}
}
