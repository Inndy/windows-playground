#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

#define ALIGN_TO(V, A) ((((V) + (A) - 1) / (A)) * (A))
#define ARR_LEN(ARR) sizeof(ARR) / sizeof(ARR[0])
#define DBG(X) do { if(DebugMode) { X; } } while (0);
DWORD DebugMode = 0;

SIZE_T proc_count = 0, sc_count = 0, dll_count = 0, pid_count = 0, module_unload_count = 0;
DWORD pid_list[1024] = { 0 };
LPCWSTR proc_names[1024] = { NULL };
LPCWSTR sc_files[1024] = { NULL };
LPCWSTR dll_files[1024] = { NULL };
HMODULE module_to_unload[1024] = { NULL };

DWORD find_pid(PCWSTR procname, DWORD *out_pids, DWORD cap)
{
	DWORD pid_list_snapshot[1024], pid_snapshot_count;
	memset(pid_list_snapshot, 0xff, sizeof(pid_list_snapshot));

	if(EnumProcesses(pid_list_snapshot, sizeof(pid_list_snapshot), &pid_snapshot_count) == FALSE) {
		return 0;
	}

	pid_snapshot_count /= sizeof(DWORD);

	DWORD count = 0;

	for(int i = 0; i < pid_snapshot_count; i++) {
		WCHAR modulename[260];
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid_list_snapshot[i]);

		if(!hProcess) {
			DBG(wprintf(L"[*] Found pid = %d, but can not OpenProcess\n", pid_list_snapshot[i]));
			continue;
		}

		DBG(wprintf(L"[*] Found pid = %d", pid_list_snapshot[i]));

		if(GetModuleFileNameExW(hProcess, NULL, modulename, ARR_LEN(modulename))) {
			PCWSTR p = wcsrchr(modulename, '\\');
			p = p ? p + 1 : modulename;
			DBG(wprintf(L", with module path \"%ls\" and name \"%ls\"", modulename, p));
			if(wcsicmp(p, procname) == 0) {
				out_pids[count++] = pid_list_snapshot[i];
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

int wparse_int(const wchar_t * str) {
	if(wcsncmp(str, L"0x", 2) == 0) {
		return wcstol(str + 2, 0, 16);
	} else {
		return wcstol(str, 0, 10);
	}
}

BOOL ReadFileToBuffer(LPCWSTR filename, PBYTE *outbuffer, SIZE_T *outsize)
{
	if(!outbuffer || !outsize) return FALSE;

	HANDLE hFile = CreateFileW(filename, FILE_READ_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	PBYTE buffer = NULL;

	if(hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	LARGE_INTEGER size = { 0 };

	if(!GetFileSizeEx(hFile, &size)) {
		goto failed;
	}

	if(size.QuadPart == 0) {
		*outsize = 0;
		*outbuffer = NULL;
		CloseHandle(hFile);
		return TRUE;
	}

	buffer = GlobalAlloc(GMEM_FIXED, size.QuadPart);
	LONGLONG read = 0;
	while(read < size.QuadPart) {
		DWORD curr_read = 0;
		if(ReadFile(hFile, buffer + read, size.QuadPart - read, &curr_read, NULL) == FALSE) {
			goto failed;
		}
		read += curr_read;
	}

	*outsize = size.QuadPart;
	*outbuffer = buffer;

	CloseHandle(hFile);

	return TRUE;

failed:
	CloseHandle(hFile);
	if(buffer) {
		GlobalFree(buffer);
	}

	*outbuffer = NULL;
	*outsize = 0;
	return FALSE;
}

HANDLE inject_shellcode(HANDLE hProcess, LPCWSTR sc_file)
{
	PBYTE buffer = NULL;
	SIZE_T size = 0;
	PBYTE remote_buff = NULL;
	if(ReadFileToBuffer(sc_file, &buffer, &size) == FALSE) {
		wprintf(L"[-] Can not read file %S\n", sc_file);
		goto failed;
	}

	if(size == 0) {
		wprintf(L"[-] File %S is empty\n", sc_file);
		goto failed;
	}

	remote_buff = VirtualAllocEx(hProcess, NULL, ALIGN_TO(size, 0x1000), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if(remote_buff == NULL) {
		wprintf(L"[-] VirtualAllocEx failed: %d\n", GetLastError());
		goto failed;
	}

	SIZE_T written = 0;
	if(WriteProcessMemory(hProcess, remote_buff, buffer, size, &written) == FALSE || written != size) {
		wprintf(L"[-] WriteProcessMemory failed: %d\n", GetLastError());
		goto failed;
	}

	DWORD tid;
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remote_buff, remote_buff, 0, &tid);
	DBG(wprintf(L"[*] Injected tid = %d\n", tid));
	if(hThread == NULL) {
		wprintf(L"[-] CreateRemoteThread failed: %d\n", GetLastError());
		goto failed;
	}

	GlobalFree(buffer);
	return hThread;
failed:
	if(buffer != NULL) GlobalFree(buffer);
	if(remote_buff != NULL) VirtualFreeEx(hProcess, remote_buff, 0, MEM_RELEASE);
	return NULL;
}

HANDLE inject_dll(HANDLE hProcess, LPCWSTR dll_file)
{
	PBYTE remote_buff = NULL;
	LPVOID LoadLibraryW_ptr = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
	DWORD str_size = wcslen(dll_file) * 2 + 2;

	remote_buff = VirtualAllocEx(hProcess, NULL, ALIGN_TO(str_size, 0x1000), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if(remote_buff == NULL) {
		wprintf(L"[-] VirtualAllocEx failed: %d\n", GetLastError());
		goto failed;
	}

	SIZE_T written = 0;
	if(WriteProcessMemory(hProcess, remote_buff, dll_file, str_size, &written) == FALSE || written != str_size) {
		wprintf(L"[-] WriteProcessMemory failed: %d\n", GetLastError());
		goto failed;
	}

	DWORD tid;
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryW_ptr, remote_buff, 0, &tid);
	DBG(wprintf(L"[*] Injected tid = %d\n", tid));
	if(hThread == NULL) {
		wprintf(L"[-] CreateRemoteThread failed: %d\n", GetLastError());
		goto failed;
	}

	return hThread;
failed:
	if(remote_buff != NULL) VirtualFreeEx(hProcess, remote_buff, 0, MEM_RELEASE);
	return NULL;
}

HANDLE unload_module(HANDLE hProcess, HMODULE module)
{
	LPVOID FreeLibrary_ptr = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "FreeLibrary");

	DWORD tid;
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)FreeLibrary_ptr, module, 0, &tid);
	DBG(wprintf(L"[*] Injected tid = %d\n", tid));
	if(hThread == NULL) {
		wprintf(L"[-] CreateRemoteThread failed: %d\n", GetLastError());
		goto failed;
	}

	return hThread;
failed:
	return NULL;
}

void dump_args_config()
{
	for(int i = 0; i < pid_count; i++)
		wprintf(L"[*] Manually specific pid => %d\n", pid_list[i]);
	for(int i = 0; i < sc_count; i++)
		wprintf(L"[*] Shellcode file to be injected => %S\n", sc_files[i]);
	for(int i = 0; i < dll_count; i++)
		wprintf(L"[*] DLL to be injected => %S\n", dll_files[i]);
	for(int i = 0; i < module_unload_count; i++)
		wprintf(L"[*] Module to be unload => %p\n", module_to_unload[i]);
}

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

int wmain(int argc, wchar_t *argv[])
{
	if(getenv("DEBUG")) DebugMode = 1;

	if(argc < 3) {
		wprintf(L"Usage: %S proc1.exe proc2.exe ... [options]\n", argv[0]);
		wprintf(L"  -p pid\n");
		wprintf(L"  -s shellcode.bin\n");
		wprintf(L"  -d payload.dll\n");
		wprintf(L"  -u 0xba5e0000\n");
		return 0;
	}

	if(!CheckWindowsPrivilege(SE_DEBUG_NAME)) {
		wprintf(L"[+] Auto grant debug privilege\n");
	} else {
		wprintf(L"[*] Unable to grant debug privilege\n");
	}

	for(int i = 1; i < argc; i++) {
		switch(argv[i][0]) {
			case '-':
				switch(argv[i][1]) {
					case 'p':
						if(pid_count < ARR_LEN(pid_list)) pid_list[pid_count++] = wparse_int(argv[i + 1]);
						goto skip_arg;
					case 's':
						if(sc_count < ARR_LEN(sc_files)) sc_files[sc_count++] = argv[i + 1];
						goto skip_arg;
					case 'd':
						if(dll_count < ARR_LEN(dll_files)) dll_files[dll_count++] = argv[i + 1];
						goto skip_arg;
					case 'u':
						if(module_unload_count < ARR_LEN(module_to_unload)) module_to_unload[module_unload_count++] = (HMODULE)(DWORD_PTR)wcstoll(argv[i + 1], NULL, 16);
						goto skip_arg;
					default:
						break;
skip_arg:
						i++;
				}
				break;
			default:
				proc_names[proc_count++] = argv[i];
				break;
		}
	}

	DBG(dump_args_config());

	for(int i = 0; i < proc_count; i++) {
		LPCWSTR name = proc_names[i];
		DWORD ret = find_pid(name, pid_list + pid_count, ARR_LEN(pid_list) - pid_count);
		wprintf(L"[*] Found %d processes named %S\n", ret, name);
		for(DWORD i = 0; i < ret; i++) {
			wprintf(L"[+] Found pid = %d\n", pid_list[pid_count + i]);
		}
		pid_count += ret;
	}

	for(int i = 0; i < pid_count; i++) {
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid_list[i]);
		if(hProcess == NULL) {
			wprintf(L"[-] Can not open pid = %d\n", pid_list[i]);
			continue;
		} else{
			DBG(wprintf(L"[*] Injecting pid = %d\n", pid_list[i]));
		}
		for(int j = 0; j < sc_count; j++) {
			HANDLE hThread = inject_shellcode(hProcess, sc_files[j]);
			if(hThread) {
				WaitForSingleObject(hThread, INFINITE);
				DWORD exit_code;
				if(GetExitCodeThread(hThread, &exit_code)) {
					DBG(wprintf(L"[*] Thread exit code = %d\n", exit_code));
				} else {
					DBG(wprintf(L"[-] Can not get exit code\n"));
				}
				CloseHandle(hThread);
			} else {
				DBG(wprintf(L"[-] Shellcode %S inject to pid %d failed\n", sc_files[j], pid_list[i]));
			}
		}
		for(int j = 0; j < dll_count; j++) {
			HANDLE hThread = inject_dll(hProcess, dll_files[j]);
			if(hThread) {
				WaitForSingleObject(hThread, INFINITE);
				DWORD exit_code;
				if(GetExitCodeThread(hThread, &exit_code)) {
					DBG(wprintf(L"[*] Thread exit code = %d\n", exit_code));
				} else {
					DBG(wprintf(L"[-] Can not get exit code\n"));
				}
				CloseHandle(hThread);
			} else {
				DBG(wprintf(L"[-] Dll %S inject to pid %d failed\n", dll_files[j], pid_list[i]));
			}
		}
		for(int j = 0; j < module_unload_count; j++) {
			HANDLE hThread = unload_module(hProcess, module_to_unload[j]);
			if(hThread) {
				WaitForSingleObject(hThread, INFINITE);
				DWORD exit_code;
				if(GetExitCodeThread(hThread, &exit_code)) {
					DBG(wprintf(L"[*] Thread exit code = %d\n", exit_code));
				} else {
					DBG(wprintf(L"[-] Can not get exit code\n"));
				}
				CloseHandle(hThread);
			} else {
				DBG(wprintf(L"[-] Module %p unload from pid %d failed\n", module_to_unload[j], pid_list[i]));
			}
		}
		CloseHandle(hProcess);
	}
}
