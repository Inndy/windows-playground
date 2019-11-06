#include <wchar.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <winternl.h>
#include <windows.h>

bool iat_hook(HMODULE mod, LPCSTR dllname, LPCSTR funcname, LPVOID function, LPVOID *pold)
{
	wprintf(L"iat_hook(0x%p, %S, %S, 0x%p, 0x%p)\n", mod, dllname, funcname, function, pold);
	if(!mod || IsBadReadPtr(mod, 0x1000) || strncmp((LPCSTR)mod, "MZ", 2)) {
		wprintf(L"FATAL: mod not existsed\n");
		return false;
	}

	DWORD_PTR base = (DWORD_PTR)mod;
	PIMAGE_NT_HEADERS nt_hdr = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
	DWORD imp_vaddr = nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	if(!imp_vaddr) {
		wprintf(L"ERROR: no import table found for mod 0x%p\n", mod);
		return false;
	}

	for(PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(base + imp_vaddr);
			ImportDescriptor->Name; ImportDescriptor++) {
		wprintf(L"Found dll: %S\n", (LPCSTR)(base + ImportDescriptor->Name));
		if(dllname && stricmp((LPCSTR)(base + ImportDescriptor->Name), dllname) != 0)
			continue;

		DWORD_PTR *ThunkPtr = (DWORD_PTR*)(base + ImportDescriptor->OriginalFirstThunk);
		PIMAGE_THUNK_DATA ThunkData = (PIMAGE_THUNK_DATA)(base + ImportDescriptor->FirstThunk);

		for(; *ThunkPtr && ThunkData->u1.Function; ThunkPtr++, ThunkData++) {
			if((*ThunkPtr) >> (sizeof(DWORD_PTR) * 8 - 1))
				continue; // ignore oridinal import
			PIMAGE_IMPORT_BY_NAME ImportName = (PIMAGE_IMPORT_BY_NAME)(base + *ThunkPtr);

			if(strcmp((LPCSTR)ImportName->Name, funcname) == 0) {
				LPVOID old = (LPVOID)ThunkData->u1.Function;
				if(pold) *pold = old;

				DWORD old_prot;
				if(!VirtualProtect((LPVOID)&ThunkData->u1.Function, sizeof(function), PAGE_READWRITE, &old_prot)) {
					wprintf(L"Can not unprotect memory region to write\n");
					return false;
				}
				ThunkData->u1.Function = (DWORD_PTR)function;
				VirtualProtect((LPVOID)&ThunkData->u1.Function, sizeof(function), old_prot, NULL);
				wprintf(L"Wrote new function 0x%p to 0x%p replaced old function 0x%p\n", function, &ThunkData->u1.Function, old);
				return true;
			}
		}
	}

	return false;
}

DWORD ForityTwo_GetCurrentProcessId()
{
	return 42;
}

void test()
{
	static int t = 0;
	wprintf(L"Test #%d, your process id is %d\n", ++t, GetCurrentProcessId());
}

int main()
{
	HMODULE current_mod = GetModuleHandleW(NULL);
	LPVOID old_function = NULL;

	wprintf(L"Before iat_hook:\n");
	test();

	if(!iat_hook(current_mod, NULL, "GetCurrentProcessId", ForityTwo_GetCurrentProcessId, &old_function)) {
		wprintf(L"iat_hook failed: unable to hook function\n");
		return 1;
	}

	wprintf(L"After iat_hook:\n");
	test();

	if(!iat_hook(current_mod, NULL, "GetCurrentProcessId", old_function, NULL)) {
		wprintf(L"iat_hook failed: unable to restore function\n");
		return 1;
	}

	wprintf(L"Restore iat_hook:\n");
	test();
}
