#define UNICODE
#include <wchar.h>
#include <stdio.h>
#include <stdarg.h>
#include <winternl.h>
#include <windows.h>
#include <stdbool.h>

typedef struct {
	struct _NT_TIB NtTib;
	VOID* _PADDING_[5];
	struct _PEB* ProcessEnvironmentBlock;
} MY_TEB;

bool parse_iat(HMODULE mod)
{
	if(!mod || IsBadReadPtr(mod, 0x1000) || strncmp((LPCSTR)mod, "MZ", 2)) {
		return false;
	}
	DWORD_PTR base = (DWORD_PTR)mod;
	PIMAGE_NT_HEADERS nt_hdr = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
	DWORD imp_vaddr = nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	if(!imp_vaddr) {
		wprintf(L"No import table found for mod 0x%p\n", mod);
		return false;
	}

	wprintf(L"sizeof(IMAGE_IMPORT_DESCRIPTOR) = 0x%x\n", sizeof(IMAGE_IMPORT_DESCRIPTOR));

	for(PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(base + imp_vaddr);
			ImportDescriptor->Name; ImportDescriptor++) {
		LPCSTR dllname = (LPCSTR)(base + ImportDescriptor->Name);
		wprintf(L"  * Import Entry -- %S\n", dllname);

		wprintf(L"ImportDescriptor -> 0x%p\n", ImportDescriptor);
		wprintf(L"ImportDescriptor->Name -> 0x%p\n", base + ImportDescriptor->Name);

		DWORD_PTR *ThunkPtr = (DWORD_PTR*)(base + ImportDescriptor->OriginalFirstThunk);
		PIMAGE_THUNK_DATA ThunkData = (PIMAGE_THUNK_DATA)(base + ImportDescriptor->FirstThunk);

		wprintf(L"ThunkPtr  -> 0x%p\n", ThunkPtr);
		wprintf(L"ThunkData -> 0x%p\n", ThunkData);

		for(; *ThunkPtr && ThunkData->u1.Function; ThunkPtr++, ThunkData++) {
			if((*ThunkPtr) >> (sizeof(DWORD_PTR) * 8 - 1)) {
				wprintf(L"     - 0x%p -> Oridinal(%d)\n", ThunkData->u1.Function, (*ThunkPtr) & 0x7fffffff);
			} else {
				PIMAGE_IMPORT_BY_NAME ImportName = (PIMAGE_IMPORT_BY_NAME)(base + *ThunkPtr);
				wprintf(L"     - 0x%p -> %S\n", ThunkData->u1.Function, ImportName->Name);
			}
		}
	}

	return true;
}

void start()
{
	LIST_ENTRY *head = &((MY_TEB *)NtCurrentTeb())->ProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList,
			   *curr = head->Flink;
	do {
		LDR_DATA_TABLE_ENTRY *entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		wprintf(L"+ Found module %p, %p, %s\n", entry, entry->DllBase, entry->FullDllName.Buffer);
		bool ret = parse_iat(entry->DllBase);
		if(!ret) {
			wprintf(L"- Can not parse IAT for %s\n", entry->FullDllName.Buffer);
		}
	} while ((curr = curr->Flink) != head);
}
