#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#define KERNEL32       0xc9e3a311
#define NTDLL          0x1ce9cb2e
#define LOADLIBRARYEXW 0xe5f70560

#define shell __attribute__((section("shell"))) NOINLINE
#define fastshell shell

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _UNICODE_STRING32
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING32, *PUNICODE_STRING32;

typedef struct _PEB32
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG Mutant;
	ULONG ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	ULONG ProcessParameters;
	ULONG SubSystemData;
	ULONG ProcessHeap;
	ULONG FastPebLock;
	ULONG AtlThunkSListPtr;
	ULONG IFEOKey;
	ULONG CrossProcessFlags;
	ULONG UserSharedInfoPtr;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	ULONG ApiSetMap;
} PEB32, *PPEB32;

typedef struct _PEB_LDR_DATA32
{
	ULONG Length;
	BOOLEAN Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
	ULONG EntryInProgress;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;
typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union
	{
		LIST_ENTRY32 HashLinks;
		ULONG SectionPointer;
	};
	ULONG CheckSum;
	union
	{
		ULONG TimeDateStamp;
		ULONG LoadedImports;
	};
	ULONG EntryPointActivationContext;
	ULONG PatchInformation;
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;
typedef struct _PROCESS_BASIC_INFORMATION64 {
	ULONG64 ExitStatus;
	ULONG64 PebBaseAddress;
	ULONG64 AffinityMask;
	ULONG64 BasePriority;
	ULONG64 UniqueProcessId;
	ULONG64 InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION64, *PPROCESS_BASIC_INFORMATION64;
typedef struct _PEB64
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG64 Mutant;
	ULONG64 ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	ULONG64 ProcessParameters;
	ULONG64 SubSystemData;
	ULONG64 ProcessHeap;
	ULONG64 FastPebLock;
	ULONG64 AtlThunkSListPtr;
	ULONG64 IFEOKey;
	ULONG64 CrossProcessFlags;
	ULONG64 UserSharedInfoPtr;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	ULONG64 ApiSetMap;
} PEB64, *PPEB64;
typedef struct _PEB_LDR_DATA64
{
	ULONG Length;
	BOOLEAN Initialized;
	ULONG64 SsHandle;
	LIST_ENTRY64 InLoadOrderModuleList;
	LIST_ENTRY64 InMemoryOrderModuleList;
	LIST_ENTRY64 InInitializationOrderModuleList;
	ULONG64 EntryInProgress;
} PEB_LDR_DATA64, *PPEB_LDR_DATA64;
typedef struct _UNICODE_STRING64
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING64, *PUNICODE_STRING64;
typedef struct _LDR_DATA_TABLE_ENTRY64
{
	LIST_ENTRY64 InLoadOrderLinks;
	LIST_ENTRY64 InMemoryOrderModuleList;
	LIST_ENTRY64 InInitializationOrderModuleList;
	ULONG64 DllBase;
	ULONG64 EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING64 FullDllName;
	UNICODE_STRING64 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union
	{
		LIST_ENTRY64 HashLinks;
		ULONG64 SectionPointer;
	};
	ULONG CheckSum;
	union
	{
		ULONG TimeDateStamp;
		ULONG64 LoadedImports;
	};
	ULONG64 EntryPointActivationContext;
	ULONG64 PatchInformation;
} LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;

# define FORCE_INLINE __attribute__((always_inline)) inline
# define NOINLINE __declspec(noinline)

DWORD WINAPI shell loader(PWCHAR path)
{
	PVOID fastshell getFuncAddrByHash(HMODULE module, DWORD targetHash);
	PVOID fastshell getModAddrByHash(DWORD targetHash);
	DWORD register ret = ((DWORD (WINAPI*)(PWCHAR, DWORD, DWORD))getFuncAddrByHash(getModAddrByHash(KERNEL32), LOADLIBRARYEXW))(path, 0, 0);
	if(ret) ret |= 1;
	return ret;
}

DWORD fastshell modHashW(wchar_t *modName) {
	DWORD buf = 0;
	while (*(modName++)) {
		buf += (modName[0] | 0x20);
		buf = buf << 25 | buf >> 7;
	}
	return buf;
}

DWORD fastshell modHash(char *modName) {
	DWORD buf = 0;
	while (*(modName++)) {
		buf += (modName[0] | 0x20);
		buf = buf << 25 | buf >> 7;
	}
	return buf;
}

PVOID fastshell getModAddrByHash(DWORD targetHash)
{
#ifdef _WIN64
	PLIST_ENTRY header = &(((PPEB64)__readgsqword(0x60))->Ldr->InMemoryOrderModuleList);
	for (PLIST_ENTRY curr = header->Flink; curr != header; curr = curr->Flink) {
		LDR_DATA_TABLE_ENTRY64 *data = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY64, InMemoryOrderModuleList);
		if (modHashW(data->BaseDllName.Buffer) == targetHash)
			return (PVOID)data->DllBase;
	}
#else
	PLIST_ENTRY header = &(((PPEB32)__readfsdword(0x30))->Ldr->InMemoryOrderModuleList);
	for (PLIST_ENTRY curr = header->Flink; curr != header; curr = curr->Flink) {
		LDR_DATA_TABLE_ENTRY32 *data = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY32, InMemoryOrderModuleList);
		if (modHashW(data->BaseDllName.Buffer) == targetHash)
			return (PVOID)data->DllBase;
	}
#endif
	return 0;
}

PVOID fastshell getFuncAddrByHash(HMODULE module, DWORD targetHash)
{
#if defined _WIN64
	PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((LPBYTE)module + ((PIMAGE_DOS_HEADER)module)->e_lfanew);
#else
	PIMAGE_NT_HEADERS32 ntHeaders = (PIMAGE_NT_HEADERS32)((LPBYTE)module + ((PIMAGE_DOS_HEADER)module)->e_lfanew);
#endif
	PIMAGE_DATA_DIRECTORY impDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (impDir->VirtualAddress == 0) return (size_t)0;

	PIMAGE_EXPORT_DIRECTORY ied = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)module + impDir->VirtualAddress);
	if (ied->NumberOfNames == 0) return (size_t)0;

	for (DWORD i = 0; i < ied->NumberOfNames; i++)
	{
		LPDWORD curName = (LPDWORD)(((LPBYTE)module) + ied->AddressOfNames + i * sizeof(DWORD));
		if (curName && (modHash((LPSTR)((LPBYTE)module + *curName)) == targetHash))
		{
			LPWORD pw = (LPWORD)(((LPBYTE)module) + ied->AddressOfNameOrdinals + i * sizeof(WORD));
			curName = (LPDWORD)(((LPBYTE)module) + ied->AddressOfFunctions + (*pw) * sizeof(DWORD));
			return (PVOID)((size_t)module + *curName);
		}
	}
	return (size_t)0;
}

// PVOID blindFindFunc(DWORD funcNameHash)
// {
// 	PVOID retAddr = (size_t)0;
// #ifdef _WIN64
// 	PPEB64 pPEB = (PPEB64)__readgsqword(0x60);
// 	PLIST_ENTRY header = &(pPEB->Ldr->InMemoryOrderModuleList);
// 	for (PLIST_ENTRY curr = header->Flink; curr != header; curr = curr->Flink) {
// 		LDR_DATA_TABLE_ENTRY64 *data = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY64, InMemoryOrderModuleList);
// 		retAddr = getFuncAddrByHash((HMODULE)data->DllBase, funcNameHash);
// 		if (retAddr) return retAddr;
// 	}
// #else
// 	PPEB32 pPEB = (PPEB32)__readfsdword(0x30);
// 	PLIST_ENTRY header = &(pPEB->Ldr->InMemoryOrderModuleList);
// 
// 	for (PLIST_ENTRY curr = header->Flink; curr != header; curr = curr->Flink) {
// 		LDR_DATA_TABLE_ENTRY32 *data = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY32, InMemoryOrderModuleList);
// 		retAddr = getFuncAddrByHash((HMODULE)data->DllBase, funcNameHash);
// 		if (retAddr) return retAddr;
// 	}
// #endif
// 	return (size_t)0;
// }

#define getModAddr(libraryName) (HMODULE)( \
	getModAddrByHash(modHash(libraryName)) \
	)

#define getFuncAddr(libraryAddress, functionName) (PVOID)( \
	getFuncAddrByHash(libraryAddress, modHash(functionName)) \
	)

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
	printf("%p\n", loader(L"kernel32.dll"));
	printf("%p\n", GetModuleHandleA("kernel32.dll"));
	return 0;
}
