#if _WIN64 || _Win64
#define DefineSyscall(Name, Index) \
asm( \
#Name ":" \
"movq %rcx, %r10;" \
"movl $" #Index ", %eax;" \
"syscall;" \
"ret;" \
);

DefineSyscall(NtClose,                   0xf);
DefineSyscall(NtOpenProcess,             0x26);
DefineSyscall(NtReadVirtualMemory,       0x3f);
DefineSyscall(NtWriteVirtualMemory,      0x3a);
DefineSyscall(NtQueryInformationProcess, 0x19);

#ifdef NTSYSCALLAPI
#undef NTSYSCALLAPI
#define NTSYSCALLAPI
#endif
#endif

NTSYSCALLAPI NTSTATUS NTAPI
NtOpenProcess(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
);

NTSYSCALLAPI NTSTATUS NTAPI
NtClose(
	HANDLE Handle
);

NTSYSCALLAPI NTSTATUS NTAPI
NtQueryInformationProcess(
	IN HANDLE           ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID           ProcessInformation,
	IN ULONG            ProcessInformationLength,
	OUT PULONG          ReturnLength
);

NTSYSCALLAPI NTSTATUS NTAPI
NtReadVirtualMemory(
	HANDLE  ProcessHandle,
	PVOID   BaseAddress,
	PVOID   Buffer,
	SIZE_T  NumberOfBytesToRead,
	PSIZE_T NumberOfBytesRead
);

enum MEMORY_INFORMATION_CLASS { MemoryBasicInformation = 0 };
typedef enum MEMORY_INFORMATION_CLASS MEMORY_INFORMATION_CLASS;

NTSYSCALLAPI NTSTATUS NTAPI
NtQueryVirtualMemory(
	HANDLE                   ProcessHandle,
	PVOID                    BaseAddress,
	MEMORY_INFORMATION_CLASS MemoryInformationClass,
	PVOID                    MemoryInformation,
	SIZE_T                   MemoryInformationLength,
	PSIZE_T                  ReturnLength
);
