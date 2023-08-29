#include <stdio.h>
#include <stdlib.h>
#include <winternl.h>
#include <windows.h>
#include "../include/peb.h"
#include "../include/hexdump.h"
#include "../include/syscall.h"
#include "../include/string.h"

#ifndef NT_ERROR
#define NT_ERROR(X) (!NT_SUCCESS(X))
#endif

PUNICODE_STRING ReadRemoteUnicodeString(HANDLE hProcess, PUNICODE_STRING remote_us)
{
	static UNICODE_STRING local_us;
	static SIZE_T maxlen = 0;
	static PWSTR buff = NULL;
	SIZE_T read;
	NTSTATUS ret;

	if(remote_us->Length == 0) {
		local_us = (UNICODE_STRING){ .Length = 0, .MaximumLength = 0, .Buffer = NULL };
		return &local_us;
	}

	if(buff == NULL || maxlen < remote_us->MaximumLength) {
		buff = realloc(buff, remote_us->MaximumLength * 2);
		maxlen = remote_us->MaximumLength;
	}

	ret = NtReadVirtualMemory(hProcess, (PVOID)remote_us->Buffer, buff, maxlen * 2, &read);
	if(NT_ERROR(ret) || read != maxlen * 2) {
		printf("NtReadVirtualMemory failed\n");
		return NULL;
	}

	local_us = *remote_us;
	local_us.Buffer = buff;

	return &local_us;
}

DWORD_PTR DumpRegionInfo(HANDLE hProcess, DWORD_PTR addr)
{
	MEMORY_BASIC_INFORMATION info;
	SIZE_T ret_len = 0;

	memset(&info, 0, sizeof(info));

	NTSTATUS ret = NtQueryVirtualMemory(hProcess, (PVOID)addr, MemoryBasicInformation, &info, sizeof(info), &ret_len);
	if(NT_ERROR(ret)) {
		printf("NtQueryVirtualMemory failed\n");
		return -1;
	}

	if((info.State & MEM_FREE) != MEM_FREE) {
		printf("%p %p %.8x %p %.8x %.8x %.8x\n", info.BaseAddress, info.AllocationBase, info.AllocationProtect, info.RegionSize, info.State, info.Protect, info.Type);
	}
	return info.RegionSize;
}

void usage(char *argv[]) {
	printf("Usage: %s [-r] [-v] pid\n", argv[0]);
	printf("    -r  Dump memory region info\n");
	printf("    -v  Verbose mode, include hexdump\n");
}

int main(int argc, char *argv[])
{
	if(argc < 2) {
		usage(argv);
		return 0;
	}

	int dump_regions = 0, verbose_dump = 0;
	char *pid_str = NULL;

	for (int i = 1; i < argc; i++) {
		switch (argv[i][0]) {
			case '-':
				switch (argv[i][1]) {
					case 'r':
						dump_regions = 1;
						break;
					case 'v':
						verbose_dump = 1;
						break;
					default:
						printf("Unknown option: %s\n", argv[i]);
						usage(argv);
						return 1;
				}
				break;
			case '0': case '1': case '2': case '3': case '4':
			case '5': case '6': case '7': case '8': case '9':
				// TODO: supports multiple PIDs
				pid_str = argv[i];
				break;
		}
	}

	if (pid_str == NULL) {
		printf("No pid was given\n");
		usage(argv);
		return 1;
	}

	NTSTATUS ret;
	DWORD_PTR pid = strtol(pid_str, 0, 10);
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	OBJECT_ATTRIBUTES objAttr = { 0 };
	CLIENT_ID clientId = { .UniqueProcess = (HANDLE)pid, .UniqueThread = 0 };

	objAttr.Length = sizeof(objAttr);

	ret = NtOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION  | PROCESS_VM_READ, &objAttr, &clientId);
	if(NT_ERROR(ret) || hProcess == INVALID_HANDLE_VALUE || hProcess == NULL) {
		printf("NtOpenProcess failed\n");
		return 1;
	}

	DWORD_PTR addr = 0;
	do {
		if (!dump_regions) {
			break;
		}

		DWORD_PTR sz = DumpRegionInfo(hProcess, addr);
		if(sz == (DWORD_PTR)-1) {
			break;
		}
		addr += sz;
	} while(addr != 0);

	ULONG outlen = 0;
	BYTE buffer[1024];
	ret = NtQueryInformationProcess(hProcess, ProcessImageFileName, &buffer, sizeof(buffer), &outlen);
	if(NT_ERROR(ret)) {
		printf("NtQueryInformationProcess failed\n");
		return 1;
	}

	PUNICODE_STRING filename = (PUNICODE_STRING)buffer;
	printf("Outlen: %d, Filename: %S\n", outlen, filename->Buffer);

	PROCESS_BASIC_INFORMATION basicInfo;
	ret = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &basicInfo, sizeof(basicInfo), &outlen);
	if(NT_ERROR(ret) || outlen != sizeof(basicInfo)) {
		printf("NtQueryInformationProcess failed\n");
		return 1;
	}

	printf("ProcessBasicInfo->PebBaseAddress = %p\n", basicInfo.PebBaseAddress);
	printf("ProcessBasicInfo->UniqueProcessId = %d\n", basicInfo.UniqueProcessId);

	SIZE_T read;

	PEB remotePEB;
	ret = NtReadVirtualMemory(hProcess, (PVOID)basicInfo.PebBaseAddress, &remotePEB, sizeof(remotePEB), &read);
	if(NT_ERROR(ret) || read != sizeof(remotePEB)) {
		printf("NtReadVirtualMemory failed\n");
		return 1;
	}

	printf("RemotePEB->BeingDebugged = %d\n", remotePEB.BeingDebugged);
	printf("RemotePEB->ImageBaseAddress = %p\n", remotePEB.ImageBaseAddress);
	printf("RemotePEB->Ldr = %p\n", remotePEB.Ldr);
	printf("RemotePEB->ProcessParameters = %p\n", remotePEB.ProcessParameters);
	printf("RemotePEB->pShimData = %p\n", remotePEB.pShimData);

	PEB_LDR_DATA remoteLdrData;
	ret = NtReadVirtualMemory(hProcess, (PVOID)remotePEB.Ldr, &remoteLdrData, sizeof(remoteLdrData), &read);
	if(NT_ERROR(ret) || read != sizeof(remoteLdrData)) {
		printf("NtReadVirtualMemory failed\n");
		return 1;
	}

	printf("RemoteLdrData->Length = %d\n", remoteLdrData.Length);
	printf("RemoteLdrData->InMemoryOrderModuleList = %p\n", remoteLdrData.InMemoryOrderModuleList);

	printf("Start parsing module list\n");
	LDR_DATA_TABLE_ENTRY remoteLdrModule;
	remoteLdrModule.InMemoryOrderLinks = remoteLdrData.InMemoryOrderModuleList;
	int dll_idx = 0;
	do {
		LPVOID remoteLdrModuleAddr = CONTAINING_RECORD(remoteLdrModule.InMemoryOrderLinks.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		ret = NtReadVirtualMemory(hProcess, remoteLdrModuleAddr, &remoteLdrModule, sizeof(remoteLdrModule), &read);
		if(NT_ERROR(ret) || read != sizeof(remoteLdrModule)) {
			printf("NtReadVirtualMemory failed (%p)\n", remoteLdrModuleAddr);
			return 1;
		}

		if (verbose_dump)
		hexdump((LPCBYTE)&remoteLdrModule, sizeof(remoteLdrModule), (DWORD_PTR)remoteLdrModuleAddr);

		printf("RemoteLdrModule[%d]->InMemoryOrderLinks.Flink = %p\n", dll_idx, remoteLdrModule.InMemoryOrderLinks.Flink);
		printf("RemoteLdrModule[%d]->DllBase = %p\n", dll_idx, remoteLdrModule.DllBase);
		printf("RemoteLdrModule[%d]->EntryPoint = %p\n", dll_idx, remoteLdrModule.EntryPoint);
		printf("RemoteLdrModule[%d]->SizeOfImage = %p\n", dll_idx, (DWORD_PTR)remoteLdrModule.SizeOfImage);
		printf("RemoteLdrModule[%d]->FullDllName = %S\n", dll_idx, ReadRemoteUnicodeString(hProcess, &remoteLdrModule.FullDllName)->Buffer);
		printf("RemoteLdrModule[%d]->BaseDllName = %S\n", dll_idx, ReadRemoteUnicodeString(hProcess, &remoteLdrModule.BaseDllName)->Buffer);
		printf("RemoteLdrModule[%d]->LoadCount = %d\n", dll_idx, remoteLdrModule.LoadCount);
		dll_idx++;
	} while(remoteLdrModule.InMemoryOrderLinks.Flink != remoteLdrData.InMemoryOrderModuleList.Flink);

	RTL_USER_PROCESS_PARAMETERS remoteUserProcessParameters;
	ret = NtReadVirtualMemory(hProcess, (PVOID)remotePEB.ProcessParameters, &remoteUserProcessParameters, sizeof(remoteUserProcessParameters), &read);
	if(NT_ERROR(ret) || read != sizeof(remoteUserProcessParameters)) {
		printf("NtReadVirtualMemory failed\n");
		return 1;
	}

	printf("RemoteUserProcessParameters->CurrentDirectory.DosPath = %S\n", ReadRemoteUnicodeString(hProcess, &remoteUserProcessParameters.CurrentDirectory.DosPath)->Buffer);
	printf("RemoteUserProcessParameters->DllPath = %S\n", ReadRemoteUnicodeString(hProcess, &remoteUserProcessParameters.DllPath)->Buffer);
	printf("RemoteUserProcessParameters->ImagePathName = %S\n", ReadRemoteUnicodeString(hProcess, &remoteUserProcessParameters.ImagePathName)->Buffer);
	printf("RemoteUserProcessParameters->CommandLine = %S\n", ReadRemoteUnicodeString(hProcess, &remoteUserProcessParameters.CommandLine)->Buffer);

	ret = NtClose(hProcess);
	if(NT_ERROR(ret)) {
		printf("NtClose failed\n");
		return 1;
	}
}
