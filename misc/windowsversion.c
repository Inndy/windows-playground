#include <winternl.h>
#include <windows.h>
#include <stdio.h>
#include "../include/peb.h"

PEB *getPEB()
{
	PEB *peb = NULL;
#if _WIN64 || _Win64
	asm("movq %%gs:0x60, %0" : "=r" (peb) : : );
#else
	asm("movl %%fs:0x30, %0" : "=r" (peb) : : );
#endif
	return peb;
}

int main()
{
	OSVERSIONINFOEXW ovi = { sizeof(ovi) };
	NTSTATUS (*RtlGetVersion)(OSVERSIONINFOEXW *) = (void*)GetProcAddress(GetModuleHandle("ntdll"), "RtlGetVersion");

	RtlGetVersion(&ovi);
	printf("RtlOsVersionInfo->dwMajorVersion = %d\n", ovi.dwMajorVersion);
	printf("RtlOsVersionInfo->dwMinorVersion = %d\n", ovi.dwMinorVersion);
	printf("RtlOsVersionInfo->dwBuildNumber = %d\n", ovi.dwBuildNumber);
	printf("RtlOsVersionInfo->dwPlatformId = %d\n", ovi.dwPlatformId);
	printf("RtlOsVersionInfo->szCSDVersion = %S\n", ovi.szCSDVersion);
	printf("RtlOsVersionInfo->wServicePackMajor = %d\n", ovi.wServicePackMajor);
	printf("RtlOsVersionInfo->wServicePackMinor = %d\n", ovi.wServicePackMinor);
	printf("RtlOsVersionInfo->wSuiteMask = %d\n", ovi.wSuiteMask);
	printf("RtlOsVersionInfo->wProductType = %d\n", ovi.wProductType);
	printf("RtlOsVersionInfo->wReserved = %d\n", ovi.wReserved);

	GetVersionExW((void*)&ovi);
	printf("OsVersionInfoExW->dwMajorVersion = %d\n", ovi.dwMajorVersion);
	printf("OsVersionInfoExW->dwMinorVersion = %d\n", ovi.dwMinorVersion);
	printf("OsVersionInfoExW->dwBuildNumber = %d\n", ovi.dwBuildNumber);
	printf("OsVersionInfoExW->dwPlatformId = %d\n", ovi.dwPlatformId);
	printf("OsVersionInfoExW->szCSDVersion = %S\n", ovi.szCSDVersion);
	printf("OsVersionInfoExW->wServicePackMajor = %d\n", ovi.wServicePackMajor);
	printf("OsVersionInfoExW->wServicePackMinor = %d\n", ovi.wServicePackMinor);
	printf("OsVersionInfoExW->wSuiteMask = %d\n", ovi.wSuiteMask);
	printf("OsVersionInfoExW->wProductType = %d\n", ovi.wProductType);
	printf("OsVersionInfoExW->wReserved = %d\n", ovi.wReserved);

	PEB *peb = getPEB();
	printf("PEB -> %p\n", peb);
	printf("PEB->OSMajorVersion = %d\n", peb->OSMajorVersion);
	printf("PEB->OSMinorVersion = %d\n", peb->OSMinorVersion);
	printf("PEB->OSBuildNumber = %d\n", peb->OSBuildNumber);

	KUSER_SHARED_DATA *share_data = (void*)0x7ffe0000;
	printf("KUSER_SHARED_DATA->NtMajorVersion = %d\n", share_data->NtMajorVersion);
	printf("KUSER_SHARED_DATA->NtMinorVersion = %d\n", share_data->NtMinorVersion);
	printf("KUSER_SHARED_DATA->NtBuildNumber = %d\n", share_data->NtBuildNumber);
	printf("KUSER_SHARED_DATA->NtProductType = %d\n", share_data->NtProductType);
	printf("KUSER_SHARED_DATA->ProductTypeIsValid = %d\n", share_data->ProductTypeIsValid);

	printf("KUSER_SHARED_DATA->NtSystemRoot = %S\n", share_data->NtSystemRoot);
	printf("KUSER_SHARED_DATA->TimeZoneId = %d\n", share_data->TimeZoneId);
}
