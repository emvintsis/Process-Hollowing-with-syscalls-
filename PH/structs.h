#pragma once
#include <Windows.h>
#include <winternl.h>

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;


typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass, 
	PVOID ProcessInformation,
	ULONG ProcessInformationLength, 
	PULONG ReturnLength);

typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t) (
	IN HANDLE               ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN ULONG                ZeroBits,
	IN OUT PULONG           RegionSize,
	IN ULONG                AllocationType,
	IN ULONG                Protect);