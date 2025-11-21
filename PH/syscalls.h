#include <Windows.h>

#ifndef _SYSCALLS_H 
#define _SYSCALLS_H

#ifdef __cplusplus   
extern "C" {        
#endif

extern NTSTATUS NtAllocateVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN ULONG                ZeroBits,
	IN OUT PULONG           RegionSize,
	IN ULONG                AllocationType,
	IN ULONG                Protect);

extern NTSTATUS NtWriteVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	IN PVOID                Buffer,
	IN ULONG                NumberOfBytesToWrite,
	OUT PULONG              NumberOfBytesWritten OPTIONAL);


#ifdef __cplusplus  
}
#endif

#endif