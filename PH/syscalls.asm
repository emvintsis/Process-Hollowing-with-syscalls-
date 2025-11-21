EXTERN wNtAllocateVirtualMemory:DWORD               ; Appel externe dans lequel le symbole sera defini dans un autre module. Ici celui de alocatevirtualmemory
EXTERN sysAddrNtAllocateVirtualMemory:QWORD  

EXTERN wNtWriteVirtualMemory:DWORD
EXTERN sysAddrNtWriteVirtualMemory:QWORD

.CODE  ; 

NtAllocateVirtualMemory PROC
    mov r10, rcx                                    ; déplace le contenu rcx à r10 (64 bits)
    mov eax, wNtAllocateVirtualMemory               ; Met dans le registre EAX l'identifiant du syscall
    jmp QWORD PTR [sysAddrNtAllocateVirtualMemory]  ; Jump vers le syscall.
NtAllocateVirtualMemory ENDP                        ;

NtWriteVirtualMemory PROC
    mov r10, rcx                                  
    mov eax, wNtWriteVirtualMemory               
    jmp QWORD PTR [sysAddrNtWriteVirtualMemory]  
NtWriteVirtualMemory ENDP                        

END  