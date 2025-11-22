EXTERN wNtAllocateVirtualMemory:DWORD               ; Appel externe dans lequel le symbole sera defini dans un autre module. Ici celui de alocatevirtualmemory
EXTERN sysAddrNtAllocateVirtualMemory:QWORD  

EXTERN wNtWriteVirtualMemory:DWORD
EXTERN sysAddrNtWriteVirtualMemory:QWORD

EXTERN wNtReadVirtualMemory:DWORD
EXTERN sysAddrNtReadVirtualMemory:QWORD

EXTERN wNtSetContextThread:DWORD
EXTERN sysAddrNtSetContextThread:QWORD

EXTERN wNtGetContextThread:DWORD
EXTERN sysAddrNtGetContextThread:QWORD

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

NtReadVirtualMemory PROC
    mov r10, rcx                                  
    mov eax, wNtReadVirtualMemory         
    jmp QWORD PTR [sysAddrNtReadVirtualMemory]  
NtReadVirtualMemory ENDP  

NtSetContextThread PROC
    mov r10, rcx                                  
    mov eax, wNtSetContextThread               
    jmp QWORD PTR [sysAddrNtSetContextThread]  
NtSetContextThread ENDP  

NtGetContextThread PROC
    mov r10, rcx                                  
    mov eax, wNtGetContextThread            
    jmp QWORD PTR [sysAddrNtGetContextThread]  
NtGetContextThread ENDP  

END  