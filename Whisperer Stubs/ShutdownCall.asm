use32
org 0



ShutdownBlockCall:
        push ebp
        mov ebp, esp
        sub esp, 4

        mov ebx, 0xaaaaaaaa ;key0
        mov edx, 0xbbbbbbbb ;key1
        mov ecx, .call_end - .call_begin

        mov eax, [ebp + 8] ; eax = whisperer context
        mov eax, [eax] ; eax = whisperer framework
        mov eax, [eax + 16] ; eax = decryption function

        call eax

.call_begin:
dq 0x2222222222222222 ; delimiter, gets filled with nops at run time

        mov ebx, [ebp + 8] ; ebx = context
        mov ebx, [ebx] ; ebx = framework

        mov [ebp - 4], ebx

        call dword [ebx + 56] ; wsacleanup

        mov ebx, [ebp - 4]

        mov al, byte [ebx + 60]
        cmp al, 1
        je .free_iphlp

.check2:
        mov ebx, [ebp - 4]

        mov al, byte [ebx + 61]
        cmp al, 1
        je .free_wininet

        jmp .exit

.free_iphlp:
        push dword [ebx] ; push iphlp base
        call dword [ebx + 62] ; call freelib
        jmp .check2

.free_wininet:
        push dword [ebx + 4] ; push wininet base
        call dword [ebx + 62]; call freelib

.exit:

        db 9 dup (0x90)

        mov esp, ebp
        pop ebp
        ret 4



.call_end: