use32
org 0



CleanupBlockCall:
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
        mov edx, [ebx] ; edx = framework
        mov [ebp - 4], edx ; ebp - 4 = framework

        push dword [ebx + 32] ; push socket
        call dword [edx + 52] ; call closesocket

        mov ebx, [ebp + 8]; ebx = context

        push dword [ebx + 844] ; response length
        push dword [ebx + 36] ; receive buffer
        call .zero_mem

        push 0x8000 ; MEM_RELEASE
        push 0 ; size
        push dword [ebx + 36] ; receive buffer

        mov edx, [ebp - 4] ; edx = framework

        call dword [edx + 36] ; call virtualfree

        jmp .exit


.zero_mem:
        push ebp
        mov ebp, esp

        mov edi, [ebp + 8]
        mov ecx, [ebp + 12]
        xor eax, eax

        rep stosb ; zero buffer



        pop ebp
        ret 8

.exit:
        xor eax, eax

        db 7 dup(0x90)

        mov esp, ebp
        pop ebp
        ret 4



.call_end: