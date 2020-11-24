use32
org 0



StartupBlockCall:
        push ebp
        mov ebp, esp
        sub esp, 400 ; sizeof wsadata

        mov ebx, 0xaaaaaaaa ;key0
        mov edx, 0xbbbbbbbb ;key1
        mov ecx, .call_end - .call_begin

        mov eax, [ebp + 8] ; eax = whisperer context
        mov eax, [eax] ; eax = whisperer framework
        mov eax, [eax + 16] ; eax = decryption function

        call eax

.call_begin:
dq 0x2222222222222222 ; delimiter, gets filled with nops at run time

        mov eax, [ebp + 8]
        mov eax, [eax]
        mov eax, [eax + 28]

        lea ebx, [ebp - 400] ;... the var that will contain the wsadata struct

        push ebx
        push 514 ;version
        call eax


db 20 dup (0x90)



        mov esp, ebp
        pop ebp
        ret 4

.call_end: